package main

import (
	"os"
	"strings"
	"time"

	"github.com/COLONAYUSH/OpenMalLab/internal/pipeline"
	enums "go.temporal.io/api/enums/v1"
	"go.temporal.io/sdk/temporal"
	"go.temporal.io/sdk/workflow"
)

// recursion bounds. a submission is a tree: an archive holds children, which
// may themselves be archives. these cap the tree so a malicious nesting cannot
// turn one submission into unbounded work. tunable; conservative for M0.
const (
	maxDepth     = 8
	maxArtifacts = 200

	// activity timeouts. the light engines finish fast, but capa and floss run
	// vivisect emulation whose jail wall clocks are 300s and 360s. the Temporal
	// activity timeout MUST exceed jail-wall + broker-pass + docker overhead, or
	// Temporal kills the engine before its own budget: the graceful timeout and
	// partial-result paths never run, and the node needlessly floors after 3x
	// wasted work. keep the invariant: activity timeout > jail wall > tool timeout.
	defaultActivityTimeout = 3 * time.Minute
	heavyActivityTimeout   = 8 * time.Minute // covers floss (360s) + broker + slack

	// per-submission finding-size budget. a wide archive (up to maxArtifacts
	// nodes, each up to ~1000 findings) can otherwise produce a workflow result
	// too large for Temporal's payload limit, so the run never records a verdict.
	// we bound the SUMMED serialized size of findings, not the count, because a
	// hostile detail can be up to the broker's 8 KiB, and stay well under 2 MiB.
	maxFindingsBytes = 1 << 20

	// per-submission ingest-bytes budget. maxIngestTotalBytes bounds ONE extraction
	// (512 MiB); a branching archive runs up to maxArtifacts extractions, so without
	// a submission-wide cap a decompression bomb could still amplify to tens of GiB
	// of DISTINCT permanent vault writes across nodes. this bounds the whole tree.
	maxSubmissionIngestBytes = 2 << 30 // 2 GiB per submission
)

// workItem is one node of the artifact tree waiting to be analyzed. path is the
// human breadcrumb from the root (e.g. "outer.zip!dir/inner.exe").
type workItem struct {
	SHA256 string
	Path   string
	Depth  int
}

// SubmissionWorkflow is the durable root of every analysis. it walks the
// artifact tree breadth-first: identify and statically scan each artifact in
// parallel jails, unpack any container one level, ingest the children, and
// recurse, all under hard depth and count caps. every engine result is joined
// on the fail-closed lattice, so the submission verdict is the most suspicious
// signal anywhere in the tree and nothing is ever benign by omission.
func SubmissionWorkflow(ctx workflow.Context, in pipeline.SubmissionInput) (pipeline.SubmissionResult, error) {
	ctx = workflow.WithActivityOptions(ctx, workflow.ActivityOptions{
		StartToCloseTimeout: defaultActivityTimeout,
		RetryPolicy:         &temporal.RetryPolicy{MaximumAttempts: 3},
	})
	// heavy engines (capa, floss) get a longer activity timeout so their own
	// jail wall clock, not Temporal, is what bounds them. a timeout here is
	// deterministic (the same big sample will time out again), so a single
	// attempt: retrying only burns another 2 GiB jail for the same result.
	heavyCtx := workflow.WithActivityOptions(ctx, workflow.ActivityOptions{
		StartToCloseTimeout: heavyActivityTimeout,
		RetryPolicy:         &temporal.RetryPolicy{MaximumAttempts: 1},
	})

	res := pipeline.SubmissionResult{
		SubmissionID: in.SubmissionID,
		SHA256:       in.SHA256,
		Filename:     in.Filename,
		Verdict:      pipeline.Unknown, // fail-closed bottom; only evidence moves it, only up
	}
	var a *Analyzer // nil receiver: activities resolve by name

	// per-submission finding budget (see maxFindingsBytes): once the byte budget
	// is spent, findings stop being appended (a marker + incomplete are emitted
	// once), but verdict severity is still joined from every finding so the cap
	// can never hide a MALICIOUS signal.
	findingsBytes := 0
	findingsCapped := false

	// fold one engine's outcome into the submission: findings tagged with the
	// artifact's breadcrumb, verdicts joined, any failure or gap floored to
	// SUSPICIOUS + incomplete. never falls through to BENIGN.
	fold := func(path, engine string, f workflow.Future) (pipeline.EngineReport, bool) {
		var rep pipeline.EngineReport
		if err := f.Get(ctx, &rep); err != nil {
			res.Verdict = pipeline.Max(res.Verdict, pipeline.Suspicious)
			res.Incomplete = true
			res.Findings = append(res.Findings, pipeline.Finding{
				Engine:     engine,
				Type:       "error",
				Detail:     "engine did not complete; verdict floored",
				Verdict:    pipeline.Suspicious,
				Confidence: pipeline.ConfLow, // a floor, not a detection
				Path:       path,
			})
			return pipeline.EngineReport{}, false
		}
		for i := range rep.Findings {
			f := rep.Findings[i]
			// lift from each finding, not only the worker's self-reported top
			// verdict: a buggy or compromised worker that emits a MALICIOUS
			// finding under an UNKNOWN top verdict must still escalate the
			// submission. this runs for EVERY finding, before the size cap, so
			// the cap can never hide severity. the broker validates each verdict
			// independently, so trusted code joins them rather than trusting the
			// rollup.
			res.Verdict = pipeline.Max(res.Verdict, f.Verdict)
			// bound the summed finding size so the workflow result fits Temporal.
			// the constant covers the per-finding JSON structural overhead the field
			// lengths above omit: the object braces, the quoted keys, and the
			// always-present verdict + confidence string values (~110 bytes). counting
			// it makes the cap trip with real headroom instead of undercounting toward
			// Temporal's payload limit.
			sz := len(f.Detail) + len(path) + len(f.Type) + len(f.Attck) + len(f.Engine) + 128
			if findingsBytes+sz > maxFindingsBytes {
				if !findingsCapped {
					findingsCapped = true
					res.Incomplete = true
					res.Verdict = pipeline.Max(res.Verdict, pipeline.Suspicious)
					res.Findings = append(res.Findings, pipeline.Finding{
						Engine:     "mal-orchestrator",
						Type:       "findings-cap",
						Detail:     "per-submission finding-size cap reached; further findings omitted (the verdict still reflects them)",
						Verdict:    pipeline.Suspicious,
						Confidence: pipeline.ConfLow,
					})
				}
				continue
			}
			f.Path = path
			res.Findings = append(res.Findings, f)
			findingsBytes += sz
		}
		res.Verdict = pipeline.Max(res.Verdict, rep.Verdict)
		if rep.Incomplete {
			res.Incomplete = true
			res.Verdict = pipeline.Max(res.Verdict, pipeline.Suspicious)
		}
		return rep, true
	}

	queue := []workItem{{SHA256: in.SHA256, Path: "", Depth: 0}}
	processed := 0
	depthCapped := false // emit the depth-cap marker at most once
	var submissionIngested int64
	ingestCapped := false // emit the per-submission ingest-cap marker at most once

	for len(queue) > 0 {
		if processed >= maxArtifacts {
			// bounded on purpose: report the truncation, do not silently stop.
			res.Incomplete = true
			res.Findings = append(res.Findings, pipeline.Finding{
				Engine:     "mal-orchestrator",
				Type:       "recursion-cap",
				Detail:     "artifact-count cap reached; deeper children not analyzed",
				Verdict:    pipeline.Suspicious,
				Confidence: pipeline.ConfLow,
			})
			res.Verdict = pipeline.Max(res.Verdict, pipeline.Suspicious)
			break
		}
		item := queue[0]
		queue = queue[1:]
		processed++

		artifact := pipeline.SubmissionInput{
			SubmissionID: in.SubmissionID,
			DomainID:     in.DomainID,
			SHA256:       item.SHA256,
		}

		// surface every NON-ROOT artifact's verified content hash as evidence, tagged
		// with its breadcrumb path. the root hash is already in SubmissionResult.SHA256;
		// extracted children were re-hashed by the extractor's ingest and then used only
		// for recursion, so without this an analyst has no way to grab the hash of a
		// bundled file to blocklist / share / pivot. informational (UNKNOWN + LOW):
		// identity, not a detection, so it carries no severity or score weight.
		if item.Depth > 0 {
			res.Findings = append(res.Findings, pipeline.Finding{
				Engine:     "mal-orchestrator",
				Type:       "artifact-sha256",
				Detail:     "sha256=" + item.SHA256,
				Verdict:    pipeline.Unknown,
				Confidence: pipeline.ConfLow,
				Path:       item.Path,
			})
		}

		// identify and scan in parallel: two jails, no ordering between them.
		identF := workflow.ExecuteActivity(ctx, a.IdentifyActivity, artifact)
		yaraF := workflow.ExecuteActivity(ctx, a.StaticAnalyzeActivity, artifact)
		identRep, _ := fold(item.Path, "mal-ident", identF)
		fold(item.Path, "mal-static-yara", yaraF)

		if item.Depth == 0 {
			res.FileType = fileTypeOf(identRep)
		}

		// capability analysis, only for executables: capa cannot analyze other
		// formats, and loading its rule set per artifact is expensive, so we
		// gate on what magika identified (content, never the extension).
		if isExecutable(identRep) {
			capaF := workflow.ExecuteActivity(heavyCtx, a.CapaActivity, artifact)
			fold(item.Path, "mal-capa", capaF)
			// Detect It Easy: packer / compiler / crypto fingerprinting on the same
			// executable surface as capa. it is the packed/unanalyzed gate (a packer
			// floors the artifact SUSPICIOUS + incomplete). light and deterministic,
			// so the default context, not the heavy one. a no-op until MAL_DIE_IMAGE
			// is set (see DieActivity), so this is safe to ship before the image exists.
			dieF := workflow.ExecuteActivity(ctx, a.DieActivity, artifact)
			fold(item.Path, "mal-static-die", dieF)
		}

		// string recovery, only for PE: FLOSS decodes PE and shellcode only, and
		// its emulation is expensive, so we gate it on magika identifying a PE.
		if isPE(identRep) {
			flossF := workflow.ExecuteActivity(heavyCtx, a.FlossActivity, artifact)
			fold(item.Path, "mal-floss", flossF)
		}

		// dynamic analysis, ELF only and ONLY when the submitter opted in: detonation
		// EXECUTES the sample (as data, under the jailed emulator), so v1 runs it on
		// request and only on the ROOT artifact (never on extracted children, whose
		// detonation would be an unbounded risk + budget explosion). heavy and
		// non-deterministic, so it shares the heavy context like capa/floss.
		if in.Detonate && item.Depth == 0 && isELF(identRep) {
			detonateF := workflow.ExecuteActivity(heavyCtx, a.DetonateActivity, artifact)
			fold(item.Path, "mal-detonate", detonateF)
		}

		// unpack one level. extraction runs on every artifact (we never trust an
		// identifier about whether something is a container). children are
		// enqueued only while within the depth cap; a child that exists AT the
		// cap floors the node the same fail-closed way the artifact-count cap
		// does, so a deep nest is never silently reported clean. this is the
		// counterpart to the maxArtifacts branch above: report the truncation,
		// never quietly stop.
		//
		// extraction is the ONLY vault-WRITE path, so once the per-submission ingest
		// budget has tripped we stop dispatching it. otherwise every remaining queued
		// node would still write up to another per-extraction cap into the shared
		// vault, bounding total writes by maxArtifacts x that cap (~100 GiB) rather
		// than the submission budget the comment above promises. the read-only engines
		// already ran on this node; cutting only the writing step bounds total vault
		// writes to about the budget plus the single in-flight extraction that tripped
		// the cap.
		if ingestCapped {
			continue
		}
		extractF := workflow.ExecuteActivity(ctx, a.ExtractActivity, artifact)
		extractRep, ok := fold(item.Path, "mal-extract", extractF)
		if ok {
			// accumulate this extraction's ingested bytes into the submission total.
			submissionIngested += extractRep.IngestedBytes
			if submissionIngested > maxSubmissionIngestBytes {
				// budget spent: stop growing the tree so a branching decompression
				// bomb cannot fill the shared vault. verified children stand; deeper
				// ones are not analyzed. fail-closed: incomplete + SUSPICIOUS + marker.
				if !ingestCapped {
					ingestCapped = true
					res.Incomplete = true
					res.Verdict = pipeline.Max(res.Verdict, pipeline.Suspicious)
					res.Findings = append(res.Findings, pipeline.Finding{
						Engine:     "mal-orchestrator",
						Type:       "ingest-cap",
						Detail:     "per-submission extracted-bytes budget reached; further extraction was halted",
						Verdict:    pipeline.Suspicious,
						Confidence: pipeline.ConfLow,
						Path:       item.Path,
					})
				}
			} else {
				for _, c := range extractRep.Children {
					if item.Depth+1 <= maxDepth {
						queue = append(queue, workItem{
							SHA256: c.SHA256,
							Path:   crumb(item.Path, c.Name),
							Depth:  item.Depth + 1,
						})
						continue
					}
					if !depthCapped {
						depthCapped = true
						res.Incomplete = true
						res.Verdict = pipeline.Max(res.Verdict, pipeline.Suspicious)
						res.Findings = append(res.Findings, pipeline.Finding{
							Engine:     "mal-orchestrator",
							Type:       "recursion-cap",
							Detail:     "archive nesting exceeded the depth cap; deeper children were not analyzed",
							Verdict:    pipeline.Suspicious,
							Confidence: pipeline.ConfLow,
							Path:       item.Path,
						})
					}
				}
			}
		}
	}

	// the triage axis: turn the findings into a ranked, confidence-weighted
	// score. the severity verdict above is untouched (fail-closed); this only
	// tells a queue how much to care.
	res.Score, res.Confidence = pipeline.ScoreFindings(res.Findings)

	// hand off to the async AI-enrichment plane if it is enabled, as an ABANDON
	// child: this deterministic workflow completes immediately with its verdict,
	// and nothing the AI plane does can change or delay it (agents propose, the
	// spine disposes). off by default; the SideEffect reads the same env flag that
	// wires the plane at all, recorded in history so replay is deterministic.
	if aiEnrichmentEnabled(ctx) {
		cctx := workflow.WithChildOptions(ctx, workflow.ChildWorkflowOptions{
			WorkflowID:        in.SubmissionID + "-enrich",
			ParentClosePolicy: enums.PARENT_CLOSE_POLICY_ABANDON,
		})
		child := workflow.ExecuteChildWorkflow(cctx, AgentGraphWorkflow, res)
		// wait only until the child has STARTED, then abandon it; never wait for its
		// result, so the verdict is returned without any AI latency.
		_ = child.GetChildWorkflowExecution().Get(ctx, nil)
	}
	return res, nil
}

// aiEnrichmentEnabled reports whether the AI-enrichment plane is wired. read once
// via a SideEffect so the decision is recorded in workflow history and replay-safe
// (reading the env directly in workflow code would be non-deterministic).
func aiEnrichmentEnabled(ctx workflow.Context) bool {
	var enabled bool
	_ = workflow.SideEffect(ctx, func(workflow.Context) interface{} {
		return os.Getenv("MAL_AGENTS_URL") != ""
	}).Get(&enabled)
	return enabled
}

// fileTypeOf pulls the identified file type out of an ident report's findings.
func fileTypeOf(rep pipeline.EngineReport) string {
	for _, f := range rep.Findings {
		if f.Type == "file-type" {
			return f.Detail
		}
	}
	return ""
}

// executableTypes are the magika labels capa can actually analyze. these are
// magika's own content-type labels (pebin is its name for a PE, .NET included);
// there is no "pe" or "dotnet" label. the group check below is the real safety
// net, so a new executable label magika adds still reaches capa.
var executableTypes = map[string]bool{
	"pebin": true, "elf": true, "macho": true, "coff": true,
}

// isExecutable decides whether capa should run, from magika's content-based
// identification. it also fires when ident labels the file's group as an
// executable, so a format magika names but we did not enumerate still gets
// capability analysis.
func isExecutable(ident pipeline.EngineReport) bool {
	for _, f := range ident.Findings {
		if f.Type == "file-type" && executableTypes[f.Detail] {
			return true
		}
		if f.Type == "file-type-group" && f.Detail == "executable" {
			return true
		}
	}
	return false
}

// isPE decides whether FLOSS should run: FLOSS decodes PE (including .NET,
// which is also a PE) only, so we gate on magika labelling the content a PE.
// "pebin" is magika's own label for a PE Windows executable; there is no "pe".
func isPE(ident pipeline.EngineReport) bool {
	for _, f := range ident.Findings {
		if f.Type == "file-type" && f.Detail == "pebin" {
			return true
		}
	}
	return false
}

// isELF decides whether detonation should run: v1 dynamically analyzes Linux ELF
// executables (x86-64/aarch64) by running them under the jailed emulator. "elf" is
// magika's own content label for an ELF (there is no "elf64"/arch split at this
// layer; the worker detects the guest arch from the ELF header itself).
func isELF(ident pipeline.EngineReport) bool {
	for _, f := range ident.Findings {
		if f.Type == "file-type" && f.Detail == "elf" {
			return true
		}
	}
	return false
}

// crumb extends a breadcrumb path with a child's name inside its container.
// the name comes from inside a hostile archive and is length-checked by the
// broker but not sanitized, so control characters (newlines, ANSI escapes)
// are stripped here before the name enters Path, which flows out through the
// api. the console defangs again at render; this closes the api-level hole.
func crumb(parent, name string) string {
	name = strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return '.'
		}
		return r
	}, name)
	if parent == "" {
		return name
	}
	return parent + "!" + name
}
