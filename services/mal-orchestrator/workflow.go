package main

import (
	"strings"
	"time"

	"github.com/COLONAYUSH/OpenMalLab/internal/pipeline"
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
			rep.Findings[i].Path = path
			res.Findings = append(res.Findings, rep.Findings[i])
			// lift from each finding, not only the worker's self-reported top
			// verdict: a buggy or compromised worker that emits a MALICIOUS
			// finding under an UNKNOWN top verdict must still escalate the
			// submission. the broker validates each verdict independently, so
			// trusted code joins them itself rather than trusting the rollup.
			res.Verdict = pipeline.Max(res.Verdict, rep.Findings[i].Verdict)
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
		}

		// string recovery, only for PE: FLOSS decodes PE and shellcode only, and
		// its emulation is expensive, so we gate it on magika identifying a PE.
		if isPE(identRep) {
			flossF := workflow.ExecuteActivity(heavyCtx, a.FlossActivity, artifact)
			fold(item.Path, "mal-floss", flossF)
		}

		// unpack one level. extraction runs on every artifact (we never trust an
		// identifier about whether something is a container). children are
		// enqueued only while within the depth cap; a child that exists AT the
		// cap floors the node the same fail-closed way the artifact-count cap
		// does, so a deep nest is never silently reported clean. this is the
		// counterpart to the maxArtifacts branch above: report the truncation,
		// never quietly stop.
		extractF := workflow.ExecuteActivity(ctx, a.ExtractActivity, artifact)
		extractRep, ok := fold(item.Path, "mal-extract", extractF)
		if ok {
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

	// the triage axis: turn the findings into a ranked, confidence-weighted
	// score. the severity verdict above is untouched (fail-closed); this only
	// tells a queue how much to care.
	res.Score, res.Confidence = pipeline.ScoreFindings(res.Findings)
	return res, nil
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
