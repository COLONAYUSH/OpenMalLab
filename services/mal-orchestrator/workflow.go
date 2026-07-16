package main

import (
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
		StartToCloseTimeout: 3 * time.Minute,
		RetryPolicy:         &temporal.RetryPolicy{MaximumAttempts: 3},
	})

	res := pipeline.SubmissionResult{
		SubmissionID: in.SubmissionID,
		SHA256:       in.SHA256,
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
				Engine:  engine,
				Type:    "error",
				Detail:  "engine did not complete; verdict floored",
				Verdict: pipeline.Suspicious,
				Path:    path,
			})
			return pipeline.EngineReport{}, false
		}
		for i := range rep.Findings {
			rep.Findings[i].Path = path
			res.Findings = append(res.Findings, rep.Findings[i])
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

	for len(queue) > 0 {
		if processed >= maxArtifacts {
			// bounded on purpose: report the truncation, do not silently stop.
			res.Incomplete = true
			res.Findings = append(res.Findings, pipeline.Finding{
				Engine:  "mal-orchestrator",
				Type:    "recursion-cap",
				Detail:  "artifact-count cap reached; deeper children not analyzed",
				Verdict: pipeline.Suspicious,
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

		// unpack one level while within the depth cap, then enqueue children.
		// extraction runs on every artifact within depth: we do not rely on any
		// single identifier being right about whether something is a container.
		if item.Depth < maxDepth {
			extractF := workflow.ExecuteActivity(ctx, a.ExtractActivity, artifact)
			extractRep, ok := fold(item.Path, "mal-extract", extractF)
			if ok {
				for _, c := range extractRep.Children {
					queue = append(queue, workItem{
						SHA256: c.SHA256,
						Path:   crumb(item.Path, c.Name),
						Depth:  item.Depth + 1,
					})
				}
			}
		}
	}
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

// crumb extends a breadcrumb path with a child's name inside its container.
func crumb(parent, name string) string {
	if parent == "" {
		return name
	}
	return parent + "!" + name
}
