package main

import (
	"time"

	"github.com/COLONAYUSH/OpenMalLab/internal/pipeline"
	"go.temporal.io/sdk/temporal"
	"go.temporal.io/sdk/workflow"
)

// SubmissionWorkflow is the durable root of every analysis. M0 spine: run the
// engines in their jails in parallel, validate everything through the broker,
// join on the fail-closed lattice. extraction, more static engines, and
// (later) detonation hang off this same join as the pipeline grows.
func SubmissionWorkflow(ctx workflow.Context, in pipeline.SubmissionInput) (pipeline.SubmissionResult, error) {
	ctx = workflow.WithActivityOptions(ctx, workflow.ActivityOptions{
		// generous: covers the jail runs plus retries on infra hiccups.
		StartToCloseTimeout: 3 * time.Minute,
		RetryPolicy:         &temporal.RetryPolicy{MaximumAttempts: 3},
	})

	// fail-closed default: a submission is never BENIGN just because we have
	// not finished. it starts UNKNOWN and only evidence moves it, only upward
	// while anything is missing.
	res := pipeline.SubmissionResult{
		SubmissionID: in.SubmissionID,
		SHA256:       in.SHA256,
		Verdict:      pipeline.Unknown,
	}

	// join folds one engine's outcome into the result: findings appended,
	// verdicts joined on the lattice, and any failure or gap floors the node
	// to SUSPICIOUS and marks it incomplete. it never falls through to BENIGN.
	join := func(engine string, f workflow.Future) pipeline.EngineReport {
		var rep pipeline.EngineReport
		if err := f.Get(ctx, &rep); err != nil {
			res.Verdict = pipeline.Max(res.Verdict, pipeline.Suspicious)
			res.Incomplete = true
			res.Findings = append(res.Findings, pipeline.Finding{
				Engine:  engine,
				Type:    "error",
				Detail:  "engine did not complete; verdict floored",
				Verdict: pipeline.Suspicious,
			})
			return pipeline.EngineReport{}
		}
		res.Findings = append(res.Findings, rep.Findings...)
		res.Verdict = pipeline.Max(res.Verdict, rep.Verdict)
		if rep.Incomplete {
			res.Incomplete = true
			res.Verdict = pipeline.Max(res.Verdict, pipeline.Suspicious)
		}
		return rep
	}

	// both engines start before either result is awaited: they run in
	// parallel, each in its own jail.
	var a *Analyzer // nil receiver: activity resolution by name only
	identF := workflow.ExecuteActivity(ctx, a.IdentifyActivity, in)
	staticF := workflow.ExecuteActivity(ctx, a.StaticAnalyzeActivity, in)

	identRep := join("mal-ident", identF)
	join("mal-static-yara", staticF)

	// identification is evidence: surface what the file really is.
	for _, f := range identRep.Findings {
		if f.Type == "file-type" {
			res.FileType = f.Detail
			break
		}
	}
	return res, nil
}
