package main

import (
	"time"

	"github.com/COLONAYUSH/OpenMalLab/internal/pipeline"
	"go.temporal.io/sdk/temporal"
	"go.temporal.io/sdk/workflow"
)

// SubmissionWorkflow is the durable root of every analysis. M0 spine: run the
// static engine in its jail, validate through the broker, roll up a
// fail-closed verdict. extraction, more static engines, and (later)
// detonation hang off this as the pipeline grows.
func SubmissionWorkflow(ctx workflow.Context, in pipeline.SubmissionInput) (pipeline.SubmissionResult, error) {
	ctx = workflow.WithActivityOptions(ctx, workflow.ActivityOptions{
		// generous: covers three jail runs plus retries on infra hiccups.
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

	var a *Analyzer // nil receiver: activity resolution by name only
	var rep pipeline.EngineReport
	if err := workflow.ExecuteActivity(ctx, a.StaticAnalyzeActivity, in).Get(ctx, &rep); err != nil {
		// a jail failure, broker reject, timeout, or crash floors the node to
		// SUSPICIOUS and flags it incomplete. it never falls through to BENIGN.
		res.Verdict = pipeline.Max(res.Verdict, pipeline.Suspicious)
		res.Incomplete = true
		res.Findings = append(res.Findings, pipeline.Finding{
			Engine:  "mal-static-yara",
			Type:    "error",
			Detail:  "static analysis did not complete; verdict floored",
			Verdict: pipeline.Suspicious,
		})
		return res, nil
	}

	// the lattice join: the most suspicious signal wins, benign masks nothing.
	res.Findings = append(res.Findings, rep.Findings...)
	res.Verdict = pipeline.Max(res.Verdict, rep.Verdict)
	if rep.Incomplete {
		res.Incomplete = true
		res.Verdict = pipeline.Max(res.Verdict, pipeline.Suspicious)
	}
	return res, nil
}
