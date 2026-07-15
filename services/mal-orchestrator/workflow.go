package main

import (
	"context"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/COLONAYUSH/OpenMalLab/internal/pipeline"
	"go.temporal.io/sdk/activity"
	"go.temporal.io/sdk/temporal"
	"go.temporal.io/sdk/workflow"
)

// SubmissionWorkflow is the durable root of every analysis. M0 spine: identify
// the file, then roll up a fail-closed verdict. extraction, the static engines,
// and (later) detonation hang off this as the pipeline grows.
func SubmissionWorkflow(ctx workflow.Context, in pipeline.SubmissionInput) (pipeline.SubmissionResult, error) {
	ctx = workflow.WithActivityOptions(ctx, workflow.ActivityOptions{
		StartToCloseTimeout: 30 * time.Second,
		RetryPolicy:         &temporal.RetryPolicy{MaximumAttempts: 3},
	})

	// fail-closed default: a submission is never BENIGN just because we have not
	// finished. it starts UNKNOWN and only deterministic evidence moves it.
	res := pipeline.SubmissionResult{
		SubmissionID: in.SubmissionID,
		SHA256:       in.SHA256,
		Verdict:      pipeline.Unknown,
	}

	var ident IdentifyResult
	if err := workflow.ExecuteActivity(ctx, IdentifyActivity, in).Get(ctx, &ident); err != nil {
		// an engine crash or timeout floors the node to SUSPICIOUS and flags it
		// incomplete. it does not fall through to BENIGN.
		res.Verdict = pipeline.Suspicious
		res.Incomplete = true
		return res, nil
	}

	res.FileType = ident.FileType
	res.Findings = append(res.Findings, pipeline.Finding{
		Engine:  "mal-ident",
		Type:    "file-type",
		Detail:  ident.FileType,
		Verdict: pipeline.Unknown,
	})
	// M0 has no scoring engine yet, so the honest rolled-up verdict is UNKNOWN.
	// the static engines will contribute real signal in M1.
	return res, nil
}

// IdentifyResult is the typed output of the identify step.
type IdentifyResult struct {
	FileType string
}

// IdentifyActivity runs mal-ident over the artifact. in M0 it shells out to the
// worker binary to prove the dispatch path. the next milestone runs it as a
// single-use, credential-less, no-network container with the artifact on a
// read-only mounted fd and the result crossing a bounded schema over a uds.
func IdentifyActivity(ctx context.Context, in pipeline.SubmissionInput) (IdentifyResult, error) {
	bin := os.Getenv("MAL_IDENT_BIN")
	if bin == "" {
		bin = "./target/debug/mal-ident"
	}
	out, err := exec.CommandContext(ctx, bin, in.ScratchPath).Output()
	if err != nil {
		activity.GetLogger(ctx).Error("mal-ident failed", "sha256", in.SHA256, "err", err)
		return IdentifyResult{}, err
	}
	return IdentifyResult{FileType: strings.TrimSpace(string(out))}, nil
}
