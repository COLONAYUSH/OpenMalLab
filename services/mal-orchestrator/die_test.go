package main

import (
	"context"
	"testing"

	"github.com/COLONAYUSH/OpenMalLab/internal/pipeline"
)

// DieActivity is config-gated: with MAL_DIE_IMAGE unset (dieImage == "") it must
// be a no-op that reports an empty UNKNOWN and never touches docker, so the DIE
// engine ships wired but dormant until its image is built on a clean network.
// This pins that gate: a disabled DIE cannot floor a verdict or mark a submission
// incomplete, so it cannot pollute an executable submission (including an ELF
// detonation test) until an operator provisions the image and sets the env.
func TestDieActivityDisabledIsCleanNoop(t *testing.T) {
	a := &Analyzer{} // dieImage == "": DIE not configured
	rep, err := a.DieActivity(context.Background(), pipeline.SubmissionInput{SHA256: "deadbeef"})
	if err != nil {
		t.Fatalf("disabled DieActivity must not error, got %v", err)
	}
	if rep.Engine != "mal-static-die" {
		t.Fatalf("engine = %q, want mal-static-die", rep.Engine)
	}
	if rep.Verdict != pipeline.Unknown {
		t.Fatalf("disabled verdict = %v, want Unknown (a disabled engine must never floor)", rep.Verdict)
	}
	if rep.Incomplete {
		t.Fatal("disabled DIE must not mark the report incomplete")
	}
	if len(rep.Findings) != 0 {
		t.Fatalf("disabled DIE must emit no findings, got %d", len(rep.Findings))
	}
}
