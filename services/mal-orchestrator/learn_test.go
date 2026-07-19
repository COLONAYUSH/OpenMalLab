package main

import (
	"context"
	"strings"
	"testing"

	"github.com/COLONAYUSH/OpenMalLab/internal/knowledge"
	"github.com/COLONAYUSH/OpenMalLab/internal/pipeline"
)

func newGraphAnalyzer() *Analyzer {
	return &Analyzer{graph: knowledge.NewGraph(knowledge.NewMemGraph())}
}

func TestIngestWritesTechniquesToWorkingIndex(t *testing.T) {
	a := newGraphAnalyzer()
	res := pipeline.SubmissionResult{
		SubmissionID: "sub-1", SHA256: strings.Repeat("a", 64), Filename: "x.exe",
		Findings: []pipeline.Finding{
			{Engine: "mal-capa", Attck: "T1055"},
			{Engine: "mal-capa", Attck: "T1055"}, // duplicate: deduped
			{Engine: "mal-yara", Attck: "T1071"},
		},
	}
	n, err := a.IngestLearningActivity(context.Background(), LearnInput{Result: res, Confirmed: false})
	if err != nil {
		t.Fatal(err)
	}
	if n < 3 { // sample + T1055 + T1071
		t.Fatalf("expected sample + 2 distinct techniques, wrote %d", n)
	}
	sample, ok := a.graph.Node(knowledge.NodeSample, res.SHA256)
	if !ok || sample.Trust != knowledge.TrustIngest {
		t.Fatalf("auto-ingested sample must land in the working index: %+v ok=%v", sample, ok)
	}
	if tech, ok := a.graph.Node(knowledge.NodeTechnique, "T1055"); !ok || tech.Trust != knowledge.TrustIngest {
		t.Fatalf("technique not ingested low-trust: %+v ok=%v", tech, ok)
	}
}

func TestIngestConfirmedIsCurated(t *testing.T) {
	a := newGraphAnalyzer()
	res := pipeline.SubmissionResult{SubmissionID: "s", SHA256: strings.Repeat("b", 64), Findings: []pipeline.Finding{{Attck: "T1055"}}}
	if _, err := a.IngestLearningActivity(context.Background(), LearnInput{Result: res, Confirmed: true}); err != nil {
		t.Fatal(err)
	}
	if tech, ok := a.graph.Node(knowledge.NodeTechnique, "T1055"); !ok || tech.Trust != knowledge.TrustCurated {
		t.Fatalf("a human-confirmed analysis must curate its facts: %+v ok=%v", tech, ok)
	}
}

func TestIngestNoOpWithoutGraphOrSHA(t *testing.T) {
	if n, _ := (&Analyzer{}).IngestLearningActivity(context.Background(), LearnInput{Result: pipeline.SubmissionResult{SHA256: "x"}}); n != 0 {
		t.Fatal("no graph wired must be a no-op")
	}
	a := newGraphAnalyzer()
	if n, _ := a.IngestLearningActivity(context.Background(), LearnInput{Result: pipeline.SubmissionResult{SubmissionID: "s"}}); n != 0 {
		t.Fatal("no sample hash: nothing to anchor facts to")
	}
}

func TestIngestPoisoningGuardCuratedWins(t *testing.T) {
	a := newGraphAnalyzer()
	sha := strings.Repeat("c", 64)
	// a human-confirmed analysis curates the technique.
	if _, err := a.IngestLearningActivity(context.Background(), LearnInput{
		Result: pipeline.SubmissionResult{SubmissionID: "s1", SHA256: sha, Findings: []pipeline.Finding{{Attck: "T1055"}}}, Confirmed: true}); err != nil {
		t.Fatal(err)
	}
	// a later AUTO analysis (ingest tier) must not downgrade the curated fact.
	if _, err := a.IngestLearningActivity(context.Background(), LearnInput{
		Result: pipeline.SubmissionResult{SubmissionID: "s2", SHA256: sha, Findings: []pipeline.Finding{{Attck: "T1055"}}}, Confirmed: false}); err != nil {
		t.Fatal(err)
	}
	if tech, ok := a.graph.Node(knowledge.NodeTechnique, "T1055"); !ok || tech.Trust != knowledge.TrustCurated {
		t.Fatalf("ingest must never overwrite curated (poisoning guard): %+v ok=%v", tech, ok)
	}
}
