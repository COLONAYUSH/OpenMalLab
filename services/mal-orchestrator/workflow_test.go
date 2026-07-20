package main

import (
	"context"
	"strings"
	"testing"

	"github.com/COLONAYUSH/OpenMalLab/internal/pipeline"
	"github.com/stretchr/testify/mock"
	"go.temporal.io/sdk/testsuite"
)

func identWith(findings ...pipeline.Finding) pipeline.EngineReport {
	return pipeline.EngineReport{Engine: "mal-ident", Findings: findings}
}

// capa is expensive and only meaningful on executables, so the workflow gates
// it on magika's content-based identification. this pins that gate against
// magika's real label vocabulary (pebin/elf/macho/coff), not the intuitive
// names ("pe") that magika never emits.
func TestIsExecutableGatesCapa(t *testing.T) {
	cases := []struct {
		name  string
		ident pipeline.EngineReport
		want  bool
	}{
		{"elf by label", identWith(pipeline.Finding{Type: "file-type", Detail: "elf"}), true},
		{"pe by label (pebin)", identWith(pipeline.Finding{Type: "file-type", Detail: "pebin"}), true},
		{"macho by label", identWith(pipeline.Finding{Type: "file-type", Detail: "macho"}), true},
		{"coff by label", identWith(pipeline.Finding{Type: "file-type", Detail: "coff"}), true},
		// a label we did not enumerate but magika groups as executable still
		// reaches capa: the group is the real gate, the label list an optimization.
		{"unknown label, exec group", identWith(
			pipeline.Finding{Type: "file-type", Detail: "somenewbin"},
			pipeline.Finding{Type: "file-type-group", Detail: "executable"}), true},
		{"by group alone", identWith(pipeline.Finding{Type: "file-type-group", Detail: "executable"}), true},
		{"plain text", identWith(pipeline.Finding{Type: "file-type", Detail: "txt"}), false},
		{"zip archive", identWith(pipeline.Finding{Type: "file-type", Detail: "zip"}), false},
		{"no ident findings", identWith(), false},
	}
	for _, c := range cases {
		if got := isExecutable(c.ident); got != c.want {
			t.Fatalf("%s: isExecutable=%v want %v", c.name, got, c.want)
		}
	}
}

// FLOSS only decodes PE, so the workflow gates it strictly on magika naming a
// PE. this pins the label magika actually uses ("pebin"): the gate regressed
// once already by checking a "pe" label that magika never emits, which silently
// stopped FLOSS from ever running.
func TestIsPEGatesFloss(t *testing.T) {
	cases := []struct {
		name  string
		ident pipeline.EngineReport
		want  bool
	}{
		{"pe (pebin)", identWith(pipeline.Finding{Type: "file-type", Detail: "pebin"}), true},
		// FLOSS is PE-only: other executables are for capa, not FLOSS.
		{"elf is not a PE", identWith(pipeline.Finding{Type: "file-type", Detail: "elf"}), false},
		{"macho is not a PE", identWith(pipeline.Finding{Type: "file-type", Detail: "macho"}), false},
		// the label magika never emits must not fire the gate.
		{"bogus 'pe' label", identWith(pipeline.Finding{Type: "file-type", Detail: "pe"}), false},
		{"executable group is not enough", identWith(pipeline.Finding{Type: "file-type-group", Detail: "executable"}), false},
		{"plain text", identWith(pipeline.Finding{Type: "file-type", Detail: "txt"}), false},
		{"no ident findings", identWith(), false},
	}
	for _, c := range cases {
		if got := isPE(c.ident); got != c.want {
			t.Fatalf("%s: isPE=%v want %v", c.name, got, c.want)
		}
	}
}

// a bottomless archive nest must never roll up as a clean, complete analysis.
// the depth cap once dropped everything past maxDepth with no incomplete flag
// and no floor (benign-by-omission); this pins the fail-closed behavior: the
// deep subtree floors to SUSPICIOUS+incomplete with a recursion-cap marker.
func TestSubmissionWorkflowDepthCapFailsClosed(t *testing.T) {
	var ts testsuite.WorkflowTestSuite
	env := ts.NewTestWorkflowEnvironment()
	a := &Analyzer{}
	// every artifact identifies as a zip, so extraction runs and capa/floss
	// (executable/PE-gated) never do; no mock needed for them.
	env.OnActivity(a.IdentifyActivity, mock.Anything, mock.Anything).Return(
		pipeline.EngineReport{Engine: "mal-ident", Verdict: pipeline.Unknown,
			Findings: []pipeline.Finding{{Engine: "mal-ident", Type: "file-type", Detail: "zip", Verdict: pipeline.Unknown}}}, nil)
	env.OnActivity(a.StaticAnalyzeActivity, mock.Anything, mock.Anything).Return(
		pipeline.EngineReport{Engine: "mal-static-yara", Verdict: pipeline.Unknown}, nil)
	// extraction always yields one child: a nest with no bottom. depth, not the
	// sha, is what advances each level, so a fixed child sha still drives it down.
	env.OnActivity(a.ExtractActivity, mock.Anything, mock.Anything).Return(
		pipeline.EngineReport{Engine: "mal-extract", Verdict: pipeline.Unknown,
			Children: []pipeline.Child{{SHA256: strings.Repeat("b", 64), Name: "inner.zip", Size: 10}}}, nil)

	env.ExecuteWorkflow(SubmissionWorkflow, pipeline.SubmissionInput{SubmissionID: "s", SHA256: strings.Repeat("a", 64)})

	if !env.IsWorkflowCompleted() {
		t.Fatal("workflow did not complete")
	}
	if err := env.GetWorkflowError(); err != nil {
		t.Fatalf("workflow error: %v", err)
	}
	var res pipeline.SubmissionResult
	if err := env.GetWorkflowResult(&res); err != nil {
		t.Fatalf("decode result: %v", err)
	}
	if !res.Incomplete {
		t.Fatal("a bottomless nest must roll up incomplete, never a clean complete result")
	}
	if res.Verdict < pipeline.Suspicious {
		t.Fatalf("depth cap must floor to at least SUSPICIOUS, got %v", res.Verdict)
	}
	hasCap := false
	for _, f := range res.Findings {
		if f.Type == "recursion-cap" {
			hasCap = true
		}
	}
	if !hasCap {
		t.Fatal("depth cap must emit a recursion-cap marker, not silently drop the subtree")
	}
}

// the submission verdict must be joined from each FINDING, not only the
// worker's self-reported top verdict: a worker that emits a MALICIOUS finding
// under an UNKNOWN top verdict must still escalate the submission. trusted code
// does not trust the worker's rollup.
func TestSubmissionWorkflowLiftsVerdictFromFindings(t *testing.T) {
	var ts testsuite.WorkflowTestSuite
	env := ts.NewTestWorkflowEnvironment()
	a := &Analyzer{}
	env.OnActivity(a.IdentifyActivity, mock.Anything, mock.Anything).Return(
		pipeline.EngineReport{Engine: "mal-ident", Verdict: pipeline.Unknown,
			Findings: []pipeline.Finding{{Engine: "mal-ident", Type: "file-type", Detail: "txt", Verdict: pipeline.Unknown}}}, nil)
	env.OnActivity(a.StaticAnalyzeActivity, mock.Anything, mock.Anything).Return(
		pipeline.EngineReport{Engine: "mal-static-yara", Verdict: pipeline.Unknown, // under-reported top
			Findings: []pipeline.Finding{{Engine: "mal-static-yara", Type: "yara", Detail: "hit", Verdict: pipeline.Malicious}}}, nil)
	env.OnActivity(a.ExtractActivity, mock.Anything, mock.Anything).Return(
		pipeline.EngineReport{Engine: "mal-extract", Verdict: pipeline.Unknown}, nil)

	env.ExecuteWorkflow(SubmissionWorkflow, pipeline.SubmissionInput{SubmissionID: "s", SHA256: strings.Repeat("a", 64)})

	if !env.IsWorkflowCompleted() || env.GetWorkflowError() != nil {
		t.Fatalf("workflow did not complete cleanly: %v", env.GetWorkflowError())
	}
	var res pipeline.SubmissionResult
	if err := env.GetWorkflowResult(&res); err != nil {
		t.Fatalf("decode result: %v", err)
	}
	if res.Verdict != pipeline.Malicious {
		t.Fatalf("verdict %v, want MALICIOUS lifted from the finding despite an UNKNOWN worker top", res.Verdict)
	}
}

func TestFileTypeOf(t *testing.T) {
	r := identWith(
		pipeline.Finding{Type: "mime-type", Detail: "application/x-elf"},
		pipeline.Finding{Type: "file-type", Detail: "elf"},
	)
	if got := fileTypeOf(r); got != "elf" {
		t.Fatalf("fileTypeOf=%q want elf", got)
	}
	if got := fileTypeOf(identWith()); got != "" {
		t.Fatalf("fileTypeOf empty=%q want empty", got)
	}
}

// a branching decompression bomb: each extraction reports more ingested bytes
// than the whole submission is allowed. the workflow must stop growing the tree
// fail-closed (incomplete + SUSPICIOUS + an ingest-cap marker), not keep writing
// distinct children into the shared vault across nodes.
func TestSubmissionWorkflowIngestBudgetFailsClosed(t *testing.T) {
	var ts testsuite.WorkflowTestSuite
	env := ts.NewTestWorkflowEnvironment()
	a := &Analyzer{}
	env.OnActivity(a.IdentifyActivity, mock.Anything, mock.Anything).Return(
		pipeline.EngineReport{Engine: "mal-ident", Verdict: pipeline.Unknown,
			Findings: []pipeline.Finding{{Engine: "mal-ident", Type: "file-type", Detail: "zip", Verdict: pipeline.Unknown}}}, nil)
	env.OnActivity(a.StaticAnalyzeActivity, mock.Anything, mock.Anything).Return(
		pipeline.EngineReport{Engine: "mal-static-yara", Verdict: pipeline.Unknown}, nil)
	// the very first extraction already reports more than the per-submission budget.
	env.OnActivity(a.ExtractActivity, mock.Anything, mock.Anything).Return(
		pipeline.EngineReport{Engine: "mal-extract", Verdict: pipeline.Unknown,
			IngestedBytes: maxSubmissionIngestBytes + 1,
			Children:      []pipeline.Child{{SHA256: strings.Repeat("b", 64), Name: "inner.zip", Size: 10}}}, nil)

	env.ExecuteWorkflow(SubmissionWorkflow, pipeline.SubmissionInput{SubmissionID: "s", SHA256: strings.Repeat("a", 64)})
	if !env.IsWorkflowCompleted() || env.GetWorkflowError() != nil {
		t.Fatalf("workflow did not complete cleanly: %v", env.GetWorkflowError())
	}
	var res pipeline.SubmissionResult
	if err := env.GetWorkflowResult(&res); err != nil {
		t.Fatal(err)
	}
	if !res.Incomplete || res.Verdict < pipeline.Suspicious {
		t.Fatalf("over-budget ingest must floor SUSPICIOUS+incomplete, got %v incomplete=%v", res.Verdict, res.Incomplete)
	}
	hasCap := false
	for _, f := range res.Findings {
		if f.Type == "ingest-cap" {
			hasCap = true
		}
	}
	if !hasCap {
		t.Fatal("the per-submission ingest cap must emit a marker, not silently stop")
	}
}

// The per-submission ingest budget must bound TOTAL vault writes, not merely stop
// ENQUEUING deeper children. Extraction is the only vault-write path, so once the
// budget trips no further ExtractActivity may be dispatched, even for nodes already
// queued. Without the halt, a branching archive drives up to maxArtifacts x the
// per-extraction cap of permanent writes. This exercises the multi-node accumulation
// the single-extraction test above cannot.
func TestSubmissionWorkflowIngestBudgetHaltsExtraction(t *testing.T) {
	var ts testsuite.WorkflowTestSuite
	env := ts.NewTestWorkflowEnvironment()
	a := &Analyzer{}
	env.OnActivity(a.IdentifyActivity, mock.Anything, mock.Anything).Return(
		pipeline.EngineReport{Engine: "mal-ident", Verdict: pipeline.Unknown,
			Findings: []pipeline.Finding{{Engine: "mal-ident", Type: "file-type", Detail: "zip", Verdict: pipeline.Unknown}}}, nil)
	env.OnActivity(a.StaticAnalyzeActivity, mock.Anything, mock.Anything).Return(
		pipeline.EngineReport{Engine: "mal-static-yara", Verdict: pipeline.Unknown}, nil)
	// Each extraction stays UNDER the budget on its own (half-plus-one) but lists four
	// fresh children. So the root (call 1) enqueues four children under budget, the
	// first child's extraction (call 2) trips the cap, and every remaining queued node
	// must be SKIPPED - not extracted. Without the halt the BFS would extract all five.
	var extractCalls int
	env.OnActivity(a.ExtractActivity, mock.Anything, mock.Anything).Return(
		func(context.Context, pipeline.SubmissionInput) (pipeline.EngineReport, error) {
			extractCalls++
			return pipeline.EngineReport{Engine: "mal-extract", Verdict: pipeline.Unknown,
				IngestedBytes: maxSubmissionIngestBytes/2 + 1,
				Children: []pipeline.Child{
					{SHA256: strings.Repeat("b", 64), Name: "c1", Size: 10},
					{SHA256: strings.Repeat("c", 64), Name: "c2", Size: 10},
					{SHA256: strings.Repeat("d", 64), Name: "c3", Size: 10},
					{SHA256: strings.Repeat("e", 64), Name: "c4", Size: 10},
				}}, nil
		})

	env.ExecuteWorkflow(SubmissionWorkflow, pipeline.SubmissionInput{SubmissionID: "s", SHA256: strings.Repeat("a", 64)})
	if !env.IsWorkflowCompleted() || env.GetWorkflowError() != nil {
		t.Fatalf("workflow did not complete cleanly: %v", env.GetWorkflowError())
	}
	// root (under budget, enqueues 4) + the one child that trips it = 2; all later
	// queued nodes are halted, never extracted.
	if extractCalls != 2 {
		t.Fatalf("ingest budget must HALT extraction after it trips (want 2 extract calls: root + tripping child), got %d", extractCalls)
	}
	var res pipeline.SubmissionResult
	if err := env.GetWorkflowResult(&res); err != nil {
		t.Fatal(err)
	}
	if !res.Incomplete || res.Verdict < pipeline.Suspicious {
		t.Fatalf("tripped ingest budget must floor SUSPICIOUS+incomplete, got %v incomplete=%v", res.Verdict, res.Incomplete)
	}
}

// when the AI plane is enabled, the deterministic workflow hands off to the
// enrichment child (ABANDON) and completes immediately with its verdict UNCHANGED
// - the AI plane can never alter or delay the spine.
func TestSubmissionWorkflowStartsEnrichmentChild(t *testing.T) {
	t.Setenv("MAL_AGENTS_URL", "http://127.0.0.1:9") // enable the handoff
	var ts testsuite.WorkflowTestSuite
	env := ts.NewTestWorkflowEnvironment()
	a := &Analyzer{} // no agents wired: the child's roster activity no-ops
	env.OnActivity(a.IdentifyActivity, mock.Anything, mock.Anything).Return(
		pipeline.EngineReport{Engine: "mal-ident", Verdict: pipeline.Unknown,
			Findings: []pipeline.Finding{{Engine: "mal-ident", Type: "file-type", Detail: "txt", Verdict: pipeline.Unknown}}}, nil)
	env.OnActivity(a.StaticAnalyzeActivity, mock.Anything, mock.Anything).Return(
		pipeline.EngineReport{Engine: "mal-static-yara", Verdict: pipeline.Unknown}, nil)
	env.OnActivity(a.ExtractActivity, mock.Anything, mock.Anything).Return(
		pipeline.EngineReport{Engine: "mal-extract", Verdict: pipeline.Unknown}, nil)
	// the enrichment child + its activities must be registered so the handoff runs.
	env.RegisterWorkflow(AgentGraphWorkflow)
	env.RegisterActivity(a.RunRosterActivity)
	env.RegisterActivity(a.GateActivity)
	env.RegisterActivity(a.IngestLearningActivity)
	env.RegisterActivity(a.RecordOutcomeActivity)

	env.ExecuteWorkflow(SubmissionWorkflow, pipeline.SubmissionInput{SubmissionID: "s", SHA256: strings.Repeat("a", 64)})
	if !env.IsWorkflowCompleted() || env.GetWorkflowError() != nil {
		t.Fatalf("workflow did not complete cleanly with the enrichment handoff: %v", env.GetWorkflowError())
	}
	var res pipeline.SubmissionResult
	if err := env.GetWorkflowResult(&res); err != nil {
		t.Fatal(err)
	}
	if res.Verdict != pipeline.Unknown {
		t.Fatalf("the enrichment handoff must not change the deterministic verdict, got %v", res.Verdict)
	}
}
