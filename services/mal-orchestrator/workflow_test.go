package main

import (
	"testing"

	"github.com/COLONAYUSH/OpenMalLab/internal/pipeline"
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
