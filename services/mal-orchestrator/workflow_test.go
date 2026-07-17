package main

import (
	"testing"

	"github.com/COLONAYUSH/OpenMalLab/internal/pipeline"
)

func identWith(findings ...pipeline.Finding) pipeline.EngineReport {
	return pipeline.EngineReport{Engine: "mal-ident", Findings: findings}
}

// capa is expensive and only meaningful on executables, so the workflow gates
// it on magika's content-based identification. this pins that gate.
func TestIsExecutableGatesCapa(t *testing.T) {
	cases := []struct {
		name  string
		ident pipeline.EngineReport
		want  bool
	}{
		{"elf by label", identWith(pipeline.Finding{Type: "file-type", Detail: "elf"}), true},
		{"pe by label", identWith(pipeline.Finding{Type: "file-type", Detail: "pe"}), true},
		{"macho by label", identWith(pipeline.Finding{Type: "file-type", Detail: "macho"}), true},
		{"by group", identWith(pipeline.Finding{Type: "file-type-group", Detail: "executable"}), true},
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
