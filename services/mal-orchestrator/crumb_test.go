package main

import (
	"strings"
	"testing"
)

// crumb feeds Finding.Path, which is emitted per non-root artifact and flows into
// the workflow result. A compromised extractor can hand it names at the broker's
// 8 KiB ceiling at every tree level; without a length bound, one hostile archive
// inflates the result past Temporal's payload limit and the workflow never records
// a verdict. This pins the bound (each segment and the whole path) while keeping
// the existing control-char stripping and normal-name behavior.
func TestCrumbBoundsHostileNames(t *testing.T) {
	huge := strings.Repeat("A", 8192) // the broker's maxStringLen ceiling

	seg := crumb("", huge)
	if len(seg) > maxCrumbSegment+1 { // +1 for the "~" truncation marker
		t.Fatalf("segment not clamped: got %d bytes, want <= %d", len(seg), maxCrumbSegment+1)
	}

	// a deep chain of huge names stays bounded by maxCrumbPath, not sum-of-segments.
	p := ""
	for i := 0; i < maxDepth; i++ {
		p = crumb(p, huge)
	}
	if len(p) > maxCrumbPath+1 {
		t.Fatalf("path not clamped: got %d bytes, want <= %d", len(p), maxCrumbPath+1)
	}

	// control chars are still stripped (existing behavior preserved).
	if got := crumb("", "a\nb\x1bc"); got != "a.b.c" {
		t.Fatalf("control-strip regressed: got %q", got)
	}
	// a normal short breadcrumb is unchanged (no marker, no clamp).
	if got := crumb("outer.zip", "inner.exe"); got != "outer.zip!inner.exe" {
		t.Fatalf("normal crumb changed: got %q", got)
	}
}
