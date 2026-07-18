package main

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"
)

// ingestChild is the extractor trust boundary: it re-hashes every staged child,
// refuses symlinks (so a compromised extractor cannot redirect the root
// orchestrator's reads), refuses hash mismatches (so it cannot smuggle bytes
// into the content-addressed vault under a chosen name), and enforces the size
// cap. none of this ran in CI before; these drive the real function.

func shaOf(b []byte) string { s := sha256.Sum256(b); return hex.EncodeToString(s[:]) }

func stageFile(t *testing.T, dir, name string, body []byte) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, name), body, 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestIngestChildHappyPath(t *testing.T) {
	a := &Analyzer{vaultPath: t.TempDir()}
	stage := t.TempDir()
	body := []byte("benign child bytes")
	sum := shaOf(body)
	stageFile(t, stage, sum, body)

	n, err := a.ingestChild(stage, sum)
	if err != nil {
		t.Fatalf("happy path errored: %v", err)
	}
	if n != uint64(len(body)) {
		t.Fatalf("returned size %d, want %d", n, len(body))
	}
	got, err := os.ReadFile(filepath.Join(a.vaultPath, sum))
	if err != nil || string(got) != string(body) {
		t.Fatalf("vault content wrong: err=%v got=%q", err, got)
	}
}

func TestIngestChildRejectsHashMismatch(t *testing.T) {
	a := &Analyzer{vaultPath: t.TempDir()}
	stage := t.TempDir()
	// name the file a valid-looking but WRONG sha: the worker's claim, not the truth.
	wrong := shaOf([]byte("a different thing"))
	stageFile(t, stage, wrong, []byte("actual bytes"))

	if _, err := a.ingestChild(stage, wrong); err == nil {
		t.Fatal("a hash mismatch must be rejected")
	}
	if _, err := os.Stat(filepath.Join(a.vaultPath, wrong)); !os.IsNotExist(err) {
		t.Fatal("nothing may land in the vault under a mismatched hash")
	}
}

func TestIngestChildRejectsSymlink(t *testing.T) {
	a := &Analyzer{vaultPath: t.TempDir()}
	stage := t.TempDir()
	secret := filepath.Join(t.TempDir(), "host-secret")
	if err := os.WriteFile(secret, []byte("host secret bytes"), 0o600); err != nil {
		t.Fatal(err)
	}
	// stage /out/<valid-sha> as a symlink to a host path: Lstat + O_NOFOLLOW must refuse it.
	name := shaOf([]byte("whatever"))
	if err := os.Symlink(secret, filepath.Join(stage, name)); err != nil {
		t.Skipf("symlink unsupported here: %v", err)
	}
	if _, err := a.ingestChild(stage, name); err == nil {
		t.Fatal("a symlinked child must be refused")
	}
	entries, _ := os.ReadDir(a.vaultPath)
	for _, e := range entries {
		if b, _ := os.ReadFile(filepath.Join(a.vaultPath, e.Name())); string(b) == "host secret bytes" {
			t.Fatal("symlink target bytes leaked into the vault")
		}
	}
}

func TestIngestChildEnforcesSizeCap(t *testing.T) {
	a := &Analyzer{vaultPath: t.TempDir()}
	stage := t.TempDir()
	saved := maxIngestBytes
	maxIngestBytes = 8
	defer func() { maxIngestBytes = saved }()

	body := []byte("this is comfortably more than eight bytes")
	sum := shaOf(body)
	stageFile(t, stage, sum, body)
	if _, err := a.ingestChild(stage, sum); err == nil {
		t.Fatal("an oversize child must be rejected")
	}
	if _, err := os.Stat(filepath.Join(a.vaultPath, sum)); !os.IsNotExist(err) {
		t.Fatal("an oversize child must not be ingested")
	}
}

func TestIngestChildRejectsNonHexName(t *testing.T) {
	a := &Analyzer{vaultPath: t.TempDir()}
	if _, err := a.ingestChild(t.TempDir(), "not-a-64-hex-sha"); err == nil {
		t.Fatal("a non-hex claimed sha must be rejected before any file access")
	}
}
