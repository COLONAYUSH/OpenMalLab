package main

import (
	"strings"
	"testing"

	"github.com/docker/docker/api/types/mount"
)

// TestJailRecipePinsTheBoundaryProof pins every field of the jail to the
// recipe proven live by deploy/proof/boundary-proof.sh. if someone loosens
// the jail, this fails before any container ever runs.
func TestJailRecipePinsTheBoundaryProof(t *testing.T) {
	hc := jailedHostConfig()

	if string(hc.NetworkMode) != "none" {
		t.Fatalf("network mode %q, want none", hc.NetworkMode)
	}
	if len(hc.CapDrop) != 1 || hc.CapDrop[0] != "ALL" {
		t.Fatalf("cap drop %v, want [ALL]", hc.CapDrop)
	}
	if len(hc.SecurityOpt) != 2 ||
		hc.SecurityOpt[0] != "no-new-privileges" ||
		hc.SecurityOpt[1] != "seccomp=builtin" {
		t.Fatalf("security opt %v", hc.SecurityOpt)
	}
	for _, o := range hc.SecurityOpt {
		if strings.Contains(o, "unconfined") {
			t.Fatalf("unconfined crept into the jail: %v", hc.SecurityOpt)
		}
	}
	if !hc.ReadonlyRootfs {
		t.Fatal("rootfs not read-only")
	}
	if hc.Privileged {
		t.Fatal("privileged jail")
	}
	if len(hc.Tmpfs) != 1 || hc.Tmpfs["/scratch"] != "rw,noexec,nosuid,nodev,size=64m" {
		t.Fatalf("tmpfs %v", hc.Tmpfs)
	}
	if hc.LogConfig.Type != "none" {
		t.Fatalf("log driver %q, want none (we capture the stream, bounded)", hc.LogConfig.Type)
	}
	if hc.Memory != 512<<20 {
		t.Fatalf("memory %d, want %d", hc.Memory, int64(512<<20))
	}
	if hc.MemorySwap != hc.Memory {
		t.Fatalf("swap %d must equal memory %d: zero swap headroom", hc.MemorySwap, hc.Memory)
	}
	if hc.NanoCPUs != 1_000_000_000 {
		t.Fatalf("nanocpus %d, want one cpu", hc.NanoCPUs)
	}
	if hc.PidsLimit == nil || *hc.PidsLimit != 128 {
		t.Fatalf("pids limit %v, want 128", hc.PidsLimit)
	}
	if string(hc.CgroupnsMode) != "private" {
		t.Fatalf("cgroupns %q, want private", hc.CgroupnsMode)
	}
	if string(hc.IpcMode) != "private" {
		t.Fatalf("ipc mode %q, want private", hc.IpcMode)
	}
	if len(hc.Binds) != 0 || len(hc.Devices) != 0 || len(hc.DeviceRequests) != 0 {
		t.Fatal("stray binds or devices in the jail")
	}
}

func TestJailedContainersCarryNothing(t *testing.T) {
	cfg := jailedConfig("img")
	if len(cfg.Env) != 0 {
		t.Fatalf("jail carries environment: %v", cfg.Env)
	}
	if cfg.User != "65534:65534" {
		t.Fatalf("jail user %q, want nobody", cfg.User)
	}
	if cfg.Labels[jailLabel] != "1" {
		t.Fatal("jail missing the reaper label")
	}
	if cfg.OpenStdin || cfg.StdinOnce {
		t.Fatal("stdin must be opt-in per run, not default")
	}
}

func TestSampleMountIsOneReadOnlyFile(t *testing.T) {
	sha := strings.Repeat("a", 64)
	m := sampleMount("openmallab-vault", sha)
	if m.Type != mount.TypeVolume {
		t.Fatalf("mount type %q", m.Type)
	}
	if !m.ReadOnly {
		t.Fatal("sample mount not read-only")
	}
	if m.Target != "/in/sample" {
		t.Fatalf("target %q", m.Target)
	}
	if m.Source != "openmallab-vault" {
		t.Fatalf("source %q", m.Source)
	}
	if m.VolumeOptions == nil || m.VolumeOptions.Subpath != sha {
		t.Fatalf("subpath must pin the one file: %+v", m.VolumeOptions)
	}
}

func TestOutMountIsTheOneWritableMount(t *testing.T) {
	m := outMount("openmallab-extract-staging", "deadbeef")
	if m.Type != mount.TypeVolume {
		t.Fatalf("out mount type %q", m.Type)
	}
	if m.ReadOnly {
		t.Fatal("out mount must be writable; it is where children are staged")
	}
	if m.Target != "/out" {
		t.Fatalf("out target %q, want /out", m.Target)
	}
	if m.VolumeOptions == nil || m.VolumeOptions.Subpath != "deadbeef" {
		t.Fatalf("out mount must be a per-run subpath: %+v", m.VolumeOptions)
	}
}

// the extract jail differs from a scan only by adding /out; every other
// hardening property is identical (the recipe is shared). this pins the two
// mounts an extractor gets: the sample read-only, the output writable, nothing
// else.
func TestExtractJailIsAScanJailPlusOneWritableOut(t *testing.T) {
	sample := sampleMount("openmallab-vault", strings.Repeat("a", 64))
	out := outMount("openmallab-extract-staging", "runid")
	mounts := []mount.Mount{sample, out}

	writable := 0
	for _, m := range mounts {
		if !m.ReadOnly {
			writable++
			if m.Target != "/out" {
				t.Fatalf("the only writable mount must be /out, got %q", m.Target)
			}
		}
	}
	if writable != 1 {
		t.Fatalf("an extractor must have exactly one writable mount, got %d", writable)
	}
	// the hostconfig is the same locked-down recipe regardless of mounts.
	if !jailedHostConfig().ReadonlyRootfs {
		t.Fatal("extract jail must still have a read-only rootfs")
	}
}

// per-engine overrides may only add env and raise resource caps; they must
// never touch the security posture. this pins that: after applying capa's
// heavy-engine overrides, every hardening flag is still exactly the default.
func TestOverridesRaiseCapsButNeverLoosenSecurity(t *testing.T) {
	cfg := jailedConfig("openmallab/mal-capa:m0")
	hc := jailedHostConfig()
	applyOverrides(cfg, hc, jailSpec{
		env:         []string{"HOME=/scratch", "TMPDIR=/scratch"},
		memoryBytes: 2 << 30,
		scratchSize: "256m",
	})

	// the overrides took effect.
	if hc.Memory != 2<<30 || hc.MemorySwap != 2<<30 {
		t.Fatalf("memory override not applied: %d/%d", hc.Memory, hc.MemorySwap)
	}
	if hc.Tmpfs["/scratch"] != "rw,noexec,nosuid,nodev,size=256m" {
		t.Fatalf("scratch override wrong: %q", hc.Tmpfs["/scratch"])
	}
	if len(cfg.Env) != 2 || cfg.Env[0] != "HOME=/scratch" {
		t.Fatalf("env override wrong: %v", cfg.Env)
	}
	// and none of the security posture moved.
	if string(hc.NetworkMode) != "none" || len(hc.CapDrop) != 1 || hc.CapDrop[0] != "ALL" ||
		!hc.ReadonlyRootfs || hc.Privileged || cfg.User != "65534:65534" {
		t.Fatal("an override loosened the security posture")
	}
	if !contains(hc.Tmpfs["/scratch"], "noexec") {
		t.Fatal("scratch lost noexec")
	}
	// a zero-value spec changes nothing.
	cfg2 := jailedConfig("x")
	hc2 := jailedHostConfig()
	applyOverrides(cfg2, hc2, jailSpec{})
	if hc2.Memory != 512<<20 || len(cfg2.Env) != 0 || hc2.Tmpfs["/scratch"] != "rw,noexec,nosuid,nodev,size=64m" {
		t.Fatal("zero-value override must be a no-op")
	}
}

func contains(s, sub string) bool { return strings.Contains(s, sub) }

func TestShaValidationIsStrict(t *testing.T) {
	good := strings.Repeat("0123456789abcdef", 4)
	if !shaHex.MatchString(good) {
		t.Fatal("rejected a valid sha")
	}
	for _, bad := range []string{
		"", "short",
		strings.Repeat("A", 64),          // uppercase
		strings.Repeat("a", 63),          // short
		strings.Repeat("a", 65),          // long
		strings.Repeat("a", 63) + "/",    // path metachar
		"../" + strings.Repeat("a", 61),  // traversal
		strings.Repeat("a", 63) + "\x00", // nul
	} {
		if shaHex.MatchString(bad) {
			t.Fatalf("accepted bad sha %q", bad)
		}
	}
}

func TestCappedBufferNeverStallsAndFlagsTruncation(t *testing.T) {
	c := &cappedBuffer{max: 8}
	n, err := c.Write([]byte("0123456789"))
	if err != nil || n != 10 {
		t.Fatalf("capped writer must swallow the full write: n=%d err=%v", n, err)
	}
	if c.buf.String() != "01234567" || !c.truncated {
		t.Fatalf("kept %q truncated=%v", c.buf.String(), c.truncated)
	}
	// exact fit does not flag
	c2 := &cappedBuffer{max: 4}
	_, _ = c2.Write([]byte("abcd"))
	if c2.truncated {
		t.Fatal("exact fit wrongly flagged as truncated")
	}
	// later writes past the cap still report success and flag
	n, err = c2.Write([]byte("x"))
	if err != nil || n != 1 || !c2.truncated {
		t.Fatalf("overflow write: n=%d err=%v truncated=%v", n, err, c2.truncated)
	}
}

func TestSanitizeForLogNeutralizesHostileBytes(t *testing.T) {
	in := []byte("ok\x1b[31mESC\r\nnul\x00tab\tdone\x7f")
	out := sanitizeForLog(in, 1024)
	for _, c := range []byte(out) {
		if c < 0x20 || c > 0x7e {
			t.Fatalf("non-printable byte %q survived: %q", c, out)
		}
	}
	if !strings.Contains(out, "ok") || !strings.Contains(out, "done") {
		t.Fatalf("legitimate text mangled: %q", out)
	}
	if got := sanitizeForLog([]byte("aaaa"), 2); got != "aa" {
		t.Fatalf("length cap broken: %q", got)
	}
}
