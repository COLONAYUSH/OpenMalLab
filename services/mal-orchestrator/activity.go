// the engine activities are the enforcement path from DESIGN-AUDIT RC-2, made
// real: every engine runs inside a jailed single-use container, the worker's
// raw bytes go only to a jailed broker, and the orchestrator decodes nothing
// but the broker's validated output. one code path for every engine, so a new
// engine cannot accidentally invent a weaker boundary. every failure floors
// upward, never down to benign.
package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/COLONAYUSH/OpenMalLab/internal/pipeline"
	"github.com/docker/docker/api/types/mount"
	"github.com/docker/docker/client"
	"go.temporal.io/sdk/activity"
	"go.temporal.io/sdk/temporal"
	"regexp"
)

// maxIngestBytes bounds a single extracted child the orchestrator will pull
// into the vault. the extractor already caps entries, but the orchestrator
// trusts nothing the worker did; this is its own limit.
const maxIngestBytes = 128 << 20

// nobodyUID is the unprivileged uid every jailed worker runs as; the per-run
// staging dir is owned by it so the extractor can write its children.
const nobodyUID = 65534

// Analyzer owns the docker handle and the jail parameters. registered as the
// activity receiver so the workflow can call the engine activities by name.
type Analyzer struct {
	docker       *client.Client
	vaultVolume  string // volume name, mounted into workers by sha subpath
	vaultPath    string // the same vault, mounted in THIS process, for ingest writes
	stagingPath  string // extract-staging volume, mounted in this process
	stagingVol   string // extract-staging volume name, for the extractor's /out
	workerImage  string
	identImage   string
	extractImage string
	capaImage    string
	flossImage   string
	brokerImage  string
	workerWall   time.Duration
	identWall    time.Duration
	extractWall  time.Duration
	capaWall     time.Duration
	flossWall    time.Duration
	brokerWall   time.Duration
	// capa and floss are memory- and disk-hungry (both run vivisect emulation);
	// these raise their jails' caps above the tight default. the light engines
	// never touch them.
	capaMemBytes  int64
	capaScratch   string
	flossMemBytes int64
	flossScratch  string
}

// the sha is about to be spliced into an engine api mount spec; it gets
// validated even though we computed it ourselves. defense costs one regexp.
var shaHex = regexp.MustCompile(`^[a-f0-9]{64}$`)

// brokerFinding, brokerChild, brokerReport mirror the broker's validated wire
// shape. the orchestrator's strict decode is of the broker's contract, never
// of anything a worker invents.
type brokerFinding struct {
	Engine  string `json:"engine"`
	Type    string `json:"type"`
	Detail  string `json:"detail"`
	Attck   string `json:"attck"`
	Verdict string `json:"verdict"`
}

type brokerChild struct {
	SHA256 string `json:"sha256"`
	Size   uint64 `json:"size"`
	Name   string `json:"name"`
}

type brokerReport struct {
	Engine     string          `json:"engine"`
	Findings   []brokerFinding `json:"findings"`
	Children   []brokerChild   `json:"children"`
	Verdict    string          `json:"verdict"`
	Incomplete bool            `json:"incomplete"`
}

// StaticAnalyzeActivity runs the yara engine over the artifact, jailed.
func (a *Analyzer) StaticAnalyzeActivity(ctx context.Context, in pipeline.SubmissionInput) (pipeline.EngineReport, error) {
	br, err := a.runWorkerThroughBroker(ctx, jailSpec{
		image:        a.workerImage,
		mounts:       []mount.Mount{sampleMount(a.vaultVolume, in.SHA256)},
		wallClock:    a.workerWall,
		submissionID: in.SubmissionID,
	}, in.SHA256)
	if err != nil {
		return pipeline.EngineReport{}, err
	}
	return mapReport(br), nil
}

// IdentifyActivity runs magika over the artifact, jailed. identification is
// evidence like any other engine output; it crosses the same broker.
func (a *Analyzer) IdentifyActivity(ctx context.Context, in pipeline.SubmissionInput) (pipeline.EngineReport, error) {
	br, err := a.runWorkerThroughBroker(ctx, jailSpec{
		image:        a.identImage,
		mounts:       []mount.Mount{sampleMount(a.vaultVolume, in.SHA256)},
		wallClock:    a.identWall,
		submissionID: in.SubmissionID,
	}, in.SHA256)
	if err != nil {
		return pipeline.EngineReport{}, err
	}
	return mapReport(br), nil
}

// CapaActivity runs Mandiant capa over the artifact, jailed. it reports
// ATT&CK/MBC-mapped capabilities as behavioral evidence. the workflow only
// dispatches it for executables (capa cannot analyze anything else), so it is
// not run per-artifact like the format-agnostic engines.
//
// capa is the heavy engine: vivisect is memory- and time-hungry, and it needs
// a writable HOME for its rule cache. so this jail raises memory and scratch
// and points HOME/TMPDIR at the writable scratch tmpfs. every security flag of
// the recipe (no network, caps dropped, read-only rootfs, seccomp, non-root,
// noexec scratch) is unchanged.
func (a *Analyzer) CapaActivity(ctx context.Context, in pipeline.SubmissionInput) (pipeline.EngineReport, error) {
	br, err := a.runWorkerThroughBroker(ctx, jailSpec{
		image:        a.capaImage,
		mounts:       []mount.Mount{sampleMount(a.vaultVolume, in.SHA256)},
		wallClock:    a.capaWall,
		submissionID: in.SubmissionID,
		env:          []string{"HOME=/scratch", "TMPDIR=/scratch"},
		memoryBytes:  a.capaMemBytes,
		scratchSize:  a.capaScratch,
	}, in.SHA256)
	if err != nil {
		return pipeline.EngineReport{}, err
	}
	return mapReport(br), nil
}

// FlossActivity runs Mandiant FLOSS over the artifact, jailed. it recovers
// static and, via vivisect emulation, stack/tight/decoded strings. the
// workflow only dispatches it for PE samples (FLOSS decodes PE and shellcode
// only). like capa it is memory-hungry and needs a writable HOME; the emulation
// phase can be slow, so its wall clock is generous and a timeout floors the
// node fail-closed at low confidence.
func (a *Analyzer) FlossActivity(ctx context.Context, in pipeline.SubmissionInput) (pipeline.EngineReport, error) {
	br, err := a.runWorkerThroughBroker(ctx, jailSpec{
		image:        a.flossImage,
		mounts:       []mount.Mount{sampleMount(a.vaultVolume, in.SHA256)},
		wallClock:    a.flossWall,
		submissionID: in.SubmissionID,
		env:          []string{"HOME=/scratch", "TMPDIR=/scratch"},
		memoryBytes:  a.flossMemBytes,
		scratchSize:  a.flossScratch,
	}, in.SHA256)
	if err != nil {
		return pipeline.EngineReport{}, err
	}
	return mapReport(br), nil
}

// ExtractActivity unpacks one level of a container. it is the only activity
// that grants the worker a writable mount (/out, a per-run staging subpath),
// and the only one that ingests: it reads the children the extractor staged,
// RE-HASHES each one (never trusting the worker's claimed hash or name), and
// content-addresses the verified bytes into the vault. children that fail to
// re-hash are dropped and the node is marked incomplete.
func (a *Analyzer) ExtractActivity(ctx context.Context, in pipeline.SubmissionInput) (pipeline.EngineReport, error) {
	logger := activity.GetLogger(ctx)
	var none pipeline.EngineReport

	if !shaHex.MatchString(in.SHA256) {
		return none, temporal.NewNonRetryableApplicationError(
			"submission sha256 is not 64 lowercase hex chars", "BadInput", nil)
	}

	// a fresh, unique output area for this run. hex only, so it is always a
	// safe path segment.
	nonce := make([]byte, 16)
	if _, err := rand.Read(nonce); err != nil {
		return none, fmt.Errorf("nonce: %w", err)
	}
	runID := hex.EncodeToString(nonce)
	stageDir := filepath.Join(a.stagingPath, runID)
	if err := os.MkdirAll(stageDir, 0o700); err != nil {
		return none, fmt.Errorf("staging dir: %w", err)
	}
	// arm cleanup the instant the dir exists, so every later return still
	// removes it (a leak here is what a crash-time sweep also guards).
	defer os.RemoveAll(stageDir)
	// the extractor runs as nobody and writes its children here, so the per-run
	// dir must be owned by nobody. it is a fresh, unique, empty dir.
	if err := os.Chown(stageDir, nobodyUID, nobodyUID); err != nil {
		return none, fmt.Errorf("staging chown: %w", err)
	}

	br, err := a.runWorkerThroughBroker(ctx, jailSpec{
		image:        a.extractImage,
		mounts:       []mount.Mount{sampleMount(a.vaultVolume, in.SHA256), outMount(a.stagingVol, runID)},
		wallClock:    a.extractWall,
		submissionID: in.SubmissionID,
	}, in.SHA256)
	if err != nil {
		return none, err
	}
	rep := mapReport(br)

	// ingest: re-hash every staged child and content-address it into the vault.
	// the manifest's sha is a claim; the bytes are the truth.
	var verified []pipeline.Child
	for _, c := range br.Children {
		size, err := a.ingestChild(stageDir, c.SHA256)
		if err != nil {
			rep.Incomplete = true
			logger.Warn("dropping an unverifiable extracted child",
				"submission", in.SubmissionID, "claimed", c.SHA256, "err", err.Error())
			rep.Findings = append(rep.Findings, pipeline.Finding{
				Engine:     "mal-extract",
				Type:       "ingest-rejected",
				Detail:     "an extracted child failed re-hash and was dropped",
				Verdict:    pipeline.Suspicious,
				Confidence: pipeline.ConfLow,
			})
			rep.Verdict = pipeline.Max(rep.Verdict, pipeline.Suspicious)
			continue
		}
		verified = append(verified, pipeline.Child{SHA256: c.SHA256, Size: size, Name: c.Name})
	}
	rep.Children = verified

	logger.Info("extraction complete",
		"submission", in.SubmissionID, "sha256", in.SHA256,
		"children", len(rep.Children), "verdict", rep.Verdict.String(), "incomplete", rep.Incomplete)
	return rep, nil
}

// sweepStaging clears leftover per-run staging dirs at boot. per-run dirs are
// always removed after their extraction; anything here after a restart is
// crash debris, the staging analogue of reapLeakedJails.
func (a *Analyzer) sweepStaging() int {
	entries, err := os.ReadDir(a.stagingPath)
	if err != nil {
		return 0
	}
	n := 0
	for _, e := range entries {
		if os.RemoveAll(filepath.Join(a.stagingPath, e.Name())) == nil {
			n++
		}
	}
	return n
}

// ingestChild copies one staged child into the vault, streaming through a
// hasher, and only accepts it if the recomputed sha256 matches the name the
// extractor gave the file. this is what lets the orchestrator distrust the
// worker completely: a compromised extractor cannot smuggle bytes under a hash
// they do not match, and the vault is only ever keyed by a hash we computed.
func (a *Analyzer) ingestChild(stageDir, claimedSHA string) (uint64, error) {
	if !shaHex.MatchString(claimedSHA) {
		return 0, fmt.Errorf("child sha not hex")
	}
	src := filepath.Join(stageDir, claimedSHA)
	info, err := os.Stat(src)
	if err != nil {
		return 0, fmt.Errorf("stat child: %w", err)
	}
	if !info.Mode().IsRegular() {
		return 0, fmt.Errorf("child is not a regular file")
	}
	if info.Size() > maxIngestBytes {
		return 0, fmt.Errorf("child exceeds ingest cap")
	}

	f, err := os.Open(src)
	if err != nil {
		return 0, fmt.Errorf("open child: %w", err)
	}
	defer f.Close()

	tmp, err := os.CreateTemp(a.vaultPath, ".ingest-*")
	if err != nil {
		return 0, fmt.Errorf("vault temp: %w", err)
	}
	tmpName := tmp.Name()
	h := sha256.New()
	n, err := io.Copy(io.MultiWriter(tmp, h), io.LimitReader(f, maxIngestBytes+1))
	tmp.Close()
	if err != nil || n > maxIngestBytes {
		os.Remove(tmpName)
		return 0, fmt.Errorf("copy child: %w", err)
	}
	sum := hex.EncodeToString(h.Sum(nil))
	if sum != claimedSHA {
		// the bytes do not match the name the worker gave them: corruption or a
		// lie. either way we refuse it.
		os.Remove(tmpName)
		return 0, fmt.Errorf("child hash mismatch: named %s, is %s", claimedSHA, sum)
	}
	dst := filepath.Join(a.vaultPath, sum)
	if _, err := os.Stat(dst); err == nil {
		// already in the vault (dedup across submissions); drop the temp.
		os.Remove(tmpName)
		return uint64(n), nil
	}
	// own it as nobody, 0600: the orchestrator writes as root, but the jailed
	// workers that will analyze this child read it as nobody via subpath, so it
	// must be readable by that uid, exactly like a gateway-seeded upload.
	_ = os.Chown(tmpName, nobodyUID, nobodyUID)
	_ = os.Chmod(tmpName, 0o600)
	if err := os.Rename(tmpName, dst); err != nil {
		os.Remove(tmpName)
		return 0, fmt.Errorf("vault rename: %w", err)
	}
	return uint64(n), nil
}

// runWorkerThroughBroker is the one enforcement path every engine goes through:
// the given jailed worker spec, its raw stdout piped into a jailed broker, then
// a strict decode of the broker's validated bytes. it returns the broker's
// report; callers map it onto the pipeline types. sha is the artifact's hash,
// validated before it is ever used in a mount spec.
func (a *Analyzer) runWorkerThroughBroker(ctx context.Context, spec jailSpec, sha string) (*brokerReport, error) {
	logger := activity.GetLogger(ctx)

	if !shaHex.MatchString(sha) {
		return nil, temporal.NewNonRetryableApplicationError(
			"submission sha256 is not 64 lowercase hex chars", "BadInput", nil)
	}

	// 1) the jailed worker. hostile bytes are parsed only in there.
	scan, err := runJailed(ctx, a.docker, spec)
	if err != nil {
		return nil, fmt.Errorf("worker jail: %w", err)
	}
	if len(scan.stderr) > 0 {
		logger.Warn("worker stderr (sanitized)",
			"submission", spec.submissionID,
			"bytes", len(scan.stderr),
			"preview", sanitizeForLog(scan.stderr, 200))
	}
	if scan.exitCode != 0 {
		return nil, fmt.Errorf("worker exited %d", scan.exitCode)
	}
	if scan.stdoutTruncated {
		return nil, temporal.NewNonRetryableApplicationError(
			"worker output exceeded the 1MiB cap", "OversizeOutput", nil)
	}

	// 2) the jailed broker: the one and only decoder of raw worker bytes.
	brok, err := runJailed(ctx, a.docker, jailSpec{
		image:        a.brokerImage,
		stdin:        scan.stdout,
		wallClock:    a.brokerWall,
		submissionID: spec.submissionID,
	})
	if err != nil {
		return nil, fmt.Errorf("broker jail: %w", err)
	}
	if brok.exitCode != 0 {
		return nil, temporal.NewNonRetryableApplicationError(
			fmt.Sprintf("broker rejected worker output: %s", sanitizeForLog(brok.stderr, 200)),
			"BrokerReject", nil)
	}
	if brok.stdoutTruncated {
		return nil, temporal.NewNonRetryableApplicationError(
			"broker output exceeded the 1MiB cap", "OversizeOutput", nil)
	}

	// 3) strict decode of broker-validated bytes only.
	dec := json.NewDecoder(bytes.NewReader(brok.stdout))
	dec.DisallowUnknownFields()
	var br brokerReport
	if err := dec.Decode(&br); err != nil {
		return nil, temporal.NewNonRetryableApplicationError(
			"broker output failed strict decode: "+err.Error(), "BrokerContract", nil)
	}
	return &br, nil
}

// mapReport turns the broker's validated report onto the typed lattice.
// anything unparseable fails closed (incomplete, never a milder verdict).
// children are handled by the caller after re-hashing, not here.
func mapReport(br *brokerReport) pipeline.EngineReport {
	rep := pipeline.EngineReport{Engine: br.Engine, Incomplete: br.Incomplete}
	v, ok := pipeline.ParseVerdict(br.Verdict)
	if !ok {
		rep.Incomplete = true
	}
	rep.Verdict = v
	for _, f := range br.Findings {
		fv, ok := pipeline.ParseVerdict(f.Verdict)
		if !ok {
			rep.Incomplete = true
		}
		rep.Findings = append(rep.Findings, pipeline.Finding{
			Engine:     f.Engine,
			Type:       f.Type,
			Detail:     f.Detail,
			Attck:      f.Attck,
			Verdict:    fv,
			Confidence: pipeline.ConfidenceFor(f.Engine, f.Type, fv),
		})
	}
	return rep
}
