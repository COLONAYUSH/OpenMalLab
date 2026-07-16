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
	"encoding/json"
	"fmt"
	"regexp"
	"time"

	"github.com/COLONAYUSH/OpenMalLab/internal/pipeline"
	"github.com/docker/docker/api/types/mount"
	"github.com/docker/docker/client"
	"go.temporal.io/sdk/activity"
	"go.temporal.io/sdk/temporal"
)

// Analyzer owns the docker handle and the jail parameters. registered as the
// activity receiver so the workflow can call the engine activities by name.
type Analyzer struct {
	docker      *client.Client
	vaultVolume string
	workerImage string
	identImage  string
	brokerImage string
	workerWall  time.Duration
	identWall   time.Duration
	brokerWall  time.Duration
}

// the sha is about to be spliced into an engine api mount spec; it gets
// validated even though we computed it ourselves. defense costs one regexp.
var shaHex = regexp.MustCompile(`^[a-f0-9]{64}$`)

// brokerFinding and brokerReport mirror the broker's validated wire shape.
// they exist so the orchestrator's strict decode is of the broker's contract,
// not of anything a worker invents.
type brokerFinding struct {
	Engine  string `json:"engine"`
	Type    string `json:"type"`
	Detail  string `json:"detail"`
	Attck   string `json:"attck"`
	Verdict string `json:"verdict"`
}

type brokerReport struct {
	Engine     string          `json:"engine"`
	Findings   []brokerFinding `json:"findings"`
	Verdict    string          `json:"verdict"`
	Incomplete bool            `json:"incomplete"`
}

// StaticAnalyzeActivity runs the yara engine over the artifact, jailed.
func (a *Analyzer) StaticAnalyzeActivity(ctx context.Context, in pipeline.SubmissionInput) (pipeline.EngineReport, error) {
	return a.runEngine(ctx, a.workerImage, a.workerWall, in)
}

// IdentifyActivity runs magika over the artifact, jailed. identification is
// evidence like any other engine output; it crosses the same broker.
func (a *Analyzer) IdentifyActivity(ctx context.Context, in pipeline.SubmissionInput) (pipeline.EngineReport, error) {
	return a.runEngine(ctx, a.identImage, a.identWall, in)
}

// runEngine is the one enforcement path every engine goes through:
// jailed scan, jailed broker, strict decode of validated bytes only.
func (a *Analyzer) runEngine(ctx context.Context, image string, wall time.Duration, in pipeline.SubmissionInput) (pipeline.EngineReport, error) {
	logger := activity.GetLogger(ctx)
	var none pipeline.EngineReport

	if !shaHex.MatchString(in.SHA256) {
		return none, temporal.NewNonRetryableApplicationError(
			"submission sha256 is not 64 lowercase hex chars", "BadInput", nil)
	}

	// 1) the jailed scan. hostile bytes are parsed only in there.
	scan, err := runJailed(ctx, a.docker, jailSpec{
		image:        image,
		mounts:       []mount.Mount{sampleMount(a.vaultVolume, in.SHA256)},
		wallClock:    wall,
		submissionID: in.SubmissionID,
	})
	if err != nil {
		return none, fmt.Errorf("worker jail: %w", err)
	}
	if len(scan.stderr) > 0 {
		logger.Warn("worker stderr (sanitized)",
			"submission", in.SubmissionID,
			"bytes", len(scan.stderr),
			"preview", sanitizeForLog(scan.stderr, 200))
	}
	if scan.exitCode != 0 {
		return none, fmt.Errorf("worker exited %d", scan.exitCode)
	}
	if scan.stdoutTruncated {
		// deterministic violation: a retry would produce the same flood.
		return none, temporal.NewNonRetryableApplicationError(
			"worker output exceeded the 1MiB cap", "OversizeOutput", nil)
	}

	// 2) the jailed broker: the one and only decoder of raw worker bytes.
	brok, err := runJailed(ctx, a.docker, jailSpec{
		image:        a.brokerImage,
		stdin:        scan.stdout,
		wallClock:    a.brokerWall,
		submissionID: in.SubmissionID,
	})
	if err != nil {
		return none, fmt.Errorf("broker jail: %w", err)
	}
	if brok.exitCode != 0 {
		// the broker said no. deterministic; retrying cannot make hostile
		// output valid. the workflow floors this node to SUSPICIOUS.
		return none, temporal.NewNonRetryableApplicationError(
			fmt.Sprintf("broker rejected worker output: %s", sanitizeForLog(brok.stderr, 200)),
			"BrokerReject", nil)
	}
	if brok.stdoutTruncated {
		return none, temporal.NewNonRetryableApplicationError(
			"broker output exceeded the 1MiB cap", "OversizeOutput", nil)
	}

	// 3) strict decode of broker-validated bytes only.
	dec := json.NewDecoder(bytes.NewReader(brok.stdout))
	dec.DisallowUnknownFields()
	var br brokerReport
	if err := dec.Decode(&br); err != nil {
		return none, temporal.NewNonRetryableApplicationError(
			"broker output failed strict decode: "+err.Error(), "BrokerContract", nil)
	}

	// 4) map onto the typed lattice; anything unparseable fails closed.
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
			Engine:  f.Engine,
			Type:    f.Type,
			Detail:  f.Detail,
			Attck:   f.Attck,
			Verdict: fv,
		})
	}

	logger.Info("engine analysis complete",
		"engine", rep.Engine,
		"image", image,
		"submission", in.SubmissionID,
		"sha256", in.SHA256,
		"verdict", rep.Verdict.String(),
		"findings", len(rep.Findings),
		"incomplete", rep.Incomplete)
	return rep, nil
}
