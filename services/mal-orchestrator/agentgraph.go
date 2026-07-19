package main

// the multi-agent graph wired into the durable spine (design sec 05). like the
// single-analyst EnrichmentWorkflow, this is a SEPARATE, post-verdict workflow;
// SubmissionWorkflow is untouched and the deterministic verdict is authoritative.
// two durable activities:
//
//   RunRosterActivity - the UNTRUSTED reasoning orchestration. calls the Python
//     roster over HTTP: Router names which agents to spawn, the specialists
//     (correlator/capability/ioc/family/novelty/report) produce typed outputs,
//     the adversarial verifier tries to REFUTE each assembled hypothesis. it
//     returns an assembled Proposal (as bytes, to be re-validated) plus a
//     per-hypothesis GateSignals (refuted? novelty?). it holds no authority.
//   GateActivity - the TRUSTED adjudication. Validate the proposal (strict,
//     fail-closed), run the confidence gate against the seeded L0 registry with
//     the roster's signals, ledger the handshake, and return only the capped
//     enrichment findings + the human-review flag.
//
// the workflow folds the gate's enrichment through the SAME fail-closed lattice
// (raise-only, capped at SUSPICIOUS). agents propose; the gate disposes; the
// spine folds. it is air-gapped by default (nil agent caller -> no-op) and caged
// at every layer (any HTTP/validate/gate failure returns the result unchanged).

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/COLONAYUSH/OpenMalLab/internal/aiplane"
	"github.com/COLONAYUSH/OpenMalLab/internal/knowledge"
	"github.com/COLONAYUSH/OpenMalLab/internal/pipeline"
	"go.temporal.io/sdk/temporal"
	"go.temporal.io/sdk/workflow"
)

// the roster does several sequential model calls; give the activity a generous
// budget. a timeout is deterministic for a given evidence set, so one attempt.
const agentGraphActivityTimeout = 10 * time.Minute

const maxAgentRespBytes = 1 << 20 // bound each agent response read

// knownAgents is the roster allow-list. the Router's chosen names are UNTRUSTED,
// so any name not here is ignored - this also makes the /v1/agent/{name} path a
// closed set (no path injection from a hostile router response).
var knownAgents = map[string]bool{
	"router": true, "correlator": true, "capability_reasoner": true,
	"ioc_extractor": true, "family_hypothesizer": true, "novelty_detector": true,
	"verifier": true, "report_writer": true, "escalation": true, "analyst": true,
}

// agentCaller is the boundary to the Python roster service. injected so the whole
// graph is testable offline with a mock.
type agentCaller interface {
	call(ctx context.Context, name string, req agentReq) ([]byte, error)
}

// agentReq mirrors the Python AgentRequest envelope. only the fields an agent
// consumes are read on the other side.
type agentReq struct {
	Evidence  aiplane.Evidence `json:"evidence"`
	Priors    json.RawMessage  `json:"priors,omitempty"`
	Claim     string           `json:"claim,omitempty"`
	Reason    string           `json:"reason,omitempty"`
	Confirmed []string         `json:"confirmed,omitempty"`
}

// httpAgentCaller talks to the jailed Python agent service over the isolated
// plane network. the response read is length-bounded so a hostile service cannot
// exhaust memory.
type httpAgentCaller struct {
	url    string
	client *http.Client
}

// newHTTPAgentCaller builds the caller for the jailed roster service at url.
func newHTTPAgentCaller(url string) *httpAgentCaller {
	return &httpAgentCaller{url: strings.TrimRight(url, "/"), client: &http.Client{Timeout: 8 * time.Minute}}
}

func (h *httpAgentCaller) call(ctx context.Context, name string, req agentReq) ([]byte, error) {
	if !knownAgents[name] {
		return nil, fmt.Errorf("agentgraph: unknown agent %q", name)
	}
	body, err := json.Marshal(req)
	if err != nil {
		return nil, err
	}
	hreq, err := http.NewRequestWithContext(ctx, http.MethodPost, h.url+"/v1/agent/"+name, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	hreq.Header.Set("Content-Type", "application/json")
	resp, err := h.client.Do(hreq)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	out, err := io.ReadAll(io.LimitReader(resp.Body, maxAgentRespBytes))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("agentgraph: %s status %d", name, resp.StatusCode)
	}
	return out, nil
}

// -------- agent output types (mirror services/mal-agents schemas.py) --------

type agentPlan struct {
	Agents       []string `json:"agents"`
	BudgetTokens int      `json:"budget_tokens"`
	Rationale    string   `json:"rationale"`
}

type agentBehavior struct {
	TTP       string             `json:"ttp"`
	Why       string             `json:"why"`
	Citations []aiplane.Citation `json:"citations"`
}

type agentBehaviors struct {
	Behaviors []agentBehavior `json:"behaviors"`
}

type agentFamily struct {
	Family     string             `json:"family"`
	Fields     map[string]string  `json:"fields"`
	Confidence string             `json:"confidence"`
	Citations  []aiplane.Citation `json:"citations"`
}

type agentIOCSet struct {
	IOCs []aiplane.ProposedIOC `json:"iocs"`
}

type agentNovelty struct {
	Score   float64 `json:"score"`
	Nearest string  `json:"nearest"`
}

type agentReport struct {
	Md string `json:"md"`
}

type agentVerdict struct {
	Real   bool   `json:"real"`
	Reason string `json:"reason"`
}

// RosterOutcome is RunRosterActivity's result: an assembled proposal to be
// re-validated + gated, and one GateSignals per hypothesis (in order).
type RosterOutcome struct {
	Configured   bool
	ProposalJSON []byte
	Signals      []aiplane.GateSignals
}

// GateInput / GateOutcome carry the trusted adjudication across the activity
// boundary.
type GateInput struct {
	Result   pipeline.SubmissionResult
	Proposal []byte
	Signals  []aiplane.GateSignals
}

// EscalatedItem is one hypothesis the gate sent to a human, with the model's
// claimed confidence - so the HITL outcome can be recorded back into calibration
// (was a HIGH claim actually right?) and graduation (per-category track record).
type EscalatedItem struct {
	Kind       string
	Confidence string
}

type GateOutcome struct {
	Findings    []pipeline.Finding
	NeedsReview bool
	Escalated   []EscalatedItem
	Reasons     []string
}

// RunRosterActivity orchestrates the untrusted roster and assembles a proposal.
// it is a no-op when no agent service is configured. it NEVER fails the pipeline:
// a failed agent call is skipped (and a hypothesis whose verifier could not be
// reached is marked refuted, fail-closed).
func (a *Analyzer) RunRosterActivity(ctx context.Context, res pipeline.SubmissionResult) (RosterOutcome, error) {
	if a == nil || a.agents == nil {
		return RosterOutcome{Configured: false}, nil
	}
	ev := aiplane.EvidenceFrom(res)

	// Router: which agents to spawn (untrusted; validated + core agents forced on).
	var plan agentPlan
	if raw, err := a.agents.call(ctx, "router", agentReq{Evidence: ev}); err == nil {
		_ = json.Unmarshal(raw, &plan)
	}
	want := plannedSet(plan.Agents)

	// deterministic KB retrieval - the Correlator's real function. the Python roster
	// has no KB access, so the SPINE retrieves independently (exactly what the
	// citation-verification design requires) and hands the reasoners known facts as
	// CITABLE priors, each with the real L0 fact id the gate will re-verify. the
	// Correlator agent additionally reasons over them for narrative leads.
	priors := a.retrievePriors(ev)
	if want["correlator"] {
		_, _ = a.agents.call(ctx, "correlator", agentReq{Evidence: ev, Priors: priors})
	}

	var hyps []aiplane.Hypothesis
	var iocs []aiplane.ProposedIOC
	summary := ""
	novelty := 0.0

	if want["family_hypothesizer"] {
		if raw, err := a.agents.call(ctx, "family_hypothesizer", agentReq{Evidence: ev, Priors: priors}); err == nil {
			var fh agentFamily
			if json.Unmarshal(raw, &fh) == nil && fh.Family != "" {
				hyps = append(hyps, aiplane.Hypothesis{Kind: "family", Claim: fh.Family, Confidence: fh.Confidence, Citations: cleanCites(fh.Citations)})
			}
		}
	}
	if want["capability_reasoner"] {
		if raw, err := a.agents.call(ctx, "capability_reasoner", agentReq{Evidence: ev, Priors: priors}); err == nil {
			var b agentBehaviors
			if json.Unmarshal(raw, &b) == nil {
				for _, bh := range b.Behaviors {
					if bh.Why == "" {
						continue
					}
					hyps = append(hyps, aiplane.Hypothesis{Kind: "technique", Claim: bh.Why, Confidence: "LOW", Citations: cleanCites(bh.Citations)})
				}
			}
		}
	}
	if want["ioc_extractor"] {
		if raw, err := a.agents.call(ctx, "ioc_extractor", agentReq{Evidence: ev}); err == nil {
			var s agentIOCSet
			if json.Unmarshal(raw, &s) == nil {
				iocs = groundIOCs(s.IOCs, ev) // B2: only IOCs actually present in the trusted evidence
			}
		}
	}
	if want["novelty_detector"] {
		if raw, err := a.agents.call(ctx, "novelty_detector", agentReq{Evidence: ev}); err == nil {
			var n agentNovelty
			if json.Unmarshal(raw, &n) == nil {
				novelty = n.Score
			}
		}
	}
	if want["report_writer"] {
		if raw, err := a.agents.call(ctx, "report_writer", agentReq{Evidence: ev}); err == nil {
			var r agentReport
			if json.Unmarshal(raw, &r) == nil {
				summary = r.Md
			}
		}
	}

	prop := aiplane.Proposal{Summary: summary, Hypotheses: hyps, IOCs: iocs}

	// adversarial verifier per hypothesis -> gate signals. no verifier reachable
	// means refuted (fail-closed: an unverifiable claim cannot ground autonomy).
	signals := make([]aiplane.GateSignals, len(hyps))
	for i, h := range hyps {
		sig := aiplane.GateSignals{Novelty: novelty}
		// calibration (downgrade-only): a category whose confident claims have been
		// historically wrong gets its self-report recalibrated down before the gate.
		if a.calibration != nil {
			sig.CalibratedConfidence = a.calibration.Calibrated(h.Kind, h.Confidence)
		}
		raw, err := a.agents.call(ctx, "verifier", agentReq{Evidence: ev, Claim: h.Claim})
		if err != nil {
			sig.Refuted = true
		} else {
			var v agentVerdict
			if json.Unmarshal(raw, &v) != nil || !v.Real {
				sig.Refuted = true
			}
		}
		signals[i] = sig
	}

	pj, err := json.Marshal(prop)
	if err != nil {
		return RosterOutcome{Configured: true}, err
	}
	return RosterOutcome{Configured: true, ProposalJSON: pj, Signals: signals}, nil
}

// GateActivity is the trusted adjudication: strict Validate, then the confidence
// gate against the seeded L0 registry with the roster's signals, ledgered. it
// returns only capped enrichment findings + the review flag; it never returns a
// verdict. caged: a rejected or unconfigured proposal yields nothing.
func (a *Analyzer) GateActivity(ctx context.Context, in GateInput) (GateOutcome, error) {
	if a == nil || a.gate == nil || len(in.Proposal) == 0 {
		return GateOutcome{}, nil
	}
	ev := aiplane.EvidenceFrom(in.Result)
	h := aiplane.Handshake{
		SubmissionID: ev.SubmissionID,
		Provider:     "agent-graph",
		EvidenceHash: sha256hex(mustJSON(ev)),
		ProposalHash: sha256hex(in.Proposal),
	}
	prop, err := aiplane.Validate(in.Proposal)
	if err != nil {
		h.Outcome = "rejected"
		a.ledgerAppend(h)
		return GateOutcome{}, nil // caged: invalid roster output contributes nothing
	}
	gr := a.gate.EvaluateWithSignals(ev, prop, in.Signals)
	h.Outcome = "gated"
	h.NeedsHuman = gr.NeedsHuman
	var escalated []EscalatedItem
	for _, gh := range gr.Hypotheses {
		switch gh.Disposition {
		case aiplane.DispAccept:
			h.Accepted++
		case aiplane.DispEscalate:
			escalated = append(escalated, EscalatedItem{Kind: gh.Kind, Confidence: gh.Confidence})
		}
		h.CitedFactIDs = append(h.CitedFactIDs, gh.VerifiedCitationIDs...)
	}
	if len(h.CitedFactIDs) > 0 {
		h.RetrievalTiers = []string{"L0"}
	}
	a.ledgerAppend(h)
	return GateOutcome{Findings: gr.EnrichmentFindings(), NeedsReview: gr.NeedsHuman, Escalated: escalated, Reasons: gr.Reasons}, nil
}

// AgentGraphWorkflow is the async, post-verdict multi-agent enrichment. it drives
// the two activities and folds the result; if the plane is disabled or anything
// fails, it returns the deterministic result unchanged.
func AgentGraphWorkflow(ctx workflow.Context, res pipeline.SubmissionResult) (pipeline.SubmissionResult, error) {
	ctx = workflow.WithActivityOptions(ctx, workflow.ActivityOptions{
		StartToCloseTimeout: agentGraphActivityTimeout,
		RetryPolicy:         &temporal.RetryPolicy{MaximumAttempts: 1},
	})
	var a *Analyzer // nil receiver: activities resolve by name

	var roster RosterOutcome
	if err := workflow.ExecuteActivity(ctx, a.RunRosterActivity, res).Get(ctx, &roster); err != nil {
		return res, nil // caged
	}
	if !roster.Configured || len(roster.ProposalJSON) == 0 {
		return res, nil
	}
	var gate GateOutcome
	if err := workflow.ExecuteActivity(ctx, a.GateActivity, GateInput{Result: res, Proposal: roster.ProposalJSON, Signals: roster.Signals}).Get(ctx, &gate); err != nil {
		return res, nil // caged
	}
	// fold accepted enrichment through the SAME fail-closed lattice (raise-only,
	// capped at SUSPICIOUS by construction), and raise the one-way review flag.
	for _, f := range gate.Findings {
		res.Verdict = pipeline.Max(res.Verdict, f.Verdict)
		res.Findings = append(res.Findings, f)
	}
	if gate.NeedsReview {
		res.NeedsReview = true
		// raise the HITL task, expose it to the console via query, and durably await
		// the analyst's decision signal or a long timeout. the deterministic verdict
		// (and the capped enrichment) stand either way; the human resolves the
		// escalation and, on approval, promotes the analysis facts to curated.
		kinds := make([]string, 0, len(gate.Escalated))
		for _, e := range gate.Escalated {
			kinds = append(kinds, e.Kind)
		}
		review := ReviewRequest{
			SubmissionID: res.SubmissionID,
			Question:     "Review the AI-escalated findings for this submission.",
			Kinds:        kinds,
			Reasons:      gate.Reasons,
		}
		_ = workflow.SetQueryHandler(ctx, reviewQueryName, func() (ReviewRequest, error) { return review, nil })

		var decision ReviewDecision
		got := false
		sel := workflow.NewSelector(ctx)
		sel.AddReceive(workflow.GetSignalChannel(ctx, reviewSignalName), func(c workflow.ReceiveChannel, _ bool) {
			c.Receive(ctx, &decision)
			got = true
		})
		sel.AddFuture(workflow.NewTimer(ctx, reviewTimeout), func(workflow.Future) {})
		sel.Select(ctx)

		if got {
			// feed the decision back into calibration + graduation (the learning
			// signal), then, on approval, promote the analysis facts to curated.
			_ = workflow.ExecuteActivity(ctx, a.RecordOutcomeActivity, RecordInput{Escalated: gate.Escalated, Approved: decision.Approved}).Get(ctx, nil)
			if decision.Approved {
				_ = workflow.ExecuteActivity(ctx, a.IngestLearningActivity, LearnInput{Result: res, Confirmed: true}).Get(ctx, nil)
			}
		}
	}
	// tier-1 working-index ingest (always; a no-op on any fact already curated).
	_ = workflow.ExecuteActivity(ctx, a.IngestLearningActivity, LearnInput{Result: res, Confirmed: false}).Get(ctx, nil)
	return res, nil
}

// plannedSet validates the Router's (untrusted) agent names against the roster
// and always forces the core analysis agents on, so a lazy or hostile router
// cannot silently skip analysis.
func plannedSet(names []string) map[string]bool {
	want := map[string]bool{}
	for _, n := range names {
		if knownAgents[n] {
			want[n] = true
		}
	}
	for _, n := range []string{"correlator", "capability_reasoner", "ioc_extractor", "novelty_detector"} {
		want[n] = true
	}
	return want
}

// cleanCites drops citations missing any field, so one malformed model citation
// does not fail the whole proposal at Validate (the gate still re-verifies the
// rest against L0).
func cleanCites(cs []aiplane.Citation) []aiplane.Citation {
	var out []aiplane.Citation
	for _, c := range cs {
		// drop any citation Validate would reject (empty, over-long, non-UTF8, or
		// control-byte-carrying), not just empty ones: Validate rejects the WHOLE
		// proposal on a single malformed citation, so one junk citation from the
		// untrusted model would otherwise discard every good hypothesis with it.
		if aiplane.CitationWellFormed(c) {
			out = append(out, c)
		}
	}
	return out
}

// RecordInput carries a resolved HITL decision back to the learning components.
type RecordInput struct {
	Escalated []EscalatedItem
	Approved  bool
}

// RecordOutcomeActivity feeds a human's decision into calibration (was a claim of
// this confidence right?) and graduation (per-category track record). it is the
// write side of the feedback loop; both components are downgrade-biased, so a
// wrong-but-confident category loses trust over time. a no-op if neither is wired.
func (a *Analyzer) RecordOutcomeActivity(ctx context.Context, in RecordInput) error {
	for _, e := range in.Escalated {
		if a.grad != nil {
			a.grad.Record(e.Kind, in.Approved)
		}
		if a.calibration != nil {
			a.calibration.Record(e.Kind, e.Confidence, in.Approved)
		}
	}
	return nil
}

// retrievePriors is the deterministic side of the Correlator: it queries L0 for
// facts that match this submission's evidence (the ATT&CK techniques it exhibited)
// and returns them as CITABLE priors - each carrying the real L0 fact id, so a
// reasoning agent handed a prior can cite it and the gate will verify it. this is
// the actual "have we seen this?" retrieval, done spine-side because the roster
// has no KB access. returns nil when nothing matches (no priors is a valid answer).
func (a *Analyzer) retrievePriors(ev aiplane.Evidence) json.RawMessage {
	if a.registry == nil {
		return nil
	}
	type prior struct {
		Kind       string `json:"kind"`
		Key        string `json:"key"`
		Relation   string `json:"relation"`
		Confidence string `json:"confidence"`
		FactID     string `json:"fact_id"`
	}
	var priors []prior
	seen := map[string]bool{}
	for _, it := range ev.Items {
		if it.Attck == "" || seen[it.Attck] {
			continue
		}
		seen[it.Attck] = true
		if f, ok := a.registry.Lookup(knowledge.KindAttck, it.Attck); ok {
			priors = append(priors, prior{Kind: "attck", Key: f.Key, Relation: "known-technique", Confidence: "HIGH", FactID: f.ID})
		}
	}
	if len(priors) == 0 {
		return nil
	}
	b, err := json.Marshal(map[string]interface{}{"priors": priors})
	if err != nil {
		return nil
	}
	return b
}

// groundIOCs enforces B2 (reconstruct from trusted): an agent-proposed IOC is kept
// only if its value actually appears in the trusted, defanged evidence handed to
// the model - it is never accepted from the agent's paraphrase alone. an invented
// or hallucinated indicator is dropped. strict by design: the anti-fabrication
// guard is worth the occasional over-drop of a reformatted value.
func groundIOCs(iocs []aiplane.ProposedIOC, ev aiplane.Evidence) []aiplane.ProposedIOC {
	var corpus strings.Builder
	for _, it := range ev.Items {
		corpus.WriteString(it.Detail)
		corpus.WriteByte('\n')
		corpus.WriteString(it.Path)
		corpus.WriteByte('\n')
	}
	hay := corpus.String()
	var kept []aiplane.ProposedIOC
	for _, ioc := range iocs {
		if v := strings.TrimSpace(ioc.Value); v != "" && strings.Contains(hay, v) {
			kept = append(kept, ioc)
		}
	}
	return kept
}

func (a *Analyzer) ledgerAppend(h aiplane.Handshake) {
	if a.agentLedger != nil {
		a.agentLedger.Append(h)
	}
}

func sha256hex(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

func mustJSON(v any) []byte {
	b, _ := json.Marshal(v)
	return b
}
