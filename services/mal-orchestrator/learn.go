package main

// tier-1 learning (design sec 09): every finalized analysis writes typed facts to
// the knowledge graph, so future runs correlate against the lab's own history -
// the moat a sovereign platform can build without anyone's corpus.
//
// the cross-time poisoning guard (THREAT #1) is structural: an AUTO-ingested
// analysis lands in the LOW-TRUST working index (ObserveNode/Observe), and only a
// human-CONFIRMED analysis writes CURATED facts (AddNode/Link). ingest can never
// overwrite curated (the graph's atomic merge), so a wrong or hostile auto-lesson
// cannot launder itself into standing trust. this is the write side of the loop;
// promotion to curated is driven by the HITL confirmation.

import (
	"context"

	"github.com/COLONAYUSH/OpenMalLab/internal/knowledge"
	"github.com/COLONAYUSH/OpenMalLab/internal/pipeline"
)

// LearnInput is one finalized analysis to record. Confirmed marks a human gold
// label (-> curated); otherwise the facts are low-trust working-index observations.
type LearnInput struct {
	Result    pipeline.SubmissionResult
	Confirmed bool
}

// IngestLearningActivity records the sample and the techniques it exhibited into
// the knowledge graph. it is a no-op when no graph is wired, and it never fails
// the pipeline: a fact that will not store (malformed key, at capacity) is simply
// skipped. returns how many facts were written, for the audit trail.
func (a *Analyzer) IngestLearningActivity(ctx context.Context, in LearnInput) (int, error) {
	if a == nil || a.graph == nil || in.Result.SHA256 == "" {
		return 0, nil
	}
	res := in.Result
	src := "analysis:" + res.SubmissionID
	written := 0

	// node/edge pick the trust tier by whether a human confirmed this analysis.
	node := func(kind knowledge.NodeKind, key, label string) bool {
		var err error
		if in.Confirmed {
			_, err = a.graph.AddNode(kind, key, label, nil, src)
		} else {
			_, err = a.graph.ObserveNode(kind, key, label, src)
		}
		return err == nil
	}
	edge := func(fromKind knowledge.NodeKind, fromKey string, rel knowledge.RelKind, toKind knowledge.NodeKind, toKey string) bool {
		var err error
		if in.Confirmed {
			_, err = a.graph.Link(fromKind, fromKey, rel, toKind, toKey, src)
		} else {
			_, err = a.graph.Observe(fromKind, fromKey, rel, toKind, toKey, src)
		}
		return err == nil
	}

	if node(knowledge.NodeSample, res.SHA256, res.Filename) {
		written++
	}
	seen := map[string]bool{}
	for _, f := range res.Findings {
		if f.Attck == "" || seen[f.Attck] {
			continue
		}
		seen[f.Attck] = true
		if node(knowledge.NodeTechnique, f.Attck, "") &&
			edge(knowledge.NodeSample, res.SHA256, knowledge.RelExhibits, knowledge.NodeTechnique, f.Attck) {
			written++
		}
	}
	return written, nil
}
