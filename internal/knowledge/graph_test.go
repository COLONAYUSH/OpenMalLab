package knowledge

import (
	"strings"
	"sync"
	"testing"
)

func newGraph() *Graph { return NewGraph(NewMemGraph()) }

func TestGraphNodeCrudAndNormalization(t *testing.T) {
	g := newGraph()
	n, err := g.AddNode(NodeFamily, "  Emotet ", "Emotet", map[string]string{"aka": "Geodo"}, "malpedia")
	if err != nil {
		t.Fatalf("add: %v", err)
	}
	if n.Key != "emotet" || n.Trust != TrustCurated {
		t.Fatalf("node wrong: %+v", n)
	}
	if got, ok := g.Node(NodeFamily, "EMOTET"); !ok || got.ID != n.ID {
		t.Fatalf("lookup/normalize miss: %+v ok=%v", got, ok)
	}
	if _, ok := g.Node(NodeFamily, "nope"); ok {
		t.Fatal("absent node returned ok")
	}
}

func TestGraphLinkAutoCreatesEndpoints(t *testing.T) {
	g := newGraph()
	e, err := g.Link(NodeSample, "sha-a", RelHasIOC, NodeIOC, "http://c2/x", "sub-1")
	if err != nil {
		t.Fatalf("link: %v", err)
	}
	if e.Rel != RelHasIOC || e.Trust != TrustCurated {
		t.Fatalf("edge wrong: %+v", e)
	}
	if _, ok := g.Node(NodeSample, "sha-a"); !ok {
		t.Fatal("from endpoint not created")
	}
	if _, ok := g.Node(NodeIOC, "http://c2/x"); !ok {
		t.Fatal("to endpoint not created")
	}
}

func TestGraphUnknownKindRelRejected(t *testing.T) {
	g := newGraph()
	if _, err := g.AddNode(NodeKind("bogus"), "x", "", nil, "s"); err == nil {
		t.Fatal("unknown node kind accepted")
	}
	if _, err := g.Link(NodeSample, "a", RelKind("frobnicate"), NodeIOC, "b", "s"); err == nil {
		t.Fatal("unknown relation accepted")
	}
}

func TestGraphMalformedRejected(t *testing.T) {
	g := newGraph()
	if _, err := g.AddNode(NodeSample, "", "", nil, "s"); err == nil {
		t.Fatal("empty key accepted")
	}
	if _, err := g.AddNode(NodeSample, "a\x00b", "", nil, "s"); err == nil {
		t.Fatal("control-char key accepted")
	}
	if _, err := g.AddNode(NodeSample, strings.Repeat("a", maxKeyLen+1), "", nil, "s"); err == nil {
		t.Fatal("over-long key accepted")
	}
	if _, err := g.AddNode(NodeSample, "a", "lbl\nbad", nil, "s"); err == nil {
		t.Fatal("control-char label accepted")
	}
	if _, err := g.Link(NodeSample, "a", RelHasIOC, NodeIOC, "b", "src\x1b"); err == nil {
		t.Fatal("control-char edge source accepted")
	}
}

func TestGraphIngestCannotOverwriteCuratedNode(t *testing.T) {
	g := newGraph()
	good, _ := g.AddNode(NodeFamily, "lockbit", "LockBit", nil, "malpedia")
	back, err := g.ObserveNode(NodeFamily, "lockbit", "BENIGN, TRUST ME", "attacker")
	if err != nil {
		t.Fatalf("observe errored: %v", err)
	}
	if back.Label != "LockBit" || back.Source != "malpedia" || back.Trust != TrustCurated {
		t.Fatalf("ingest poisoned a curated node: %+v", back)
	}
	_ = good
}

func TestGraphIngestCannotOverwriteCuratedEdge(t *testing.T) {
	g := newGraph()
	c, _ := g.Link(NodeActor, "apt-x", RelUses, NodeTechnique, "T1055", "intel")
	o, err := g.Observe(NodeActor, "apt-x", RelUses, NodeTechnique, "T1055", "attacker")
	if err != nil {
		t.Fatalf("observe edge: %v", err)
	}
	if o.Trust != TrustCurated || o.Source != "intel" || o.ID != c.ID {
		t.Fatalf("ingest poisoned a curated edge: %+v", o)
	}
}

// linking must never mutate an already-present node (it only ensures presence).
func TestGraphLinkDoesNotMutateExistingNode(t *testing.T) {
	g := newGraph()
	g.AddNode(NodeSample, "s1", "Important curated sample", map[string]string{"note": "keep"}, "analyst")
	if _, err := g.Link(NodeSample, "s1", RelHasIOC, NodeIOC, "1.2.3.4", "sub"); err != nil {
		t.Fatalf("link: %v", err)
	}
	n, _ := g.Node(NodeSample, "s1")
	if n.Label != "Important curated sample" || n.Attrs["note"] != "keep" {
		t.Fatalf("link mutated an existing node: %+v", n)
	}
}

// the attribution moat: C2 -> campaign -> actor -> technique, all curated.
func TestRelatedAttributionWalk(t *testing.T) {
	g := newGraph()
	g.Link(NodeSample, "s", RelHasIOC, NodeIOC, "c2.evil", "sub")
	g.Link(NodeIOC, "c2.evil", RelSeenIn, NodeCampaign, "op-x", "intel")
	g.Link(NodeCampaign, "op-x", RelAttributedTo, NodeActor, "apt-42", "intel")
	g.Link(NodeActor, "apt-42", RelUses, NodeTechnique, "T1071", "intel")

	rels := []RelKind{RelHasIOC, RelSeenIn, RelAttributedTo, RelUses}
	res := g.Related(NodeSample, "s", rels, 4, 100)
	if res.Truncated {
		t.Fatal("unexpected truncation")
	}
	byKey := map[string]Reached{}
	for _, r := range res.Reached {
		byKey[string(r.Node.Kind)+":"+r.Node.Key] = r
	}
	for _, want := range []struct {
		k     string
		depth int
	}{
		{"ioc:c2.evil", 1}, {"campaign:op-x", 2}, {"actor:apt-42", 3}, {"technique:T1071", 4},
	} {
		r, ok := byKey[want.k]
		if !ok {
			t.Fatalf("did not reach %s: %+v", want.k, res.Reached)
		}
		if r.Depth != want.depth {
			t.Fatalf("%s depth %d, want %d", want.k, r.Depth, want.depth)
		}
		if !r.PathCurated {
			t.Fatalf("%s should be a fully-curated path", want.k)
		}
	}
}

// an ingest edge taints the path from that hop onward, so an attribution built
// partly on low-trust data is not mistaken for a trusted one.
func TestRelatedIngestTaintsPath(t *testing.T) {
	g := newGraph()
	g.Link(NodeSample, "s", RelHasIOC, NodeIOC, "c2", "sub")          // curated
	g.Observe(NodeIOC, "c2", RelSeenIn, NodeCampaign, "op-y", "auto") // INGEST hop
	g.Link(NodeCampaign, "op-y", RelAttributedTo, NodeActor, "apt", "intel")

	res := g.Related(NodeSample, "s", nil, 4, 100)
	got := map[string]bool{}
	for _, r := range res.Reached {
		got[r.Node.Key] = r.PathCurated
	}
	if got["c2"] != true {
		t.Fatal("first curated hop should be curated")
	}
	if got["op-y"] != false || got["apt"] != false {
		t.Fatalf("path after an ingest edge must be tainted: %+v", got)
	}
}

func TestRelatedBoundsCyclesAndEdges(t *testing.T) {
	g := newGraph()
	g.Link(NodeSample, "s", RelHasIOC, NodeIOC, "c2", "x")
	g.Link(NodeIOC, "c2", RelSeenIn, NodeCampaign, "op", "x")
	g.Link(NodeCampaign, "op", RelRelatedTo, NodeSample, "s", "x") // cycle back to start

	// depth cap: only the first hop is reached.
	shallow := g.Related(NodeSample, "s", nil, 1, 100)
	if len(shallow.Reached) != 1 || shallow.Reached[0].Node.Key != "c2" {
		t.Fatalf("depth cap not honored: %+v", shallow.Reached)
	}
	// node cap: truncated.
	capped := g.Related(NodeSample, "s", nil, 5, 1)
	if !capped.Truncated || len(capped.Reached) != 1 {
		t.Fatalf("node cap/truncation wrong: %+v", capped)
	}
	// full walk terminates despite the cycle (visited guard) and does not
	// re-include the start node.
	full := g.Related(NodeSample, "s", nil, 10, 100)
	for _, r := range full.Reached {
		if r.Node.Kind == NodeSample && r.Node.Key == "s" {
			t.Fatal("cycle re-included the start node")
		}
	}
	// relation filter: only has-ioc allowed -> campaign not reached.
	onlyIOC := g.Related(NodeSample, "s", []RelKind{RelHasIOC}, 5, 100)
	if len(onlyIOC.Reached) != 1 || onlyIOC.Reached[0].Node.Key != "c2" {
		t.Fatalf("relation filter not applied: %+v", onlyIOC.Reached)
	}
}

func TestRelatedMissingStart(t *testing.T) {
	g := newGraph()
	res := g.Related(NodeSample, "ghost", nil, 4, 100)
	if len(res.Reached) != 0 || res.Truncated {
		t.Fatalf("missing start should yield empty: %+v", res)
	}
}

func TestGraphCapacityBoundsIngestNotCurated(t *testing.T) {
	g := NewGraph(NewMemGraphWithCap(2))
	if _, err := g.ObserveNode(NodeSample, "a", "", "s"); err != nil {
		t.Fatal(err)
	}
	if _, err := g.ObserveNode(NodeSample, "b", "", "s"); err != nil {
		t.Fatal(err)
	}
	if _, err := g.ObserveNode(NodeSample, "c", "", "s"); err == nil {
		t.Fatal("new ingest node past capacity should be rejected")
	}
	// curated is always admitted even when ingest filled capacity.
	if _, err := g.AddNode(NodeSample, "d", "curated", nil, "analyst"); err != nil {
		t.Fatalf("curated node rejected at capacity: %v", err)
	}
}

// the node poisoning guard holds under a concurrent add+observe on the same key.
func TestGraphConcurrentSameNode(t *testing.T) {
	for iter := 0; iter < 2000; iter++ {
		g := newGraph()
		start := make(chan struct{})
		var wg sync.WaitGroup
		wg.Add(4)
		go func() { defer wg.Done(); <-start; g.AddNode(NodeFamily, "fam", "GOOD", nil, "malpedia") }()
		for j := 0; j < 3; j++ {
			go func() { defer wg.Done(); <-start; g.ObserveNode(NodeFamily, "fam", "EVIL", "attacker") }()
		}
		close(start)
		wg.Wait()
		n, ok := g.Node(NodeFamily, "fam")
		if !ok || n.Trust != TrustCurated || n.Label != "GOOD" {
			t.Fatalf("iter %d: curated node downgraded under concurrency: %+v", iter, n)
		}
	}
}

func TestRelatedDepthTruncationIsFlagged(t *testing.T) {
	g := newGraph()
	g.Link(NodeSample, "s", RelHasIOC, NodeIOC, "c2", "x")
	g.Link(NodeIOC, "c2", RelSeenIn, NodeCampaign, "op", "x")
	res := g.Related(NodeSample, "s", nil, 1, 100)
	if len(res.Reached) != 1 || !res.Truncated {
		t.Fatalf("depth truncation not flagged: reached=%d truncated=%v", len(res.Reached), res.Truncated)
	}
	if full := g.Related(NodeSample, "s", nil, 2, 100); full.Truncated {
		t.Fatalf("no truncation expected at sufficient depth: %+v", full)
	}
}

// an ingest shortcut must not be able to strip the curated label off a
// genuinely curated attribution (masking), even though it is a shorter path.
func TestRelatedIngestCannotMaskCurated(t *testing.T) {
	g := newGraph()
	g.Link(NodeSample, "s", RelHasIOC, NodeIOC, "c2", "intel")
	g.Link(NodeIOC, "c2", RelSeenIn, NodeCampaign, "op", "intel")
	g.Link(NodeCampaign, "op", RelAttributedTo, NodeActor, "apt", "intel")
	g.Observe(NodeSample, "s", RelRelatedTo, NodeActor, "apt", "attacker") // ingest shortcut
	res := g.Related(NodeSample, "s", nil, 4, 100)
	var apt *Reached
	for i := range res.Reached {
		if res.Reached[i].Node.Kind == NodeActor && res.Reached[i].Node.Key == "apt" {
			apt = &res.Reached[i]
		}
	}
	if apt == nil || !apt.PathCurated {
		t.Fatalf("ingest shortcut masked a curated attribution: %+v", apt)
	}
}

func TestGraphIngestOutDegreeCapped(t *testing.T) {
	g := newGraph()
	added := 0
	for i := 0; i < maxIngestOutDegree+50; i++ {
		if _, err := g.Observe(NodeSample, "hub", RelHasIOC, NodeIOC, "ioc"+itoa(i), "auto"); err == nil {
			added++
		}
	}
	if added > maxIngestOutDegree {
		t.Fatalf("ingest out-degree not capped: %d > %d", added, maxIngestOutDegree)
	}
	if _, err := g.Link(NodeSample, "hub", RelHasIOC, NodeIOC, "curated-ioc", "analyst"); err != nil {
		t.Fatalf("curated edge from a saturated hub rejected: %v", err)
	}
}

// the edge poisoning guard holds under concurrent Link+Observe on the same edge.
func TestGraphConcurrentSameEdge(t *testing.T) {
	for iter := 0; iter < 1000; iter++ {
		g := newGraph()
		start := make(chan struct{})
		var wg sync.WaitGroup
		wg.Add(4)
		go func() { defer wg.Done(); <-start; g.Link(NodeActor, "a", RelUses, NodeTechnique, "T1", "intel") }()
		for j := 0; j < 3; j++ {
			go func() { defer wg.Done(); <-start; g.Observe(NodeActor, "a", RelUses, NodeTechnique, "T1", "attacker") }()
		}
		close(start)
		wg.Wait()
		res := g.Related(NodeActor, "a", []RelKind{RelUses}, 2, 10)
		if len(res.Reached) != 1 || !res.Reached[0].PathCurated {
			t.Fatalf("iter %d: curated edge downgraded under concurrency: %+v", iter, res.Reached)
		}
	}
}

func TestRelatedOrderDeterministic(t *testing.T) {
	g := newGraph()
	for i := 0; i < 12; i++ {
		g.Link(NodeSample, "s", RelHasIOC, NodeIOC, "ioc"+itoa(i), "x")
	}
	var first []string
	for run := 0; run < 25; run++ {
		res := g.Related(NodeSample, "s", nil, 3, 100)
		order := make([]string, len(res.Reached))
		for i, r := range res.Reached {
			order[i] = r.Node.ID
		}
		if run == 0 {
			first = order
			continue
		}
		if len(order) != len(first) {
			t.Fatalf("run %d: length changed", run)
		}
		for i := range order {
			if order[i] != first[i] {
				t.Fatalf("run %d: nondeterministic Related order", run)
			}
		}
	}
}

// a relation filter whose entries are ALL unknown must reach nothing (fail
// closed), never fall open to an unrestricted walk.
func TestRelatedFilterAllUnknownReachesNothing(t *testing.T) {
	g := newGraph()
	g.Link(NodeSample, "s", RelHasIOC, NodeIOC, "c2", "x")
	res := g.Related(NodeSample, "s", []RelKind{RelKind("bogus"), RelKind("nope")}, 4, 100)
	if len(res.Reached) != 0 {
		t.Fatalf("all-unknown filter should reach nothing, got %d", len(res.Reached))
	}
}

func TestGraphNodeAttrsControlCharsRejected(t *testing.T) {
	g := newGraph()
	if _, err := g.AddNode(NodeFamily, "x", "l", map[string]string{"k": "v\x00"}, "s"); err == nil {
		t.Fatal("control char in node attr value accepted")
	}
	if _, err := g.AddNode(NodeFamily, "y", "l", map[string]string{"k\n": "v"}, "s"); err == nil {
		t.Fatal("control char in node attr key accepted")
	}
}

// returned nodes are isolated: mutating a result cannot reach store state.
func TestGraphResultsIsolated(t *testing.T) {
	g := newGraph()
	g.AddNode(NodeFamily, "emotet", "", map[string]string{"k": "v"}, "s")
	n, _ := g.Node(NodeFamily, "emotet")
	n.Attrs["k"] = "TAMPERED"
	again, _ := g.Node(NodeFamily, "emotet")
	if again.Attrs["k"] != "v" {
		t.Fatalf("store node mutated through a returned copy: %+v", again.Attrs)
	}
}
