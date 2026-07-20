package knowledge

import (
	"path/filepath"
	"sync"
	"testing"

	"go.etcd.io/bbolt"
)

// helper: a persistent graph store at a fresh temp path, closed on cleanup.
func tempBoltGraph(t *testing.T, max int) (*BoltGraph, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "kg.bolt")
	g, err := OpenBoltGraphWithCap(path, max)
	if err != nil {
		t.Fatalf("open bolt graph: %v", err)
	}
	t.Cleanup(func() { _ = g.Close() })
	return g, path
}

// the whole point of the persistent graph: learned nodes and edges survive a
// close+reopen, including the adjacency index a traversal depends on, and the
// curated/ingest path distinction is still computable from the reopened file.
func TestBoltGraphPersistsAcrossReopen(t *testing.T) {
	path := filepath.Join(t.TempDir(), "kg.bolt")
	s1, err := OpenBoltGraph(path)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	g1 := NewGraph(s1)
	if _, err := g1.AddNode(NodeFamily, "Emotet", "Emotet banking trojan", map[string]string{"aka": "Geodo"}, "malpedia"); err != nil {
		t.Fatalf("add node: %v", err)
	}
	if _, err := g1.Link(NodeSample, "sha256:abc", RelMemberOf, NodeFamily, "emotet", "analyst"); err != nil {
		t.Fatalf("curated link: %v", err)
	}
	if _, err := g1.Observe(NodeSample, "sha256:abc", RelHasIOC, NodeIOC, "http://c2.evil/gate.php", "sub-1"); err != nil {
		t.Fatalf("ingest observe: %v", err)
	}
	if s1.NodeCount() != 3 || s1.EdgeCount() != 2 {
		t.Fatalf("before reopen: %d nodes / %d edges, want 3 / 2", s1.NodeCount(), s1.EdgeCount())
	}
	if err := s1.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	// reopen the SAME file: nodes, edges and the adjacency must still be there.
	s2, err := OpenBoltGraph(path)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	defer s2.Close()
	if s2.NodeCount() != 3 || s2.EdgeCount() != 2 {
		t.Fatalf("counts did not survive reopen: %d nodes / %d edges", s2.NodeCount(), s2.EdgeCount())
	}
	g2 := NewGraph(s2)
	n, ok := g2.Node(NodeFamily, "EMOTET") // key normalization must survive too
	if !ok || n.Label != "Emotet banking trojan" || n.Attrs["aka"] != "Geodo" || n.Trust != TrustCurated {
		t.Fatalf("curated node did not survive reopen: %+v ok=%v", n, ok)
	}
	res := g2.Related(NodeSample, "sha256:abc", nil, 0, 0)
	if res.Truncated || len(res.Reached) != 2 {
		t.Fatalf("traversal over reopened graph: %+v", res)
	}
	for _, r := range res.Reached {
		switch r.Node.Kind {
		case NodeFamily:
			if !r.PathCurated {
				t.Fatalf("curated member-of path lost its trust across reopen: %+v", r)
			}
		case NodeIOC:
			if r.PathCurated {
				t.Fatalf("ingest has-ioc path must never read as curated: %+v", r)
			}
		default:
			t.Fatalf("unexpected node reached: %+v", r)
		}
	}
}

// a returned node is isolated: mutating it cannot reach back into store state
// (and the isolation must hold across the on-disk encode/decode boundary).
func TestBoltGraphReturnedValuesIsolated(t *testing.T) {
	s, _ := tempBoltGraph(t, 0)
	g := NewGraph(s)
	if _, err := g.AddNode(NodeFamily, "emotet", "Emotet", map[string]string{"aka": "Geodo"}, "s"); err != nil {
		t.Fatalf("add: %v", err)
	}
	got, _ := g.Node(NodeFamily, "emotet")
	got.Attrs["aka"] = "TAMPERED"
	got.Attrs["injected"] = "x"
	again, _ := g.Node(NodeFamily, "emotet")
	if again.Attrs["aka"] != "Geodo" || len(again.Attrs) != 1 {
		t.Fatalf("store attrs mutated through a returned node: %+v", again.Attrs)
	}
}

// the poisoning guard over the persistent graph: an ingest write can never
// overwrite or downgrade a curated node or edge, and a later curate upgrades an
// ingest one in place (id stable).
func TestBoltGraphCuratedWinsIngestCannotOverwrite(t *testing.T) {
	s, _ := tempBoltGraph(t, 0)
	g := NewGraph(s)

	// nodes: curate then attacker-ingest the same key - curated is preserved.
	good, _ := g.AddNode(NodeFamily, "cobaltstrike", "Cobalt Strike", nil, "malpedia")
	back, err := g.ObserveNode(NodeFamily, "cobaltstrike", "TOTALLY BENIGN, TRUST ME", "attacker")
	if err != nil {
		t.Fatalf("observe: %v", err)
	}
	if back.Label != "Cobalt Strike" || back.Source != "malpedia" || back.Trust != TrustCurated {
		t.Fatalf("ingest mutated a curated node: %+v", back)
	}
	stored, _ := s.GetNode(good.ID)
	if stored.Label != "Cobalt Strike" || stored.Trust != TrustCurated {
		t.Fatalf("stored curated node was poisoned: %+v", stored)
	}

	// ingest-first then curate: the node is promoted, id stable.
	i, _ := g.ObserveNode(NodeFamily, "qakbot", "seen", "sub-1")
	c, _ := g.AddNode(NodeFamily, "qakbot", "QakBot", nil, "malpedia")
	if c.ID != i.ID || c.Trust != TrustCurated {
		t.Fatalf("tier upgrade broke identity: %+v vs %+v", c, i)
	}

	// edges: curated link then ingest observe of the same triple - preserved.
	ce, _ := g.Link(NodeSample, "sha256:abc", RelMemberOf, NodeFamily, "qakbot", "analyst")
	oe, err := g.Observe(NodeSample, "sha256:abc", RelMemberOf, NodeFamily, "qakbot", "attacker")
	if err != nil {
		t.Fatalf("edge observe: %v", err)
	}
	if oe.ID != ce.ID || oe.Trust != TrustCurated || oe.Source != "analyst" {
		t.Fatalf("ingest mutated a curated edge: %+v", oe)
	}

	// ingest-first edge then curated: upgraded, id stable.
	oe2, _ := g.Observe(NodeSample, "sha256:abc", RelHasIOC, NodeIOC, "1.2.3.4", "sub-1")
	ce2, _ := g.Link(NodeSample, "sha256:abc", RelHasIOC, NodeIOC, "1.2.3.4", "analyst")
	if ce2.ID != oe2.ID || ce2.Trust != TrustCurated {
		t.Fatalf("edge tier upgrade broke: %+v vs %+v", ce2, oe2)
	}
}

// the trust-aware capacity rule holds for nodes and edges independently, and the
// counts are re-derived at open, so both caps are enforced from the persisted
// size after a reopen - never from a forgotten in-memory counter.
func TestBoltGraphCapsBoundIngestNotCuratedAcrossReopen(t *testing.T) {
	path := filepath.Join(t.TempDir(), "kg.bolt")
	s, err := OpenBoltGraphWithCap(path, 2)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	g := NewGraph(s)

	// node cap: two ingest nodes fill it; the third is rejected.
	if _, err := g.ObserveNode(NodeFamily, "a", "", "s"); err != nil {
		t.Fatal(err)
	}
	if _, err := g.ObserveNode(NodeFamily, "b", "", "s"); err != nil {
		t.Fatal(err)
	}
	if _, err := g.ObserveNode(NodeFamily, "c", "", "s"); err == nil {
		t.Fatal("a new ingest node past capacity should be rejected")
	}
	// a new CURATED node past capacity MUST still be admitted (never starved),
	// and an UPDATE to an existing key is not a new key, so it is never capped.
	if _, err := g.AddNode(NodeFamily, "d", "", nil, "s"); err != nil {
		t.Fatalf("curated node must be admitted past the ingest cap: %v", err)
	}
	if _, err := g.ObserveNode(NodeFamily, "a", "updated", "s"); err != nil {
		t.Fatalf("update at capacity rejected: %v", err)
	}

	// edge cap: two ingest edges fill it; the third is rejected; curated passes.
	if _, err := g.Observe(NodeFamily, "a", RelRelatedTo, NodeFamily, "b", "s"); err != nil {
		t.Fatal(err)
	}
	if _, err := g.Observe(NodeFamily, "b", RelRelatedTo, NodeFamily, "a", "s"); err != nil {
		t.Fatal(err)
	}
	if _, err := g.Observe(NodeFamily, "a", RelRelatedTo, NodeFamily, "d", "s"); err == nil {
		t.Fatal("a new ingest edge past capacity should be rejected")
	}
	if _, err := g.Link(NodeFamily, "a", RelRelatedTo, NodeFamily, "d", "s"); err != nil {
		t.Fatalf("curated edge must be admitted past the ingest cap: %v", err)
	}
	if _, err := g.Observe(NodeFamily, "a", RelRelatedTo, NodeFamily, "b", "s"); err != nil {
		t.Fatalf("update to an existing edge at capacity rejected: %v", err)
	}
	if err := s.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	// reopen: counts (3 nodes a,b,d; 3 edges) are re-derived, caps still bind.
	s2, err := OpenBoltGraphWithCap(path, 2)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	defer s2.Close()
	if s2.NodeCount() != 3 || s2.EdgeCount() != 3 {
		t.Fatalf("reopened counts wrong: %d nodes / %d edges, want 3 / 3", s2.NodeCount(), s2.EdgeCount())
	}
	g2 := NewGraph(s2)
	if _, err := g2.ObserveNode(NodeFamily, "e", "", "s"); err == nil {
		t.Fatal("a new ingest node must stay capped after reopen")
	}
	if _, err := g2.AddNode(NodeFamily, "f", "", nil, "s"); err != nil {
		t.Fatalf("curated node must still be admitted after reopen: %v", err)
	}
	if _, err := g2.Observe(NodeFamily, "b", RelRelatedTo, NodeFamily, "d", "s"); err == nil {
		t.Fatal("a new ingest edge must stay capped after reopen")
	}
	if _, err := g2.Link(NodeFamily, "d", RelRelatedTo, NodeFamily, "b", "s"); err != nil {
		t.Fatalf("curated edge must still be admitted after reopen: %v", err)
	}
}

// the per-node out-degree cap on ingest edges is counted from the on-disk
// adjacency index, so it binds within a run and equally after a reopen. the cap
// is lowered white-box here: exercising the real 4096 would mean 4096 fsynced
// transactions for no extra coverage.
func TestBoltGraphIngestOutDegreeCapAcrossReopen(t *testing.T) {
	path := filepath.Join(t.TempDir(), "kg.bolt")
	s, err := OpenBoltGraphWithCap(path, 0)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	s.outDegCap = 4
	g := NewGraph(s)
	for i := 0; i < 4; i++ {
		if _, err := g.Observe(NodeFamily, "hub", RelRelatedTo, NodeFamily, "t"+itoa(i), "s"); err != nil {
			t.Fatalf("ingest edge %d under the cap rejected: %v", i, err)
		}
	}
	if _, err := g.Observe(NodeFamily, "hub", RelRelatedTo, NodeFamily, "t4", "s"); err == nil {
		t.Fatal("an ingest edge past the out-degree cap should be rejected")
	}
	// curated edges from the same hub are operator-controlled and uncapped.
	if _, err := g.Link(NodeFamily, "hub", RelRelatedTo, NodeFamily, "t5", "s"); err != nil {
		t.Fatalf("curated edge past the out-degree cap rejected: %v", err)
	}
	// a different from-node is unaffected by the hub's saturation.
	if _, err := g.Observe(NodeFamily, "t0", RelRelatedTo, NodeFamily, "t1", "s"); err != nil {
		t.Fatalf("other node's ingest edge rejected: %v", err)
	}
	if err := s.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	// reopen: the degree comes straight off the index, so the cap still binds.
	s2, err := OpenBoltGraphWithCap(path, 0)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	defer s2.Close()
	s2.outDegCap = 4
	g2 := NewGraph(s2)
	if _, err := g2.Observe(NodeFamily, "hub", RelRelatedTo, NodeFamily, "t9", "s"); err == nil {
		t.Fatal("out-degree cap must still bind after reopen")
	}
}

// fail-closed handling of corrupt rows: on the read path a corrupt node is a
// miss and a corrupt edge is skipped (never returned as garbage, never
// fabricated into a traversal); on the write path a merge over a corrupt row is
// a hard error, never a silent overwrite.
func TestBoltGraphCorruptRowsFailClosed(t *testing.T) {
	path := filepath.Join(t.TempDir(), "kg.bolt")
	s, err := OpenBoltGraph(path)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	g := NewGraph(s)
	fam, _ := g.AddNode(NodeFamily, "emotet", "Emotet", nil, "s")
	if _, err := g.Link(NodeSample, "sha256:abc", RelMemberOf, NodeFamily, "emotet", "s"); err != nil {
		t.Fatalf("link: %v", err)
	}
	ioc, err := g.Link(NodeSample, "sha256:abc", RelHasIOC, NodeIOC, "1.2.3.4", "s")
	if err != nil {
		t.Fatalf("link ioc: %v", err)
	}
	sample, _ := g.Node(NodeSample, "sha256:abc")
	if err := s.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	// vandalize the family node row and the has-ioc edge row straight through
	// bbolt, the way on-disk corruption would present.
	db, err := bbolt.Open(path, 0o600, &bbolt.Options{Timeout: openTimeout})
	if err != nil {
		t.Fatalf("raw open: %v", err)
	}
	err = db.Update(func(tx *bbolt.Tx) error {
		if e := tx.Bucket(graphNodesBucket).Put([]byte(fam.ID), []byte("{corrupt")); e != nil {
			return e
		}
		return tx.Bucket(graphEdgesBucket).Put([]byte(ioc.ID), []byte("{corrupt"))
	})
	if err != nil {
		t.Fatalf("corrupt rows: %v", err)
	}
	if err := db.Close(); err != nil {
		t.Fatalf("raw close: %v", err)
	}

	s2, err := OpenBoltGraph(path)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	defer s2.Close()
	g2 := NewGraph(s2)
	// read path: corrupt node reads as absent, intact node still reads fine.
	if _, ok := s2.GetNode(fam.ID); ok {
		t.Fatal("a corrupt node row must read as absent")
	}
	if _, ok := s2.GetNode(sample.ID); !ok {
		t.Fatal("intact node lost alongside the corrupt one")
	}
	// read path: the corrupt edge is skipped, the intact one survives.
	out := s2.OutEdges(sample.ID)
	if len(out) != 1 || out[0].Rel != RelMemberOf {
		t.Fatalf("corrupt edge must be skipped and intact edge kept, got %+v", out)
	}
	// a traversal never fabricates from corrupt rows: the member-of target node
	// is corrupt (skipped) and the has-ioc edge is corrupt (skipped).
	if res := g2.Related(NodeSample, "sha256:abc", nil, 0, 0); len(res.Reached) != 0 {
		t.Fatalf("traversal fabricated results from corrupt rows: %+v", res.Reached)
	}
	// write path: merging over a corrupt row errors instead of clobbering it.
	if _, err := g2.AddNode(NodeFamily, "emotet", "Emotet again", nil, "s"); err == nil {
		t.Fatal("a merge over a corrupt node row must error")
	}
	if _, err := g2.Link(NodeSample, "sha256:abc", RelHasIOC, NodeIOC, "1.2.3.4", "s"); err == nil {
		t.Fatal("a merge over a corrupt edge row must error")
	}
}

// the poisoning guard must hold under a concurrent first-time curate+ingest on
// the same fresh key, over the persistent graph, for nodes and for edges. this
// is the semantic race the -race detector cannot see, so it asserts the OUTCOME:
// once the curated write has run, the stored value is curated, never downgraded
// by an interleaved ingest. fewer iterations than the MemGraph twins because
// every write here is a real transaction.
func TestBoltGraphConcurrentIngestVsCurateSameKey(t *testing.T) {
	s, _ := tempBoltGraph(t, 0)
	g := NewGraph(s)
	const iters = 32
	for i := 0; i < iters; i++ {
		key := "fam" + itoa(i)
		start := make(chan struct{})
		var wg sync.WaitGroup
		wg.Add(4)
		go func() { defer wg.Done(); <-start; _, _ = g.AddNode(NodeFamily, key, "GOOD", nil, "malpedia") }()
		for j := 0; j < 3; j++ {
			go func() { defer wg.Done(); <-start; _, _ = g.ObserveNode(NodeFamily, key, "EVIL", "attacker") }()
		}
		close(start) // release all four at once for maximum contention
		wg.Wait()
		n, ok := g.Node(NodeFamily, key)
		if !ok {
			t.Fatalf("iter %d: node vanished", i)
		}
		if n.Trust != TrustCurated || n.Label != "GOOD" || n.Source != "malpedia" {
			t.Fatalf("iter %d: curated node downgraded by a raced ingest: %+v", i, n)
		}
	}
	for i := 0; i < iters; i++ {
		to := "target" + itoa(i)
		start := make(chan struct{})
		var wg sync.WaitGroup
		wg.Add(4)
		go func() {
			defer wg.Done()
			<-start
			_, _ = g.Link(NodeFamily, "hub", RelRelatedTo, NodeFamily, to, "analyst")
		}()
		for j := 0; j < 3; j++ {
			go func() {
				defer wg.Done()
				<-start
				_, _ = g.Observe(NodeFamily, "hub", RelRelatedTo, NodeFamily, to, "attacker")
			}()
		}
		close(start)
		wg.Wait()
		hub, _ := g.Node(NodeFamily, "hub")
		toN, _ := g.Node(NodeFamily, to)
		var found *Edge
		for _, e := range s.OutEdges(hub.ID) {
			if e.To == toN.ID {
				ec := e
				found = &ec
			}
		}
		if found == nil {
			t.Fatalf("iter %d: edge vanished", i)
		}
		if found.Trust != TrustCurated || found.Source != "analyst" {
			t.Fatalf("iter %d: curated edge downgraded by a raced ingest: %+v", i, *found)
		}
	}
}

// concurrent distinct-key writes are safe under -race, and the live counts stay
// consistent with the number of distinct keys written - including the shared
// "root" node every goroutine races to create exactly once.
func TestBoltGraphConcurrentDistinctKeys(t *testing.T) {
	s, _ := tempBoltGraph(t, 0)
	g := NewGraph(s)
	const n = 24
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			key := "fam" + itoa(i)
			if _, err := g.AddNode(NodeFamily, key, "l", nil, "s"); err != nil {
				t.Errorf("add %s: %v", key, err)
			}
			if _, err := g.Link(NodeFamily, key, RelRelatedTo, NodeFamily, "root", "s"); err != nil {
				t.Errorf("link %s: %v", key, err)
			}
			_, _ = g.Node(NodeFamily, key)
		}(i)
	}
	wg.Wait()
	if s.NodeCount() != n+1 {
		t.Fatalf("node count after %d distinct concurrent adds = %d, want %d", n, s.NodeCount(), n+1)
	}
	if s.EdgeCount() != n {
		t.Fatalf("edge count after %d distinct concurrent links = %d, want %d", n, s.EdgeCount(), n)
	}
}

// OpenGraphFromEnv selects the persistent graph when MAL_KNOWLEDGE_GRAPH_DB is
// set, the in-memory graph when it is not, and always returns a usable close
// func - even on a failed open.
func TestOpenGraphFromEnv(t *testing.T) {
	// unset -> in-memory MemGraph, close is a no-op.
	t.Setenv(EnvKnowledgeGraphDB, "")
	store, closeFn, err := OpenGraphFromEnv()
	if err != nil {
		t.Fatalf("env unset: %v", err)
	}
	if _, ok := store.(*MemGraph); !ok {
		t.Fatalf("unset env should yield a MemGraph, got %T", store)
	}
	if closeFn == nil {
		t.Fatal("close func must never be nil")
	}
	if err := closeFn(); err != nil {
		t.Fatalf("memgraph close should be a no-op: %v", err)
	}

	// set -> persistent BoltGraph that actually persists across a reopen.
	path := filepath.Join(t.TempDir(), "env-graph.bolt")
	t.Setenv(EnvKnowledgeGraphDB, path)
	store, closeFn, err = OpenGraphFromEnv()
	if err != nil {
		t.Fatalf("env set: %v", err)
	}
	if _, ok := store.(*BoltGraph); !ok {
		t.Fatalf("set env should yield a BoltGraph, got %T", store)
	}
	node, err := NewGraph(store).AddNode(NodeFamily, "emotet", "Emotet", nil, "seed")
	if err != nil {
		t.Fatalf("curate: %v", err)
	}
	if err := closeFn(); err != nil {
		t.Fatalf("close: %v", err)
	}
	store2, closeFn2, err := OpenGraphFromEnv()
	if err != nil {
		t.Fatalf("reopen via env: %v", err)
	}
	defer closeFn2()
	if got, ok := store2.GetNode(node.ID); !ok || got.Trust != TrustCurated || got.Label != "Emotet" {
		t.Fatalf("node did not persist via env-selected graph: %+v ok=%v", got, ok)
	}

	// a failed open still returns a non-nil close func (safe to defer blindly).
	t.Setenv(EnvKnowledgeGraphDB, t.TempDir()) // a directory is not a valid db file
	_, closeFn3, err := OpenGraphFromEnv()
	if err == nil {
		t.Fatal("opening a directory as the graph db should fail")
	}
	if closeFn3 == nil {
		t.Fatal("close func must be non-nil even on a failed open")
	}
	if err := closeFn3(); err != nil {
		t.Fatalf("noop close after failed open: %v", err)
	}
}
