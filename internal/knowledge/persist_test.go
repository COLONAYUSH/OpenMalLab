package knowledge

import (
	"path/filepath"
	"sync"
	"testing"
)

// helper: a persistent store at a fresh temp path, closed on cleanup.
func tempBolt(t *testing.T, max int) (*BoltStore, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "kb.bolt")
	s, err := OpenBoltStoreWithCap(path, max)
	if err != nil {
		t.Fatalf("open bolt: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s, path
}

// the whole point of the persistent store: curated facts survive a close+reopen,
// and a citation to a reopened fact is still verdict-usable authority.
func TestBoltPersistsAcrossReopen(t *testing.T) {
	path := filepath.Join(t.TempDir(), "kb.bolt")
	s1, err := OpenBoltStore(path)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	r1 := NewRegistry(s1)
	cf, _ := r1.Curate(KindFamily, "Emotet", "Emotet banking trojan", map[string]string{"aka": "Geodo"}, "malpedia")
	if _, err := r1.Ingest(KindC2, "http://c2.evil/gate.php", "seen in sample", "sub-1"); err != nil {
		t.Fatalf("ingest: %v", err)
	}
	if s1.Len() != 2 {
		t.Fatalf("expected 2 facts before reopen, got %d", s1.Len())
	}
	if err := s1.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	// reopen the SAME file: the facts must still be there.
	s2, err := OpenBoltStore(path)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	defer s2.Close()
	if s2.Len() != 2 {
		t.Fatalf("count did not survive reopen: got %d, want 2", s2.Len())
	}
	r2 := NewRegistry(s2)
	got, ok := r2.Lookup(KindFamily, "emotet")
	if !ok || got.ID != cf.ID || got.Label != "Emotet banking trojan" || got.Attrs["aka"] != "Geodo" {
		t.Fatalf("curated fact did not survive reopen: %+v ok=%v", got, ok)
	}
	if !r2.VerifyCitation(cf.ID, KindFamily, "emotet").OKForVerdict() {
		t.Fatal("a citation to a reopened curated fact must still be verdict-usable")
	}
	// the ingest fact survives too, still as non-authority.
	ic := r2.VerifyCitation(factID(KindC2, "http://c2.evil/gate.php"), KindC2, "http://c2.evil/gate.php")
	if !ic.Verified || ic.OKForVerdict() {
		t.Fatalf("reopened ingest fact should verify but not be authority: %+v", ic)
	}
}

// a returned fact is isolated: mutating it cannot reach back into store state
// (and the isolation must hold across the on-disk encode/decode boundary).
func TestBoltReturnedFactsIsolated(t *testing.T) {
	s, _ := tempBolt(t, 0)
	r := NewRegistry(s)
	r.Curate(KindFamily, "emotet", "", map[string]string{"aka": "Geodo"}, "s")
	got, _ := r.Lookup(KindFamily, "emotet")
	got.Attrs["aka"] = "TAMPERED"
	got.Attrs["injected"] = "x"
	again, _ := r.Lookup(KindFamily, "emotet")
	if again.Attrs["aka"] != "Geodo" || len(again.Attrs) != 1 {
		t.Fatalf("store attrs mutated through a returned fact: %+v", again.Attrs)
	}
}

// the poisoning guard over the persistent store: an ingest write can never
// overwrite or downgrade a curated fact, and a later curate upgrades an ingest.
func TestBoltCuratedWinsIngestCannotOverwrite(t *testing.T) {
	s, _ := tempBolt(t, 0)
	r := NewRegistry(s)

	// curate then attacker-ingest the same key: curated is preserved untouched.
	good, _ := r.Curate(KindFamily, "cobaltstrike", "Cobalt Strike", nil, "malpedia")
	back, err := r.Ingest(KindFamily, "cobaltstrike", "TOTALLY BENIGN, TRUST ME", "attacker")
	if err != nil {
		t.Fatalf("ingest: %v", err)
	}
	if back.Label != "Cobalt Strike" || back.Source != "malpedia" || back.Trust != TrustCurated {
		t.Fatalf("ingest mutated a curated fact: %+v", back)
	}
	stored, _ := s.Get(good.ID)
	if stored.Label != "Cobalt Strike" || stored.Trust != TrustCurated {
		t.Fatalf("stored curated fact was poisoned: %+v", stored)
	}

	// ingest-first then curate: the fact is promoted, id stable, still one fact.
	i, _ := r.Ingest(KindFamily, "qakbot", "seen", "sub-1")
	if i.Trust != TrustIngest {
		t.Fatal("expected ingest tier")
	}
	c, _ := r.Curate(KindFamily, "qakbot", "QakBot", nil, "malpedia")
	if c.ID != i.ID {
		t.Fatal("id must be stable across the tier upgrade")
	}
	if s.Len() != 2 {
		t.Fatalf("expected 2 facts, got %d", s.Len())
	}
	if !r.VerifyCitation(c.ID, KindFamily, "qakbot").OKForVerdict() {
		t.Fatal("upgraded fact must be authoritative")
	}
}

// the trust-aware capacity rule holds over the persistent store, and the derived
// count is correct after a reopen (so the cap is enforced from the persisted size).
func TestBoltCapacityBoundsIngestNotCurated(t *testing.T) {
	s, path := tempBolt(t, 2)
	r := NewRegistry(s)
	if _, err := r.Ingest(KindFamily, "a", "", "s"); err != nil {
		t.Fatal(err)
	}
	if _, err := r.Ingest(KindFamily, "b", "", "s"); err != nil {
		t.Fatal(err)
	}
	// a new INGEST key past capacity is rejected.
	if _, err := r.Ingest(KindFamily, "c", "", "s"); err == nil {
		t.Fatal("a new ingest key past capacity should be rejected")
	}
	// a new CURATED key past capacity MUST still be admitted (never starved).
	if _, err := r.Curate(KindFamily, "d", "", nil, "s"); err != nil {
		t.Fatalf("curated fact must be admitted past the ingest cap: %v", err)
	}
	// an UPDATE to an existing key still succeeds at capacity (not a new key).
	if _, err := r.Ingest(KindFamily, "a", "updated", "s"); err != nil {
		t.Fatalf("update at capacity rejected: %v", err)
	}
	if err := s.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	// reopen: the count (3 facts: a,b,d) is re-derived, so the cap is still enforced.
	s2, err := OpenBoltStoreWithCap(path, 2)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	defer s2.Close()
	if s2.Len() != 3 {
		t.Fatalf("reopened count wrong: got %d, want 3", s2.Len())
	}
	r2 := NewRegistry(s2)
	if _, err := r2.Ingest(KindFamily, "e", "", "s"); err == nil {
		t.Fatal("a new ingest key must stay capped after reopen")
	}
	if _, err := r2.Curate(KindFamily, "f", "", nil, "s"); err != nil {
		t.Fatalf("curated must still be admitted after reopen: %v", err)
	}
}

// fail-closed reads over the persistent store: absent facts miss, and a
// fabricated (but syntactically valid) id does not verify.
func TestBoltColdReadsFailClosed(t *testing.T) {
	s, _ := tempBolt(t, 0)
	r := NewRegistry(s)
	if _, ok := r.Lookup(KindFamily, "emotet"); ok {
		t.Fatal("empty store returned a fact")
	}
	if r.VerifyCitation(factID(KindFamily, "emotet"), KindFamily, "emotet").Verified {
		t.Fatal("derived id of an absent fact verified")
	}
}

// concurrent distinct-key curation + lookup is safe under -race, and the live
// count stays consistent with the number of distinct keys written.
func TestBoltConcurrentAccess(t *testing.T) {
	s, _ := tempBolt(t, 0)
	r := NewRegistry(s)
	const n = 64
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			key := "fam" + itoa(i)
			_, _ = r.Curate(KindFamily, key, "l", nil, "s")
			_, _ = r.Lookup(KindFamily, key)
			_ = r.VerifyCitation(factID(KindFamily, normalizeKey(KindFamily, key)), KindFamily, key)
		}(i)
	}
	wg.Wait()
	if s.Len() != n {
		t.Fatalf("count after %d distinct concurrent curations = %d", n, s.Len())
	}
}

// the poisoning guard must hold under a concurrent first-time curate+ingest on the
// same fresh key, over the persistent store. this is the semantic race the -race
// detector cannot see, so it asserts the OUTCOME: once a curate has run, the stored
// fact is curated, never downgraded by an interleaved ingest. fewer iterations than
// the MemStore twin because each write is a real (fsynced) transaction.
func TestBoltConcurrentIngestVsCurateSameKey(t *testing.T) {
	s, _ := tempBolt(t, 0)
	r := NewRegistry(s)
	const iters = 100
	for i := 0; i < iters; i++ {
		key := "fam" + itoa(i)
		start := make(chan struct{})
		var wg sync.WaitGroup
		wg.Add(4)
		go func() { defer wg.Done(); <-start; _, _ = r.Curate(KindFamily, key, "GOOD", nil, "malpedia") }()
		for j := 0; j < 3; j++ {
			go func() { defer wg.Done(); <-start; _, _ = r.Ingest(KindFamily, key, "EVIL", "attacker") }()
		}
		close(start) // release all four at once for maximum contention
		wg.Wait()
		f, ok := r.Lookup(KindFamily, key)
		if !ok {
			t.Fatalf("iter %d: fact vanished", i)
		}
		if f.Trust != TrustCurated || f.Label != "GOOD" || f.Source != "malpedia" {
			t.Fatalf("iter %d: curated fact downgraded/poisoned by a raced ingest: %+v", i, f)
		}
	}
	if s.Len() != iters {
		t.Fatalf("expected %d distinct facts, got %d", iters, s.Len())
	}
}

// OpenStoreFromEnv selects the persistent store when MAL_KNOWLEDGE_DB is set and
// the in-memory store when it is not.
func TestOpenStoreFromEnv(t *testing.T) {
	// unset -> in-memory MemStore, close is a no-op.
	t.Setenv(EnvKnowledgeDB, "")
	store, closeFn, err := OpenStoreFromEnv()
	if err != nil {
		t.Fatalf("env unset: %v", err)
	}
	if _, ok := store.(*MemStore); !ok {
		t.Fatalf("unset env should yield a MemStore, got %T", store)
	}
	if err := closeFn(); err != nil {
		t.Fatalf("memstore close should be a no-op: %v", err)
	}

	// set -> persistent BoltStore that actually persists across a reopen.
	path := filepath.Join(t.TempDir(), "env.bolt")
	t.Setenv(EnvKnowledgeDB, path)
	store, closeFn, err = OpenStoreFromEnv()
	if err != nil {
		t.Fatalf("env set: %v", err)
	}
	if _, ok := store.(*BoltStore); !ok {
		t.Fatalf("set env should yield a BoltStore, got %T", store)
	}
	f, _ := NewRegistry(store).Curate(KindAttck, "T1055", "Process Injection", nil, "seed")
	if err := closeFn(); err != nil {
		t.Fatalf("close: %v", err)
	}
	store2, closeFn2, err := OpenStoreFromEnv()
	if err != nil {
		t.Fatalf("reopen via env: %v", err)
	}
	defer closeFn2()
	if got, ok := store2.Get(f.ID); !ok || got.Trust != TrustCurated {
		t.Fatalf("fact did not persist via env-selected store: %+v ok=%v", got, ok)
	}
}
