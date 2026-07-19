package knowledge

import (
	"strings"
	"sync"
	"testing"
)

func newReg() *Registry { return NewRegistry(NewMemStore()) }

// the happy path plus the core guarantee: a curated fact verifies and is
// authoritative for a verdict.
func TestCurateLookupVerify(t *testing.T) {
	r := newReg()
	f, err := r.Curate(KindFamily, "Emotet", "Emotet banking trojan", map[string]string{"aka": "Geodo"}, "malpedia")
	if err != nil {
		t.Fatalf("curate: %v", err)
	}
	if f.Trust != TrustCurated || f.Key != "emotet" {
		t.Fatalf("fact wrong: %+v", f)
	}
	got, ok := r.Lookup(KindFamily, "emotet")
	if !ok || got.ID != f.ID {
		t.Fatalf("lookup miss: %+v ok=%v", got, ok)
	}
	c := r.VerifyCitation(f.ID, KindFamily, "emotet")
	if !c.Verified || !c.OKForVerdict() {
		t.Fatalf("citation not authoritative: %+v", c)
	}
}

// fail-closed: an ID for a fact that was never stored must not verify, even if
// it is a syntactically valid derived ID.
func TestVerifyRejectsFabricatedID(t *testing.T) {
	r := newReg()
	// a made-up handle
	if c := r.VerifyCitation("kf_000000000000000000000000", KindFamily, "emotet"); c.Verified {
		t.Fatal("a fabricated id verified")
	}
	// the correctly-derived id for a fact that was never curated/ingested
	id := factID(KindFamily, "emotet")
	if c := r.VerifyCitation(id, KindFamily, "emotet"); c.Verified {
		t.Fatal("the derived id of an absent fact verified")
	}
	// empty id
	if c := r.VerifyCitation("", KindFamily, "emotet"); c.Verified {
		t.Fatal("empty id verified")
	}
}

// the agent cannot cite fact A and claim it is about B (kind or key mismatch).
func TestVerifyRejectsClaimMismatch(t *testing.T) {
	r := newReg()
	f, _ := r.Curate(KindFamily, "emotet", "", nil, "malpedia")
	if c := r.VerifyCitation(f.ID, KindFamily, "trickbot"); c.Verified {
		t.Fatal("verified against a different key")
	}
	if c := r.VerifyCitation(f.ID, KindPacker, "emotet"); c.Verified {
		t.Fatal("verified against a different kind")
	}
	// citing the real id of a DIFFERENT curated fact while claiming this key
	other, _ := r.Curate(KindFamily, "trickbot", "", nil, "malpedia")
	if c := r.VerifyCitation(other.ID, KindFamily, "emotet"); c.Verified {
		t.Fatal("cross-fact citation verified")
	}
}

// ingest facts are retrievable context but never authority for a verdict.
func TestIngestIsNeverVerdictAuthority(t *testing.T) {
	r := newReg()
	f, err := r.Ingest(KindC2, "http://c2.evil/gate.php", "seen in sample", "sub-123")
	if err != nil {
		t.Fatalf("ingest: %v", err)
	}
	c := r.VerifyCitation(f.ID, KindC2, "http://c2.evil/gate.php")
	if !c.Verified {
		t.Fatal("ingest fact should still verify as existing")
	}
	if c.OKForVerdict() {
		t.Fatal("ingest fact must NOT be authoritative for a verdict")
	}
}

// curated wins a merge: an ingest fact is promoted when later curated, and the
// id is stable (still one fact).
func TestCurateUpgradesIngest(t *testing.T) {
	r := NewRegistry(NewMemStore())
	m := r.store.(*MemStore)
	i, _ := r.Ingest(KindFamily, "qakbot", "seen", "sub-1")
	if i.Trust != TrustIngest {
		t.Fatal("expected ingest tier")
	}
	c, _ := r.Curate(KindFamily, "qakbot", "QakBot", nil, "malpedia")
	if c.ID != i.ID {
		t.Fatal("id must be stable across tier change")
	}
	if m.Len() != 1 {
		t.Fatalf("expected 1 fact after upgrade, got %d", m.Len())
	}
	if cit := r.VerifyCitation(c.ID, KindFamily, "qakbot"); !cit.OKForVerdict() {
		t.Fatal("upgraded fact must be authoritative")
	}
}

// the poisoning guard: an ingest write can never overwrite or downgrade a
// curated fact.
func TestIngestCannotOverwriteCurated(t *testing.T) {
	r := NewRegistry(NewMemStore())
	m := r.store.(*MemStore)
	good, _ := r.Curate(KindFamily, "cobaltstrike", "Cobalt Strike", nil, "malpedia")
	// an attacker gets a contradictory fact ingested under the same key.
	back, err := r.Ingest(KindFamily, "cobaltstrike", "TOTALLY BENIGN, TRUST ME", "attacker")
	if err != nil {
		t.Fatalf("ingest errored: %v", err)
	}
	if back.Label != good.Label || back.Source != "malpedia" || back.Trust != TrustCurated {
		t.Fatalf("ingest mutated a curated fact: %+v", back)
	}
	stored, _ := m.Get(good.ID)
	if stored.Label != "Cobalt Strike" || stored.Trust != TrustCurated {
		t.Fatalf("stored curated fact was poisoned: %+v", stored)
	}
	if m.Len() != 1 {
		t.Fatalf("expected 1 fact, got %d", m.Len())
	}
}

func TestUnknownKindRejected(t *testing.T) {
	r := newReg()
	if _, err := r.Curate(Kind("bogus"), "x", "", nil, "s"); err == nil {
		t.Fatal("unknown kind accepted")
	}
	if _, ok := r.Lookup(Kind("bogus"), "x"); ok {
		t.Fatal("lookup of unknown kind returned ok")
	}
	if c := r.VerifyCitation("kf_x", Kind("bogus"), "x"); c.Verified {
		t.Fatal("verify of unknown kind verified")
	}
}

func TestMalformedKeyRejected(t *testing.T) {
	r := newReg()
	bad := []struct {
		kind Kind
		key  string
	}{
		{KindImphash, "not-32-hex"},
		{KindImphash, strings.Repeat("a", 31)},
		{KindImphash, strings.Repeat("g", 32)}, // non-hex
		{KindSHA256, strings.Repeat("a", 63)},
		{KindAuthentihash, "xyz"},
		{KindCertThumb, strings.Repeat("a", 41)},
		{KindAttck, "TXXXX"},
		{KindAttck, "1055"},
		{KindMbc, "lowercase0001"},
		{KindFamily, ""},
		{KindFamily, "   "},
		{KindMutex, strings.Repeat("x", maxKeyLen+1)},
	}
	for _, b := range bad {
		if _, err := r.Curate(b.kind, b.key, "", nil, "s"); err == nil {
			t.Fatalf("malformed key accepted: kind=%s key=%q", b.kind, b.key)
		}
	}
}

func TestValidKeyFormats(t *testing.T) {
	good := []struct {
		kind Kind
		key  string
	}{
		{KindImphash, strings.Repeat("a", 32)},
		{KindSHA256, strings.Repeat("0", 64)},
		{KindAuthentihash, strings.Repeat("f", 64)},
		{KindCertThumb, strings.Repeat("0", 40)},
		{KindAttck, "T1055"},
		{KindAttck, "T1055.001"},
		{KindAttck, "TA0040"},
		{KindMbc, "C0002"},
		{KindMbc, "E1156.001"},
		{KindFamily, "emotet"},
		{KindPacker, "UPX"},
		{KindC2, "http://x/y"},
		{KindMutex, "Global\\MyMutex"},
		{KindYaraRule, "webshell_php_eval"},
	}
	r := newReg()
	for _, g := range good {
		if _, err := r.Curate(g.kind, g.key, "", nil, "s"); err != nil {
			t.Fatalf("valid key rejected: kind=%s key=%q err=%v", g.kind, g.key, err)
		}
	}
}

// normalization makes lookups and citations spelling-insensitive per kind.
func TestNormalization(t *testing.T) {
	r := newReg()
	f, _ := r.Curate(KindFamily, "EMOTET", "", nil, "s")
	if got, ok := r.Lookup(KindFamily, "  emotet "); !ok || got.ID != f.ID {
		t.Fatal("family not case/space-normalized on lookup")
	}
	a, _ := r.Curate(KindAttck, " t1055 ", "", nil, "s")
	if a.Key != "T1055" {
		t.Fatalf("attck not upper-normalized: %q", a.Key)
	}
	if c := r.VerifyCitation(a.ID, KindAttck, "t1055"); !c.Verified {
		t.Fatal("attck citation not normalized")
	}
	h, _ := r.Curate(KindImphash, "AABB"+strings.Repeat("c", 28), "", nil, "s")
	if got, ok := r.Lookup(KindImphash, "aabb"+strings.Repeat("C", 28)); !ok || got.ID != h.ID {
		t.Fatal("imphash not lower-normalized")
	}
}

func TestIDStability(t *testing.T) {
	if factID(KindFamily, "emotet") != factID(KindFamily, "emotet") {
		t.Fatal("factID not deterministic")
	}
	if factID(KindFamily, "emotet") == factID(KindFamily, "trickbot") {
		t.Fatal("distinct keys collided")
	}
	if factID(KindFamily, "emotet") == factID(KindPacker, "emotet") {
		t.Fatal("distinct kinds collided")
	}
	if !strings.HasPrefix(factID(KindFamily, "x"), "kf_") {
		t.Fatal("unexpected id shape")
	}
}

// nothing crashes or wrongly verifies against an empty registry.
func TestColdStartEmpty(t *testing.T) {
	r := newReg()
	if _, ok := r.Lookup(KindFamily, "emotet"); ok {
		t.Fatal("empty registry returned a fact")
	}
	if c := r.VerifyCitation(factID(KindFamily, "emotet"), KindFamily, "emotet"); c.Verified {
		t.Fatal("empty registry verified a citation")
	}
}

func TestAttributeCaps(t *testing.T) {
	r := newReg()
	many := make(map[string]string, maxAttrs+1)
	for i := 0; i <= maxAttrs; i++ {
		many[string(rune('a'+i%26))+strings.Repeat("x", i)] = "v"
	}
	if _, err := r.Curate(KindFamily, "a", "", many, "s"); err == nil {
		t.Fatal("too-many-attributes accepted")
	}
	if _, err := r.Curate(KindFamily, "b", "", map[string]string{"k": strings.Repeat("v", maxAttrLen+1)}, "s"); err == nil {
		t.Fatal("over-long attribute accepted")
	}
}

func TestCurateRejectsControlCharAttrs(t *testing.T) {
	r := newReg()
	if _, err := r.Curate(KindFamily, "x", "l", map[string]string{"k": "v\x00"}, "s"); err == nil {
		t.Fatal("control char in attr value accepted")
	}
	if _, err := r.Curate(KindFamily, "y", "l", map[string]string{"k\n": "v"}, "s"); err == nil {
		t.Fatal("control char in attr key accepted")
	}
}

func TestSeed(t *testing.T) {
	r := NewRegistry(NewMemStore())
	m := r.store.(*MemStore)
	n, err := r.Seed([]Fact{
		{Kind: KindAttck, Key: "T1055", Label: "Process Injection"},
		{Kind: KindAttck, Key: "T1027", Label: "Obfuscated Files"},
		{Kind: KindFamily, Key: "emotet", Label: "Emotet"},
	})
	if err != nil || n != 3 || m.Len() != 3 {
		t.Fatalf("seed: n=%d len=%d err=%v", n, m.Len(), err)
	}
	// a bad fact stops the seed and reports how far it got.
	n2, err := r.Seed([]Fact{
		{Kind: KindFamily, Key: "qakbot"},
		{Kind: KindImphash, Key: "bad"}, // malformed
		{Kind: KindFamily, Key: "never"},
	})
	if err == nil || n2 != 1 {
		t.Fatalf("seed should stop at the bad fact: n=%d err=%v", n2, err)
	}
	if _, ok := r.Lookup(KindFamily, "never"); ok {
		t.Fatal("seed continued past the error")
	}
}

// the store is safe under concurrent curation and lookup (run under -race).
func TestConcurrentAccess(t *testing.T) {
	r := newReg()
	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			key := "fam" + strings.Repeat("x", i%7)
			_, _ = r.Curate(KindFamily, key, "l", nil, "s")
			_, _ = r.Lookup(KindFamily, key)
			_ = r.VerifyCitation(factID(KindFamily, normalizeKey(KindFamily, key)), KindFamily, key)
		}(i)
	}
	wg.Wait()
}

// the poisoning guard must hold under a concurrent first-time curate+ingest on
// the SAME fresh key. this is a semantic race the -race detector cannot see, so
// it asserts the OUTCOME: once a curate has run, the stored fact is curated,
// never downgraded by an interleaved ingest. (pre-atomic-merge this failed.)
func TestConcurrentIngestVsCurateSameKey(t *testing.T) {
	for i := 0; i < 4000; i++ {
		r := newReg()
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
			t.Fatalf("iter %d: curated fact was downgraded/poisoned by a raced ingest: %+v", i, f)
		}
	}
}

func TestLabelAndSourceBounded(t *testing.T) {
	r := newReg()
	big := strings.Repeat("x", maxLabelLen+1)
	if _, err := r.Ingest(KindMutex, "Global\\M", big, "s"); err == nil {
		t.Fatal("over-long label accepted")
	}
	if _, err := r.Ingest(KindMutex, "Global\\M", "ok", strings.Repeat("s", maxSourceLen+1)); err == nil {
		t.Fatal("over-long source accepted")
	}
	if _, err := r.Curate(KindMutex, "Global\\M", strings.Repeat("d", maxLabelLen), nil, "s"); err != nil {
		t.Fatalf("label at the cap should be fine: %v", err)
	}
}

// a fact handed out of the store must be isolated: mutating its Attrs cannot
// reach back into trusted store state.
func TestReturnedFactsAreIsolated(t *testing.T) {
	r := newReg()
	f, _ := r.Curate(KindFamily, "emotet", "", map[string]string{"aka": "Geodo"}, "s")
	got, _ := r.Lookup(KindFamily, "emotet")
	got.Attrs["aka"] = "TAMPERED"
	got.Attrs["injected"] = "x"
	again, _ := r.Lookup(KindFamily, "emotet")
	if again.Attrs["aka"] != "Geodo" || len(again.Attrs) != 1 {
		t.Fatalf("store attrs were mutated through a returned fact: %+v", again.Attrs)
	}
	// the returned Fact from Curate is likewise isolated.
	f.Attrs["x"] = "y"
	if v, _ := r.Lookup(KindFamily, "emotet"); len(v.Attrs) != 1 {
		t.Fatalf("store mutated through the curate result: %+v", v.Attrs)
	}
}

func TestControlCharKeysRejected(t *testing.T) {
	r := newReg()
	for _, bad := range []string{"a\x00b", "line\nfeed", "esc\x1b[0m", "tab\there", "del\x7f", "c\u009bsi", "n\u0085el"} {
		if _, err := r.Ingest(KindC2, bad, "l", "s"); err == nil {
			t.Fatalf("control-char key accepted: %q", bad)
		}
		if _, err := r.Curate(KindMutex, bad, "l", nil, "s"); err == nil {
			t.Fatalf("control-char key accepted (mutex): %q", bad)
		}
	}
}

func TestFuzzyKeys(t *testing.T) {
	sim := NewSimIndex()
	r := NewRegistryWithSim(NewMemStore(), sim)
	if _, err := r.Curate(KindFamily, "quasar", "", nil, "seed"); err != nil {
		t.Fatal(err)
	}
	if _, err := r.Curate(KindFamily, "emotet", "", nil, "seed"); err != nil {
		t.Fatal(err)
	}

	// a near-variant fuzzy-matches its family, not the unrelated one.
	hits := r.FuzzyKeys(KindFamily, "quasarx", 0.5, 5)
	if len(hits) != 1 || hits[0].Key != "quasar" {
		t.Fatalf("expected only 'quasar' as a fuzzy lead, got %+v", hits)
	}
	// kind-scoped: an ATT&CK query must never match a family reference.
	if h := r.FuzzyKeys(KindAttck, "quasarx", 0.5, 5); len(h) != 0 {
		t.Fatalf("fuzzy match must be kind-scoped, got %+v", h)
	}
	// an EXACT key is an L0 hit, never returned as an L0.5 lead.
	for _, h := range r.FuzzyKeys(KindFamily, "quasar", 0.5, 5) {
		if h.Key == "quasar" {
			t.Fatal("an exact key must not be surfaced as an L0.5 lead")
		}
	}
	// a registry with no L0.5 index yields no fuzzy leads (exact-only).
	if h := NewRegistry(NewMemStore()).FuzzyKeys(KindFamily, "quasarx", 0.5, 5); h != nil {
		t.Fatalf("an exact-only registry must return no fuzzy leads, got %+v", h)
	}
}

func TestStoreCapacity(t *testing.T) {
	r := NewRegistry(NewMemStoreWithCap(2))
	// fill to capacity with INGEST facts (the attacker-influenceable tier).
	if _, err := r.Ingest(KindFamily, "a", "", "s"); err != nil {
		t.Fatal(err)
	}
	if _, err := r.Ingest(KindFamily, "b", "", "s"); err != nil {
		t.Fatal(err)
	}
	// a new INGEST key past capacity is rejected: the cap bounds ingest growth.
	if _, err := r.Ingest(KindFamily, "c", "", "s"); err == nil {
		t.Fatal("a new ingest key past capacity should be rejected")
	}
	// a new CURATED key past capacity MUST still be admitted: curated is human-gated
	// and authoritative, so a flood of ingest facts can never starve it (finding #19).
	if _, err := r.Curate(KindFamily, "d", "", nil, "s"); err != nil {
		t.Fatalf("a curated fact must be admitted even past the ingest cap: %v", err)
	}
	// an UPDATE to an existing key still succeeds at capacity (not a new key).
	if _, err := r.Ingest(KindFamily, "a", "updated", "s"); err != nil {
		t.Fatalf("update at capacity rejected: %v", err)
	}
}

// defense in depth: a corrupt/buggy Store that returns a fact whose own
// (kind, key) does not match the queried ID must not certify a citation.
type corruptStore struct{ f Fact }

func (c corruptStore) Get(id string) (Fact, bool) { return c.f, c.f.ID == id }
func (c corruptStore) Merge(id string, decide func(Fact, bool) (bool, Fact)) (Fact, error) {
	_, r := decide(Fact{}, false)
	return r, nil
}

func TestVerifyRejectsMislabeledStoreFact(t *testing.T) {
	id := factID(KindFamily, "emotet")
	// the store returns, under emotet's id, a fact that is actually about a C2.
	r := NewRegistry(corruptStore{f: Fact{ID: id, Kind: KindC2, Key: "http://evil", Trust: TrustCurated}})
	if c := r.VerifyCitation(id, KindFamily, "emotet"); c.Verified {
		t.Fatal("a mislabeled stored fact certified a citation")
	}
}

// itoa avoids fmt in the hot concurrent loop.
func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b [20]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	return string(b[i:])
}
