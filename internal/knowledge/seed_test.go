package knowledge

import "testing"

func TestSeedStarterPopulates(t *testing.T) {
	store := NewMemStore()
	r := NewRegistry(store)
	curated, skipped, err := r.SeedStarter()
	if err != nil {
		t.Fatalf("seed: %v", err)
	}
	if skipped != 0 {
		t.Fatalf("the bundled starter corpus must be clean, %d skipped", skipped)
	}
	if curated < 50 || store.Len() != curated {
		t.Fatalf("starter corpus too small or count mismatch: curated=%d len=%d", curated, store.Len())
	}
	// a seeded ATT&CK technique is curated authority: a citation to it verifies.
	f, ok := r.Lookup(KindAttck, "T1055")
	if !ok || f.Trust != TrustCurated {
		t.Fatalf("T1055 not curated after seed: %+v ok=%v", f, ok)
	}
	if !r.VerifyCitation(f.ID, KindAttck, "T1055").OKForVerdict() {
		t.Fatal("a citation to a seeded curated fact must be verdict-usable")
	}
	// a normalized family key resolves too.
	if _, ok := r.Lookup(KindFamily, "Emotet"); !ok {
		t.Fatal("family lookup should be case-normalized (Emotet -> emotet)")
	}
}

func TestSeedJSONSkipsMalformed(t *testing.T) {
	r := NewRegistry(NewMemStore())
	blob := []byte(`{"source":"t","facts":[` +
		`{"kind":"bogus","key":"x","label":"y"},` + // unknown kind -> skip
		`{"kind":"attck","key":"notatechnique","label":"z"},` + // malformed key -> skip
		`{"kind":"attck","key":"T1055","label":"Process Injection"}` + // valid -> curate
		`]}`)
	curated, skipped, err := r.SeedJSON(blob)
	if err != nil {
		t.Fatalf("seed json: %v", err)
	}
	if curated != 1 || skipped != 2 {
		t.Fatalf("tolerant per-fact seeding wrong: curated=%d skipped=%d", curated, skipped)
	}
}

func TestSeedJSONStrictEnvelope(t *testing.T) {
	r := NewRegistry(NewMemStore())
	if _, _, err := r.SeedJSON([]byte(`{"facts":[],"evil":1}`)); err == nil {
		t.Fatal("unknown envelope field must be rejected")
	}
	if _, _, err := r.SeedJSON([]byte(`{"facts":[]}{"more":1}`)); err == nil {
		t.Fatal("trailing data must be rejected")
	}
}

func TestSeedIdempotent(t *testing.T) {
	store := NewMemStore()
	r := NewRegistry(store)
	if _, _, err := r.SeedStarter(); err != nil {
		t.Fatal(err)
	}
	n1 := store.Len()
	if _, _, err := r.SeedStarter(); err != nil {
		t.Fatal(err)
	}
	if store.Len() != n1 {
		t.Fatalf("re-seeding must not grow the store: %d -> %d", n1, store.Len())
	}
}
