package knowledge

import (
	"fmt"
	"math"
	"sync"
	"testing"
)

func feats(prefix string, from, to int) []string {
	out := make([]string, 0, to-from)
	for i := from; i < to; i++ {
		out = append(out, fmt.Sprintf("%s%d", prefix, i))
	}
	return out
}

// a signature is deterministic, order-independent, and duplicate-insensitive.
func TestSignatureIsDeterministicSetSemantics(t *testing.T) {
	a := SignatureOf([]string{"a", "b", "c"})
	b := SignatureOf([]string{"c", "a", "b"})           // reordered
	c := SignatureOf([]string{"a", "b", "c", "b", "a"}) // duplicates
	if a != b {
		t.Fatal("signature is order-dependent")
	}
	if a != c {
		t.Fatal("signature is duplicate-sensitive")
	}
	if a.Card != 3 {
		t.Fatalf("cardinality wrong: %d", a.Card)
	}
	if a.ID() != b.ID() {
		t.Fatal("id not stable for the same set")
	}
}

func TestSimilarityExtremes(t *testing.T) {
	a := SignatureOf(feats("x", 0, 100))
	if s := Similarity(a, a); s != 1.0 {
		t.Fatalf("identical similarity %v, want 1.0", s)
	}
	disjointA := SignatureOf(feats("a", 0, 50))
	disjointB := SignatureOf(feats("b", 0, 50))
	if s := Similarity(disjointA, disjointB); s != 0.0 {
		t.Fatalf("disjoint similarity %v, want 0.0", s)
	}
}

func TestSimilarityEmptyMatchesNothing(t *testing.T) {
	empty := SignatureOf(nil)
	if !empty.Empty() {
		t.Fatal("nil features should be an empty signature")
	}
	nonEmpty := SignatureOf([]string{"a"})
	if Similarity(empty, nonEmpty) != 0 {
		t.Fatal("empty vs non-empty must be 0")
	}
	if Similarity(empty, empty) != 0 {
		t.Fatal("empty vs empty must be 0 (a featureless artifact never matches)")
	}
	// signatures of only empty strings are still empty.
	if !SignatureOf([]string{"", "", ""}).Empty() {
		t.Fatal("all-empty-string features should be empty")
	}
}

// the MinHash estimate tracks the true Jaccard within its statistical error.
func TestSimilarityEstimatesJaccard(t *testing.T) {
	// A = 0..199, B = 100..299: intersection 100, union 300, Jaccard = 1/3.
	a := SignatureOf(feats("f", 0, 200))
	b := SignatureOf(feats("f", 100, 300))
	got := Similarity(a, b)
	want := 1.0 / 3.0
	if got < want-0.16 || got > want+0.16 {
		t.Fatalf("jaccard estimate %v, want ~%v (K=%d)", got, want, sigLanes)
	}
	// higher overlap must score higher than lower overlap (monotone ranking).
	hi := Similarity(SignatureOf(feats("f", 0, 200)), SignatureOf(feats("f", 20, 220)))  // J ~ 0.82
	lo := Similarity(SignatureOf(feats("f", 0, 200)), SignatureOf(feats("f", 180, 380))) // J ~ 0.05
	if !(hi > lo) {
		t.Fatalf("ranking broken: hi=%v lo=%v", hi, lo)
	}
}

func TestNGrams(t *testing.T) {
	g := NGrams([]byte("ABCD"), 2)
	if len(g) != 3 || g[0] != "4142" || g[2] != "4344" {
		t.Fatalf("ngrams wrong: %v", g)
	}
	if NGrams([]byte("A"), 2) != nil {
		t.Fatal("input shorter than n should yield nil")
	}
	if NGrams([]byte("ABC"), 0) != nil {
		t.Fatal("n<=0 should yield nil")
	}
	// a repacked-variant analogy: shared substring -> nonzero similarity.
	x := SignatureOf(NGrams([]byte("the quick brown fox jumps over the lazy dog"), 4))
	y := SignatureOf(NGrams([]byte("the quick brown fox leaps over the lazy cat"), 4))
	if s := Similarity(x, y); s <= 0.2 {
		t.Fatalf("shared-substring similarity too low: %v", s)
	}
}

func TestIndexNearest(t *testing.T) {
	idx := NewSimIndex()
	ref := SignatureOf(feats("f", 0, 200))
	idx.AddReference(ref, "family:acme", "malpedia")
	idx.AddReference(SignatureOf(feats("g", 0, 200)), "family:other", "malpedia")

	// a near-identical variant queries close to the acme reference.
	variant := SignatureOf(feats("f", 5, 205)) // ~0.90 Jaccard with ref
	got := idx.Nearest(variant, 0.5, 10)
	if len(got) != 1 {
		t.Fatalf("expected 1 neighbor over threshold, got %d: %+v", len(got), got)
	}
	if got[0].Label != "family:acme" || got[0].Trust != TrustCurated || got[0].Sim < 0.7 {
		t.Fatalf("nearest wrong: %+v", got[0])
	}
	// a neighbor is re-resolvable and its score recomputes (spine verification).
	e, ok := idx.Get(got[0].ID)
	if !ok || Similarity(variant, e.Sig) != got[0].Sim {
		t.Fatal("neighbor not verifiable / score not reproducible")
	}
	// empty query and empty index yield nothing.
	if idx.Nearest(SignatureOf(nil), 0, 10) != nil {
		t.Fatal("empty query matched")
	}
	if NewSimIndex().Nearest(variant, 0, 10) != nil {
		t.Fatal("empty index matched")
	}
}

func TestNearestSortingAndLimit(t *testing.T) {
	idx := NewSimIndex()
	base := feats("f", 0, 200)
	idx.AddReference(SignatureOf(base), "closest", "s")
	idx.AddReference(SignatureOf(feats("f", 40, 240)), "mid", "s")
	idx.AddReference(SignatureOf(feats("f", 120, 320)), "far", "s")
	q := SignatureOf(feats("f", 0, 200))
	got := idx.Nearest(q, 0.0, 2)
	if len(got) != 2 {
		t.Fatalf("limit not honored: %d", len(got))
	}
	if got[0].Label != "closest" || got[0].Sim < got[1].Sim {
		t.Fatalf("not sorted by similarity desc: %+v", got)
	}
}

// an ingest signature can never overwrite a curated one at the same sketch, and
// ingest neighbors carry the low-trust tier so the gate can discount them.
func TestSimIngestCannotOverwriteReference(t *testing.T) {
	idx := NewSimIndex()
	sig := SignatureOf(feats("f", 0, 100))
	idx.AddReference(sig, "TRUSTED family", "malpedia")
	e, ok := idx.AddObserved(sig, "attacker relabel", "attacker")
	if !ok {
		t.Fatal("observe should succeed as a no-op")
	}
	if e.Trust != TrustCurated || e.Label != "TRUSTED family" {
		t.Fatalf("ingest overwrote a curated reference: %+v", e)
	}
	if idx.Len() != 1 {
		t.Fatalf("expected 1 entry, got %d", idx.Len())
	}
}

func TestSimEmptyAndBoundsRejected(t *testing.T) {
	idx := NewSimIndex()
	if _, ok := idx.AddReference(SignatureOf(nil), "x", "s"); ok {
		t.Fatal("empty signature should be rejected")
	}
	if idx.Len() != 0 {
		t.Fatal("empty signature was stored")
	}
	big := make([]byte, maxLabelLen+1)
	for i := range big {
		big[i] = 'x'
	}
	if _, ok := idx.AddReference(SignatureOf(feats("f", 0, 10)), string(big), "s"); ok {
		t.Fatal("over-long label should be rejected")
	}
}

// capacity bounds the low-trust INGEST working index; a trusted curated
// reference is always admitted, so ingest can never starve curated out.
func TestSimCapacityBoundsIngestNotCurated(t *testing.T) {
	idx := NewSimIndexWithCap(2)
	if _, ok := idx.AddObserved(SignatureOf(feats("a", 0, 10)), "a", "s"); !ok {
		t.Fatal("first ingest failed")
	}
	if _, ok := idx.AddObserved(SignatureOf(feats("b", 0, 10)), "b", "s"); !ok {
		t.Fatal("second ingest failed")
	}
	if _, ok := idx.AddObserved(SignatureOf(feats("c", 0, 10)), "c", "s"); ok {
		t.Fatal("new ingest past capacity should be rejected")
	}
	if _, ok := idx.AddReference(SignatureOf(feats("d", 0, 10)), "d", "malpedia"); !ok {
		t.Fatal("curated reference must be admitted even when ingest filled capacity")
	}
}

func TestSimLabelSourceControlCharsRejected(t *testing.T) {
	idx := NewSimIndex()
	sig := SignatureOf(feats("f", 0, 20))
	if _, ok := idx.AddReference(sig, "bad\nlabel", "s"); ok {
		t.Fatal("control char in label accepted")
	}
	if _, ok := idx.AddObserved(sig, "ok", "src\x00x"); ok {
		t.Fatal("control char in source accepted")
	}
}

func TestNearestNaNAndNoLimit(t *testing.T) {
	idx := NewSimIndex()
	idx.AddReference(SignatureOf(feats("f", 0, 50)), "x", "s")
	q := SignatureOf(feats("f", 0, 50))
	if got := idx.Nearest(q, math.NaN(), 10); got != nil {
		t.Fatalf("NaN minSim must match nothing, got %d", len(got))
	}
	if got := idx.Nearest(q, 0, 0); len(got) != 1 {
		t.Fatalf("limit<=0 must return all, got %d", len(got))
	}
}

// the poisoning guard holds under concurrent curate+observe on the SAME sketch
// (outcome-asserted, since -race cannot see this semantic race).
func TestSimConcurrentSameSketch(t *testing.T) {
	for iter := 0; iter < 2000; iter++ {
		idx := NewSimIndex()
		sig := SignatureOf(feats("f", 0, 40))
		start := make(chan struct{})
		var wg sync.WaitGroup
		wg.Add(4)
		go func() { defer wg.Done(); <-start; idx.AddReference(sig, "GOOD", "malpedia") }()
		for j := 0; j < 3; j++ {
			go func() { defer wg.Done(); <-start; idx.AddObserved(sig, "EVIL", "attacker") }()
		}
		close(start)
		wg.Wait()
		if e, ok := idx.Get(sig.ID()); !ok || e.Trust != TrustCurated || e.Label != "GOOD" {
			t.Fatalf("iter %d: curated reference downgraded under concurrency: %+v", iter, e)
		}
	}
}

// output order is stable across runs despite randomized map iteration: the sort
// is a total order (unique-ID final tiebreak), so a tie regression would surface.
func TestNearestOrderIsDeterministic(t *testing.T) {
	idx := NewSimIndex()
	for i := 0; i < 8; i++ {
		idx.AddReference(SignatureOf(feats("f", i*10, i*10+200)), "r"+itoa(i), "s")
	}
	q := SignatureOf(feats("f", 0, 200))
	var first []string
	for run := 0; run < 30; run++ {
		got := idx.Nearest(q, 0.0, 100)
		order := make([]string, len(got))
		for i, n := range got {
			order[i] = n.ID
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
				t.Fatalf("run %d: nondeterministic order at %d", run, i)
			}
		}
	}
}

func TestSimilaritySymmetryAndBounds(t *testing.T) {
	sets := [][]string{feats("a", 0, 100), feats("a", 50, 150), feats("b", 0, 100), {"x"}, {"y"}, nil}
	for _, s1 := range sets {
		for _, s2 := range sets {
			a, b := SignatureOf(s1), SignatureOf(s2)
			ab, ba := Similarity(a, b), Similarity(b, a)
			if ab != ba {
				t.Fatalf("asymmetric similarity: %v vs %v", ab, ba)
			}
			if ab < 0 || ab > 1 || ab != ab {
				t.Fatalf("similarity out of [0,1] or NaN: %v", ab)
			}
		}
	}
	if Similarity(SignatureOf([]string{"x"}), SignatureOf([]string{"y"})) != 0 {
		t.Fatal("distinct singletons must score 0")
	}
}

func TestSimConcurrent(t *testing.T) {
	idx := NewSimIndex()
	q := SignatureOf(feats("q", 0, 50))
	var wg sync.WaitGroup
	for i := 0; i < 60; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			idx.AddObserved(SignatureOf(feats(fmt.Sprintf("s%d-", i), 0, 30)), "l", "s")
			_ = idx.Nearest(q, 0.1, 5)
			_ = idx.Len()
		}(i)
	}
	wg.Wait()
}
