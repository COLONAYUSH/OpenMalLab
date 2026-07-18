package knowledge

import (
	"math"
	"testing"
)

func TestHashEmbedderDeterministicAndNormalized(t *testing.T) {
	e := NewHashEmbedder(128)
	a1, _ := e.Embed("cobalt strike beacon http")
	a2, _ := e.Embed("cobalt strike beacon http")
	for i := range a1 {
		if a1[i] != a2[i] {
			t.Fatal("embedding must be deterministic")
		}
	}
	var n float64
	for _, x := range a1 {
		n += float64(x) * float64(x)
	}
	if math.Abs(n-1) > 1e-5 {
		t.Fatalf("embedding must be unit-normalized, |v|^2=%v", n)
	}
	// empty text -> zero vector (maximally novel).
	z, _ := e.Embed("   ")
	if cosine(z, a1) != 0 {
		t.Fatal("empty text must embed to a zero vector")
	}
}

func TestSemanticNearestRanksAndNeverCites(t *testing.T) {
	idx := NewSemanticIndex(NewHashEmbedder(256), 0)
	if err := idx.Add("emotet dropper registry run key persistence", "sample:a"); err != nil {
		t.Fatal(err)
	}
	if err := idx.Add("benign text editor opens a document", "sample:b"); err != nil {
		t.Fatal(err)
	}
	claims, err := idx.Nearest("emotet persistence registry run key", 2)
	if err != nil {
		t.Fatal(err)
	}
	if len(claims) != 2 {
		t.Fatalf("want 2 claims, got %d", len(claims))
	}
	// the lexically-overlapping item ranks first.
	if claims[0].Provenance != "sample:a" {
		t.Fatalf("nearest is not the overlapping item: %+v", claims)
	}
	// EVERY L2 claim is non-citable and has a bounded similarity.
	for _, c := range claims {
		if c.Citable {
			t.Fatal("an L2 claim must NEVER be citable")
		}
		if c.Similarity < 0 || c.Similarity > 1 {
			t.Fatalf("similarity out of range: %v", c.Similarity)
		}
	}
}

func TestSemanticEmptyAndKGuards(t *testing.T) {
	idx := NewSemanticIndex(NewHashEmbedder(64), 0)
	// empty index: "no novel context" is a valid, non-error answer.
	if c, err := idx.Nearest("anything", 3); err != nil || len(c) != 0 {
		t.Fatalf("empty index should return no claims, no error: %v %v", c, err)
	}
	_ = idx.Add("x", "p")
	if c, _ := idx.Nearest("x", 0); len(c) != 0 {
		t.Fatal("k<=0 must return nothing")
	}
}

func TestSemanticBoundedFailsClosed(t *testing.T) {
	idx := NewSemanticIndex(NewHashEmbedder(32), 2)
	if err := idx.Add("a", "1"); err != nil {
		t.Fatal(err)
	}
	if err := idx.Add("b", "2"); err != nil {
		t.Fatal(err)
	}
	if err := idx.Add("c", "3"); err == nil {
		t.Fatal("adding past capacity must fail closed, not evict")
	}
	if idx.Len() != 2 {
		t.Fatalf("capacity not held: %d", idx.Len())
	}
}
