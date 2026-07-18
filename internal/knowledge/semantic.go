package knowledge

// L2: the semantic / GraphRAG novelty-only fallback (design sec 08). it is
// consulted ONLY when the deterministic tiers (L0 exact-key, L0.5 fuzzy, L1
// graph) leave material uncertainty, and its output is deliberately weak by
// construction:
//
//   - NON-CITABLE: an L2 result is a Claim, never a Citation. it carries no L0
//     fact id, so it can never be passed to VerifyCitation and can never ground a
//     verdict-moving statement. the type system enforces this - the gate only
//     grounds on curated-verified Citations.
//   - confidence-LOWERING: reaching L2 at all means the deterministic tiers were
//     insufficient; a consumer treats an L2 hit as a reason to LOWER confidence /
//     escalate, never to raise it.
//   - provenance-tagged: every claim records where it came from, for the human.
//
// the semantic quality depends on the embedding model (ASK.md EMB-1); the
// STRUCTURE - bounded nearest-neighbour, non-citable, deterministic ordering - is
// what lives here and is proven offline with a deterministic hash embedder. the
// real embedder swaps in behind the Embedder interface by config alone.

import (
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"math"
	"sort"
	"strings"
	"sync"
)

// defaultSemanticMax bounds the in-memory index so an attacker cannot grow it
// without limit by getting many artifacts analyzed.
const defaultSemanticMax = 500_000

// Embedder turns text into a unit-normalized vector. the real implementation
// calls a local embedding server; HashEmbedder is the deterministic offline one.
type Embedder interface {
	Embed(text string) ([]float32, error)
	Dim() int
}

// Claim is an L2 result: a non-citable, confidence-lowering, provenance-tagged
// nearest neighbour. Citable is ALWAYS false - it is present to make the
// invariant explicit and greppable, not because it could ever be true.
type Claim struct {
	Text       string
	Provenance string
	Similarity float64 // cosine, clamped to [0,1]
	Citable    bool    // always false for L2; L2 claims never ground a verdict
}

// SemanticIndex is the L2 store: unit vectors + their source text, with bounded
// capacity and cosine nearest-neighbour retrieval. safe for concurrent use.
type SemanticIndex struct {
	mu    sync.Mutex
	emb   Embedder
	items []semItem
	max   int
}

type semItem struct {
	vec  []float32
	text string
	prov string
}

// NewSemanticIndex builds an L2 index over an embedder. max<=0 uses the default.
func NewSemanticIndex(emb Embedder, max int) *SemanticIndex {
	if max <= 0 {
		max = defaultSemanticMax
	}
	return &SemanticIndex{emb: emb, max: max}
}

// Add embeds text and stores it with provenance. it is bounded: once full, new
// entries are rejected (fail-closed on growth) rather than evicting, so L2 can
// never be forced to forget under flood - it simply stops growing and the tier
// degrades to "no novel context", which only lowers confidence further.
func (s *SemanticIndex) Add(text, provenance string) error {
	if s.emb == nil {
		return fmt.Errorf("knowledge: semantic index has no embedder")
	}
	v, err := s.emb.Embed(text)
	if err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.items) >= s.max {
		return fmt.Errorf("knowledge: semantic index at capacity (%d)", s.max)
	}
	s.items = append(s.items, semItem{vec: v, text: text, prov: provenance})
	return nil
}

// Nearest returns the top-k most similar stored items as NON-CITABLE claims,
// ordered by similarity (deterministic tie-break on text). an empty index or a
// non-positive k returns nothing. it never errors on emptiness - "no novel
// context" is a valid, confidence-lowering answer.
func (s *SemanticIndex) Nearest(query string, k int) ([]Claim, error) {
	if s.emb == nil {
		return nil, fmt.Errorf("knowledge: semantic index has no embedder")
	}
	if k <= 0 {
		return nil, nil
	}
	q, err := s.emb.Embed(query)
	if err != nil {
		return nil, err
	}
	s.mu.Lock()
	items := s.items // slice header copy; entries are immutable once stored
	s.mu.Unlock()

	claims := make([]Claim, 0, len(items))
	for _, it := range items {
		sim := cosine(q, it.vec)
		if sim < 0 {
			sim = 0 // novelty similarity is non-negative; opposite vectors are "not similar"
		}
		claims = append(claims, Claim{Text: it.text, Provenance: it.prov, Similarity: sim, Citable: false})
	}
	sort.Slice(claims, func(i, j int) bool {
		if claims[i].Similarity != claims[j].Similarity {
			return claims[i].Similarity > claims[j].Similarity
		}
		return claims[i].Text < claims[j].Text
	})
	if len(claims) > k {
		claims = claims[:k]
	}
	return claims, nil
}

// Len reports how many items are indexed.
func (s *SemanticIndex) Len() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.items)
}

// cosine is the dot product of two vectors; for unit vectors that IS the cosine.
// mismatched lengths return 0 (defensive - a corrupt/wrong-dim vector is "not
// similar", never a panic).
func cosine(a, b []float32) float64 {
	if len(a) != len(b) || len(a) == 0 {
		return 0
	}
	var dot float64
	for i := range a {
		dot += float64(a[i]) * float64(b[i])
	}
	return dot
}

// HashEmbedder is a deterministic, network-free embedder: signed feature hashing
// of whitespace tokens into a fixed-dim, L2-normalized vector. it is not a
// semantic model - it captures lexical overlap - but it is fully reproducible,
// which is exactly what the offline tests and an air-gapped default need. the
// real embedding model replaces it behind the Embedder interface.
type HashEmbedder struct{ dim int }

// NewHashEmbedder builds a hash embedder of the given dimension (<=0 -> 256).
func NewHashEmbedder(dim int) *HashEmbedder {
	if dim <= 0 {
		dim = 256
	}
	return &HashEmbedder{dim: dim}
}

// Dim returns the vector dimension.
func (h *HashEmbedder) Dim() int { return h.dim }

// Embed maps text to a unit vector via signed feature hashing. empty/token-free
// text yields a zero vector (cosine 0 against everything - maximally novel).
func (h *HashEmbedder) Embed(text string) ([]float32, error) {
	v := make([]float32, h.dim)
	for _, tok := range strings.Fields(strings.ToLower(text)) {
		sum := sha256.Sum256([]byte(tok))
		idx := binary.BigEndian.Uint32(sum[:4]) % uint32(h.dim)
		if sum[4]&1 == 1 {
			v[idx] -= 1
		} else {
			v[idx] += 1
		}
	}
	var n float64
	for _, x := range v {
		n += float64(x) * float64(x)
	}
	if n > 0 {
		inv := float32(1 / math.Sqrt(n))
		for i := range v {
			v[i] *= inv
		}
	}
	return v, nil
}
