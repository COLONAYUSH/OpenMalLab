package knowledge

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"sort"
	"sync"
)

// tier L0.5 is fuzzy-but-deterministic similarity: the workhorse for "known
// family, repacked variant", the huge middle that is neither an exact-key hit
// (L0) nor genuine novelty. it is a MinHash sketch over a feature set, so a
// similarity score is REPRODUCIBLE - the spine can recompute it and re-verify a
// neighbor's stored signature, exactly as the design requires. no LLM, no
// floating opinion, just algebra over hashes.
//
// like L0 it carries a trust tier: a CURATED reference set (trusted) versus an
// INGEST working index (auto-populated, lower-trust). an ingest neighbor may
// inform triage but LOWERS confidence and never backs a verdict on its own, and
// an ingest entry can never overwrite a curated one. this keeps the poisoning
// surface bounded even though the index self-populates.
//
// the MinHash estimates Jaccard set similarity; TLSH/ssdeep/imphash and other
// concrete signals become feature extractors that feed SignatureOf. this file
// is dependency-free on purpose (the air-gapped plane keeps its surface tiny).

// sigLanes is the MinHash width. 64 lanes gives a Jaccard estimate with stderr
// ~ sqrt(J(1-J)/64) (about 0.06 at J=0.5) - enough to rank neighbors while the
// gate treats any single score as evidence, not proof.
const sigLanes = 64

// laneSeed are fixed per-lane seeds, so a Signature is identical across
// processes and runs. computed once from a constant, never from a clock/random.
var laneSeed [sigLanes]uint64

func init() {
	for i := range laneSeed {
		laneSeed[i] = mix64(uint64(i)*0x9e3779b97f4a7c15 + 0x123456789abcdef0)
	}
}

// mix64 is a splitmix64 finalizer: a strong, deterministic bit mixer.
func mix64(x uint64) uint64 {
	x ^= x >> 30
	x *= 0xbf58476d1ce4e5b9
	x ^= x >> 27
	x *= 0x94d049bb133111eb
	x ^= x >> 31
	return x
}

// baseHash hashes a feature to a base value the lanes then mix. sha256-derived,
// so it is collision- and preimage-resistant: an adversary cannot cheaply craft
// two different feature strings that collapse to the same base (which would let
// a substituted feature set reproduce a reference sketch and defeat recompute-to-
// verify), and a feature is not recoverable from a stored sketch. deterministic
// (no key or seed from a clock), so signatures stay reproducible across runs.
func baseHash(feature string) uint64 {
	sum := sha256.Sum256([]byte(feature))
	return binary.LittleEndian.Uint64(sum[:8])
}

// Signature is a MinHash sketch of a feature set. Card is the number of
// distinct features observed, so an empty/degenerate signature is detectable
// (it must never spuriously match).
type Signature struct {
	Min  [sigLanes]uint64
	Card int
}

// Empty reports whether the signature was built from no features.
func (s Signature) Empty() bool { return s.Card == 0 }

// ID is a stable content handle for the signature: two identical sketches share
// an ID, so a similarity neighbor is a re-resolvable reference (the spine can
// fetch it and recompute the score).
func (s Signature) ID() string {
	var buf [sigLanes * 8]byte
	for i, m := range s.Min {
		binary.LittleEndian.PutUint64(buf[i*8:], m)
	}
	sum := sha256.Sum256(buf[:])
	return "ks_" + hex.EncodeToString(sum[:12])
}

// SignatureOf builds a sketch from a feature set. order-independent and
// duplicate-insensitive (set semantics): the same set always yields the same
// signature. empty strings are ignored.
func SignatureOf(features []string) Signature {
	var s Signature
	for i := range s.Min {
		s.Min[i] = ^uint64(0)
	}
	seen := make(map[uint64]struct{}, len(features))
	for _, f := range features {
		if f == "" {
			continue
		}
		bh := baseHash(f)
		if _, dup := seen[bh]; dup {
			continue
		}
		seen[bh] = struct{}{}
		for i := 0; i < sigLanes; i++ {
			if h := mix64(bh ^ laneSeed[i]); h < s.Min[i] {
				s.Min[i] = h
			}
		}
	}
	s.Card = len(seen)
	return s
}

// maxNGramBytes bounds how much input NGrams scans, so a huge sample cannot make
// it allocate without limit.
const maxNGramBytes = 8 << 20

// NGrams extracts DISTINCT overlapping byte n-grams as hex feature strings - a
// simple, deterministic structural-similarity signal usable directly on raw
// bytes. a repacked variant that shares code shares n-grams. it dedups as it
// scans and considers at most the first maxNGramBytes, so memory is bounded
// regardless of input size. n<=0 or too-short input yields no features.
func NGrams(data []byte, n int) []string {
	if n <= 0 || len(data) < n {
		return nil
	}
	if len(data) > maxNGramBytes {
		data = data[:maxNGramBytes]
	}
	seen := make(map[string]struct{})
	out := make([]string, 0, 1024)
	for i := 0; i+n <= len(data); i++ {
		g := hex.EncodeToString(data[i : i+n])
		if _, dup := seen[g]; dup {
			continue
		}
		seen[g] = struct{}{}
		out = append(out, g)
	}
	return out
}

// Similarity estimates the Jaccard similarity of the two feature sets, in
// [0,1]. it is exact at the extremes (identical sets -> 1, disjoint -> 0) and an
// unbiased estimate between. an empty signature is similar to nothing, including
// another empty one (so a featureless artifact never matches).
func Similarity(a, b Signature) float64 {
	if a.Empty() || b.Empty() {
		return 0
	}
	match := 0
	for i := 0; i < sigLanes; i++ {
		if a.Min[i] == b.Min[i] {
			match++
		}
	}
	return float64(match) / float64(sigLanes)
}

// SimEntry is one signature in the index.
type SimEntry struct {
	ID     string
	Sig    Signature
	Trust  Trust
	Label  string
	Source string
}

// Neighbor is a similarity hit: a re-resolvable ID, its trust tier (ingest
// lowers confidence), the reproducible score, and its label.
type Neighbor struct {
	ID     string
	Trust  Trust
	Sim    float64
	Label  string
	Source string
}

// SimIndex is the L0.5 nearest-neighbor index over signatures. safe for
// concurrent use. entries are keyed by signature ID, so near-duplicate files
// (identical sketch) collapse to one entry, merged with the same tier rule as
// L0: curated wins, ingest never overwrites curated.
//
// NOTE: Nearest is a linear scan today - correct and reproducible, but O(n) per
// query. locality-sensitive-hashing (band the lanes into buckets) is the sub-
// linear scale optimization and is a later, behavior-preserving change.
type SimIndex struct {
	mu      sync.Mutex
	entries map[string]SimEntry
	max     int
}

// NewSimIndex returns an empty index with the default capacity.
func NewSimIndex() *SimIndex { return NewSimIndexWithCap(defaultMaxFacts) }

// NewSimIndexWithCap bounds the index to max entries (<=0 means the default).
func NewSimIndexWithCap(max int) *SimIndex {
	if max <= 0 {
		max = defaultMaxFacts
	}
	return &SimIndex{entries: make(map[string]SimEntry), max: max}
}

// add inserts or merges a signature at the given tier. an empty signature is
// rejected (it would match nothing and only bloat the index). curated wins;
// ingest never overwrites a curated entry.
func (x *SimIndex) add(sig Signature, trust Trust, label, source string) (SimEntry, bool) {
	if sig.Empty() || len(label) > maxLabelLen || len(source) > maxSourceLen ||
		hasControl(label) || hasControl(source) {
		return SimEntry{}, false
	}
	id := sig.ID()
	x.mu.Lock()
	defer x.mu.Unlock()
	if existing, ok := x.entries[id]; ok {
		if existing.Trust == TrustCurated && trust == TrustIngest {
			return existing, true // poisoning guard, under the lock
		}
	} else if trust == TrustIngest && len(x.entries) >= x.max {
		// the cap bounds the attacker-populated INGEST working index; a trusted
		// curated reference is always admitted, so ingest can never starve it out.
		return SimEntry{}, false
	}
	e := SimEntry{ID: id, Sig: sig, Trust: trust, Label: label, Source: source}
	x.entries[id] = e
	return e, true
}

// AddReference adds a trusted (curated) reference signature.
func (x *SimIndex) AddReference(sig Signature, label, source string) (SimEntry, bool) {
	return x.add(sig, TrustCurated, label, source)
}

// AddObserved records a low-trust (ingest) signature seen during an analysis.
func (x *SimIndex) AddObserved(sig Signature, label, source string) (SimEntry, bool) {
	return x.add(sig, TrustIngest, label, source)
}

// Nearest returns entries whose similarity to sig is >= minSim, most similar
// first (ties broken by curated-over-ingest, then ID, for determinism). an empty
// query signature - or a NaN minSim - matches nothing. minSim is clamped to
// [0,1]; limit <= 0 means no limit.
func (x *SimIndex) Nearest(sig Signature, minSim float64, limit int) []Neighbor {
	if sig.Empty() || minSim != minSim { // NaN minSim matches nothing
		return nil
	}
	if minSim < 0 {
		minSim = 0
	}
	if minSim > 1 {
		minSim = 1
	}
	x.mu.Lock()
	entries := make([]SimEntry, 0, len(x.entries))
	for _, e := range x.entries {
		entries = append(entries, e)
	}
	x.mu.Unlock()

	var out []Neighbor
	for _, e := range entries {
		if s := Similarity(sig, e.Sig); s >= minSim {
			out = append(out, Neighbor{ID: e.ID, Trust: e.Trust, Sim: s, Label: e.Label, Source: e.Source})
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Sim != out[j].Sim {
			return out[i].Sim > out[j].Sim
		}
		if out[i].Trust != out[j].Trust {
			return out[i].Trust > out[j].Trust // curated first
		}
		return out[i].ID < out[j].ID
	})
	if limit > 0 && len(out) > limit {
		out = out[:limit]
	}
	return out
}

// Get returns the stored entry for a signature ID, so the spine can re-resolve a
// neighbor and recompute its score (verification).
func (x *SimIndex) Get(id string) (SimEntry, bool) {
	x.mu.Lock()
	defer x.mu.Unlock()
	e, ok := x.entries[id]
	return e, ok
}

// Len reports how many signatures are indexed.
func (x *SimIndex) Len() int {
	x.mu.Lock()
	defer x.mu.Unlock()
	return len(x.entries)
}
