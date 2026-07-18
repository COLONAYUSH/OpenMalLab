// package knowledge is the deterministic memory the AI-analyst plane reasons
// against, and the source of truth the confidence gate verifies citations with.
// it is spine-side and trusted: the agents never write it directly.
//
// tier L0 (this file) is the exact-key registry. a fact is looked up by its
// (kind, key) and carries provenance and a trust tier. CURATED facts (human or
// CI gated) are the only ones that can satisfy a verdict-moving citation;
// INGEST facts (auto-populated from analyses) are retrievable context but never
// authority. that split is what bounds the feedback-loop poisoning surface the
// design calls out: an attacker who gets a fact ingested still cannot move a
// verdict with it, and ingest can never overwrite a curated fact.
//
// everything fails closed: an unknown kind, a malformed key, or a citation that
// does not resolve EXACTLY is a rejection, never a silent pass. the fact ID is
// derived from (kind, normalized key), so a citation is a stable handle the
// spine re-resolves, and an agent cannot cite fact A while claiming it is about
// B, nor mint an ID for a fact that is not actually stored.
//
// the tier merge is ATOMIC: the poisoning guard (ingest never overwrites
// curated) is applied inside the Store's own critical section, so it cannot be
// defeated by a concurrent first-time curate+ingest race - a defect a data-race
// detector would not even flag, because it is a semantic race, not a data race.
package knowledge

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"regexp"
	"strings"
	"sync"
)

// Kind is the type of an exact-key fact. only known kinds are accepted; an
// unknown kind is rejected, never stored.
type Kind string

const (
	KindFamily       Kind = "family"          // malware family name
	KindYaraRule     Kind = "yara-rule"       // a YARA rule identifier
	KindAttck        Kind = "attck"           // MITRE ATT&CK technique/tactic id
	KindMbc          Kind = "mbc"             // MBC behavior id
	KindC2           Kind = "c2"              // a known command-and-control indicator
	KindPacker       Kind = "packer"          // packer/crypter signature name
	KindMutex        Kind = "mutex"           // a named mutex
	KindImphash      Kind = "imphash"         // PE import hash (32 hex)
	KindAuthentihash Kind = "authentihash"    // PE authenticode hash (64 hex)
	KindSHA256       Kind = "sha256"          // a known sample hash (64 hex)
	KindCertThumb    Kind = "cert-thumbprint" // signing cert thumbprint (40 hex)
)

var knownKinds = map[Kind]bool{
	KindFamily: true, KindYaraRule: true, KindAttck: true, KindMbc: true,
	KindC2: true, KindPacker: true, KindMutex: true, KindImphash: true,
	KindAuthentihash: true, KindSHA256: true, KindCertThumb: true,
}

// Trust is the confidence tier of a fact. the ORDER matters: curated outranks
// ingest, so a merge never downgrades and ingest can never overwrite curated.
type Trust uint8

const (
	TrustIngest  Trust = iota // auto-populated from analyses; retrievable, never authority
	TrustCurated              // human/CI-gated; the only tier that satisfies a verdict-moving citation
)

func (t Trust) String() string {
	if t == TrustCurated {
		return "curated"
	}
	return "ingest"
}

// bounds so a hostile or absurd value cannot bloat the store. label and source
// are attacker-controllable on the ingest path, so they are capped too.
const (
	maxKeyLen    = 512
	maxLabelLen  = 1024
	maxSourceLen = 512
	maxAttrs     = 32
	maxAttrLen   = 1024
)

// defaultMaxFacts backstops the in-memory store against unbounded growth from an
// attacker ingesting many distinct keys. generous; a persistent backend bounds
// by its own quota instead.
const defaultMaxFacts = 2_000_000

// Fact is one exact-key entry. ID is derived deterministically from
// (Kind, normalized Key), so the same key always maps to the same fact (natural
// dedup) and a citation is a stable, content-bound handle.
type Fact struct {
	ID     string
	Kind   Kind
	Key    string // normalized
	Label  string
	Attrs  map[string]string
	Trust  Trust
	Source string // provenance: where this fact came from
}

// clone returns a copy whose Attrs map is independent of the receiver's, so a
// fact handed out of the store can never be mutated back into store state.
func (f Fact) clone() Fact {
	f.Attrs = cloneAttrs(f.Attrs)
	return f
}

// Citation is the result of verifying an agent's cited fact. fail-closed:
// Verified is true only when the cited ID exists AND is bound to the claimed
// (kind, key). OKForVerdict additionally requires the curated tier.
type Citation struct {
	Verified bool
	Fact     Fact
}

// OKForVerdict reports whether this citation may back a verdict-moving claim:
// verified AND curated. ingest-tier facts are context, never authority.
func (c Citation) OKForVerdict() bool {
	return c.Verified && c.Fact.Trust == TrustCurated
}

// Store persists facts by ID. an implementation must be safe for concurrent use,
// and Merge MUST run read-decide-write as one atomic critical section.
type Store interface {
	// Get returns the fact at id. the returned fact must be isolated from store
	// state (its Attrs map must not alias the stored one).
	Get(id string) (Fact, bool)
	// Merge atomically reads the fact at id, calls decide with a copy of it, and
	// if decide returns write=true stores the returned fact. the whole
	// read-decide-write MUST be one critical section, so the tier/poisoning rule
	// the Registry supplies cannot be raced: a persistent backend must use a
	// SELECT ... FOR UPDATE or serializable transaction, never a naive
	// read-then-write, which would silently reintroduce the poisoning race that
	// no data-race detector can see. decide MUST NOT call back into the store
	// (it runs under the store's lock; re-entry would deadlock). the returned
	// fact is isolated (its Attrs do not alias store state); Merge may error
	// (e.g. at capacity).
	Merge(id string, decide func(existing Fact, existed bool) (write bool, result Fact)) (Fact, error)
}

// factID binds a fact to its (kind, normalized key). deterministic and
// fixed-length, so citations are stable and an agent cannot mint an ID that
// resolves to a fact it never legitimately retrieved (existence is still
// checked on verify). the NUL separator is injective: no Kind contains a NUL.
func factID(kind Kind, normKey string) string {
	sum := sha256.Sum256([]byte(string(kind) + "\x00" + normKey))
	return "kf_" + hex.EncodeToString(sum[:12])
}

var (
	reHex32 = regexp.MustCompile(`^[0-9a-f]{32}$`)
	reHex40 = regexp.MustCompile(`^[0-9a-f]{40}$`)
	reHex64 = regexp.MustCompile(`^[0-9a-f]{64}$`)
	reAttck = regexp.MustCompile(`^TA?\d{4}(\.\d{3})?$`)
	reMbc   = regexp.MustCompile(`^[A-Z]{1,2}\d{4}(\.\d{3})?$`)
)

// normalizeKey canonicalizes a key per kind so lookups and citations are
// consistent regardless of how a caller spelled it.
func normalizeKey(kind Kind, key string) string {
	key = strings.TrimSpace(key)
	switch kind {
	case KindImphash, KindAuthentihash, KindSHA256, KindCertThumb:
		return strings.ToLower(strings.ReplaceAll(key, ":", ""))
	case KindAttck, KindMbc:
		return strings.ToUpper(key)
	case KindFamily, KindPacker:
		return strings.ToLower(key)
	default:
		// c2, mutex, yara-rule: content is significant; only trimmed.
		return key
	}
}

// hasControl reports whether s contains a C0 control, DEL, or a C1 control
// (U+0080-U+009F). keys never legitimately carry these (a real rule id / C2 /
// mutex is printable), so we reject them to keep hostile bytes (NUL, newline,
// ANSI/CSI) out of the store.
func hasControl(s string) bool {
	for _, r := range s {
		if r < 0x20 || r == 0x7f || (r >= 0x80 && r <= 0x9f) {
			return true
		}
	}
	return false
}

// validKey enforces a per-kind format, so garbage never enters the registry and
// hashes cannot be cited in a shape that could not have been produced by a real
// engine.
func validKey(kind Kind, normKey string) bool {
	if normKey == "" || len(normKey) > maxKeyLen || hasControl(normKey) {
		return false
	}
	switch kind {
	case KindImphash:
		return reHex32.MatchString(normKey)
	case KindAuthentihash, KindSHA256:
		return reHex64.MatchString(normKey)
	case KindCertThumb:
		return reHex40.MatchString(normKey)
	case KindAttck:
		return reAttck.MatchString(normKey)
	case KindMbc:
		return reMbc.MatchString(normKey)
	default:
		return true // family/packer/c2/mutex/yara-rule: any printable, bounded key
	}
}

// Registry is the L0 exact-key knowledge layer over a Store.
type Registry struct {
	store Store
}

// NewRegistry wraps a Store as an L0 registry.
func NewRegistry(store Store) *Registry { return &Registry{store: store} }

// Curate adds or upgrades a trusted fact. curated always wins a merge, so a
// re-curation refreshes label/attrs/source and an ingest fact is promoted.
func (r *Registry) Curate(kind Kind, key, label string, attrs map[string]string, source string) (Fact, error) {
	return r.put(kind, key, label, attrs, source, TrustCurated)
}

// Ingest records a low-trust fact observed during an analysis. it NEVER
// modifies an existing curated fact (the poisoning vector): an ingest write
// against a curated key returns the curated fact unchanged. the guard is
// evaluated atomically inside the Store, so it holds under concurrency.
func (r *Registry) Ingest(kind Kind, key, label, source string) (Fact, error) {
	return r.put(kind, key, label, nil, source, TrustIngest)
}

func (r *Registry) put(kind Kind, key, label string, attrs map[string]string, source string, trust Trust) (Fact, error) {
	if !knownKinds[kind] {
		return Fact{}, fmt.Errorf("knowledge: unknown kind %q", kind)
	}
	norm := normalizeKey(kind, key)
	if !validKey(kind, norm) {
		return Fact{}, fmt.Errorf("knowledge: malformed key for kind %q", kind)
	}
	if len(label) > maxLabelLen {
		return Fact{}, fmt.Errorf("knowledge: label exceeds %d bytes", maxLabelLen)
	}
	if len(source) > maxSourceLen {
		return Fact{}, fmt.Errorf("knowledge: source exceeds %d bytes", maxSourceLen)
	}
	if len(attrs) > maxAttrs {
		return Fact{}, fmt.Errorf("knowledge: too many attributes (%d > %d)", len(attrs), maxAttrs)
	}
	for k, v := range attrs {
		if len(k) > maxAttrLen || len(v) > maxAttrLen {
			return Fact{}, fmt.Errorf("knowledge: attribute too long")
		}
	}
	incoming := Fact{
		ID: factID(kind, norm), Kind: kind, Key: norm, Label: strings.TrimSpace(label),
		Attrs: cloneAttrs(attrs), Trust: trust, Source: source,
	}
	// the tier rule is applied atomically inside the store: ingest never wins
	// over an existing curated fact, no matter how the calls interleave.
	return r.store.Merge(incoming.ID, func(existing Fact, existed bool) (bool, Fact) {
		if existed && existing.Trust == TrustCurated && trust == TrustIngest {
			return false, existing
		}
		return true, incoming
	})
}

// Lookup returns the fact for an exact (kind, key), for retrieval. it returns
// whichever tier is stored; the caller decides how much to trust it.
func (r *Registry) Lookup(kind Kind, key string) (Fact, bool) {
	if !knownKinds[kind] {
		return Fact{}, false
	}
	norm := normalizeKey(kind, key)
	if !validKey(kind, norm) {
		return Fact{}, false
	}
	return r.store.Get(factID(kind, norm))
}

// VerifyCitation is the linchpin of the anti-hallucination gate: it confirms an
// agent's cited fact ID exists AND is bound to the (kind, key) the agent claims
// it is about. so an agent cannot cite fact A while asserting it supports a
// statement about B, and cannot invent an ID for a fact that is not stored.
// fail-closed: anything that does not resolve exactly is unverified.
func (r *Registry) VerifyCitation(citedID string, kind Kind, key string) Citation {
	if citedID == "" || !knownKinds[kind] {
		return Citation{}
	}
	norm := normalizeKey(kind, key)
	if !validKey(kind, norm) {
		return Citation{}
	}
	// the claimed (kind, key) must itself produce the cited ID: this binds the
	// handle to its content, so a mismatched claim cannot verify.
	if factID(kind, norm) != citedID {
		return Citation{}
	}
	f, ok := r.store.Get(citedID)
	if !ok {
		return Citation{} // no such fact: fail closed
	}
	// defense in depth: the Store is pluggable, so do not blindly trust that a
	// stored fact's own (kind, key) matches its ID. a buggy or corrupt backend
	// that returned a mislabeled fact must not be able to certify a citation.
	if f.Kind != kind || f.Key != norm {
		return Citation{}
	}
	return Citation{Verified: true, Fact: f}
}

// Seed bulk-curates facts, e.g. pre-loading the bundled public corpora (ATT&CK /
// MBC ids, capa rule metadata, known family names) so L0 is not empty on day
// one. it stops and returns the count curated so far on the first bad fact.
func (r *Registry) Seed(facts []Fact) (int, error) {
	n := 0
	for _, f := range facts {
		if _, err := r.Curate(f.Kind, f.Key, f.Label, f.Attrs, f.Source); err != nil {
			return n, err
		}
		n++
	}
	return n, nil
}

func cloneAttrs(a map[string]string) map[string]string {
	if len(a) == 0 {
		return nil
	}
	c := make(map[string]string, len(a))
	for k, v := range a {
		c[k] = v
	}
	return c
}

// MemStore is an in-memory Store, safe for concurrent use, with an atomic Merge
// and a capacity backstop. good for tests and small deployments; a persistent
// backend implements the same interface (Merge as a SELECT-FOR-UPDATE upsert).
type MemStore struct {
	mu    sync.Mutex
	facts map[string]Fact
	max   int
}

// NewMemStore returns an empty in-memory store with the default capacity.
func NewMemStore() *MemStore { return NewMemStoreWithCap(defaultMaxFacts) }

// NewMemStoreWithCap returns an empty store bounded to max facts (<=0 means the
// default). the cap only rejects NEW keys, never updates to existing ones.
func NewMemStoreWithCap(max int) *MemStore {
	if max <= 0 {
		max = defaultMaxFacts
	}
	return &MemStore{facts: make(map[string]Fact), max: max}
}

func (m *MemStore) Get(id string) (Fact, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	f, ok := m.facts[id]
	if !ok {
		return Fact{}, false
	}
	return f.clone(), true
}

func (m *MemStore) Merge(id string, decide func(existing Fact, existed bool) (bool, Fact)) (Fact, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	existing, ok := m.facts[id]
	write, result := decide(existing.clone(), ok)
	if !write {
		if ok {
			return existing.clone(), nil
		}
		return result.clone(), nil
	}
	if !ok && len(m.facts) >= m.max {
		return Fact{}, fmt.Errorf("knowledge: store at capacity (%d facts)", m.max)
	}
	m.facts[id] = result
	return result.clone(), nil
}

// Len reports how many facts are stored.
func (m *MemStore) Len() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.facts)
}
