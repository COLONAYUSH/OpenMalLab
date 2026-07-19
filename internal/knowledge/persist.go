package knowledge

// persistent L0. the in-memory MemStore forgets every curated fact on exit, so a
// freshly rebooted spine could ground nothing until it is re-seeded. BoltStore is
// an embedded, single-file, pure-Go Store (go.etcd.io/bbolt: no cgo) so curated
// facts survive a restart - reopen the same file and they are still there.
//
// the security-critical properties are preserved EXACTLY as MemStore holds them,
// only now the critical section is a bbolt read-write transaction instead of a
// mutex: Merge runs read-decide-write atomically (bbolt permits exactly one write
// txn at a time, so the poisoning guard cannot be raced), curated always wins,
// ingest NEVER overwrites a curated fact, and the trust-aware capacity cap admits
// curated unconditionally while bounding only the attacker-influenceable ingest
// tier. everything fails closed: a corrupt row never certifies and never gets
// silently overwritten against garbage.
//
// TODO(persist-graph, ASK STORE-1): only L0 (this Store) is durable. the L1 Graph
// still runs on the in-memory MemGraph, so learned nodes/edges are lost on restart.
// a BoltGraph backing GraphStore (GetNode/MergeNode/MergeEdge/OutEdges) would mirror
// this file: a "nodes" and an "edges" bucket plus an "out:<fromID>" adjacency index
// maintained in the SAME txn as each edge write, the same atomic poisoning guard on
// MergeNode/MergeEdge, and the ingest-only capacity + out-degree caps. that is a
// larger change (the adjacency index and two guards), so it is deferred here rather
// than half-built - MemGraph stays the only GraphStore for now.

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"sync"
	"time"

	"go.etcd.io/bbolt"
)

// EnvKnowledgeDB is the env var that, when set to a file path, selects the
// persistent BoltStore over the default in-memory MemStore.
const EnvKnowledgeDB = "MAL_KNOWLEDGE_DB"

// factsBucket holds every fact, keyed by its derived ID, value = JSON(Fact).
var factsBucket = []byte("facts")

// openTimeout bounds how long Open waits for the single-writer file lock, so a
// double-open (or a stale lock) fails fast instead of hanging the process.
const openTimeout = 5 * time.Second

// BoltStore is a persistent Store backed by one BoltDB file. safe for concurrent
// use; like MemStore it runs Merge's read-decide-write as one atomic critical
// section - here a bbolt write transaction, of which bbolt runs exactly one at a
// time, so the tier/poisoning rule cannot be raced. curated facts outlive the
// process (reopen the same file and they are still there).
type BoltStore struct {
	db    *bbolt.DB
	mu    sync.Mutex // serializes the live-count maintenance around each write txn
	max   int
	count int // live fact count, so the capacity check is O(1), not a bucket scan
}

// OpenBoltStore opens (creating if absent) a persistent store at path with the
// default capacity.
func OpenBoltStore(path string) (*BoltStore, error) {
	return OpenBoltStoreWithCap(path, defaultMaxFacts)
}

// OpenBoltStoreWithCap opens a persistent store bounded to max facts (<=0 means
// the default). the cap only rejects NEW ingest keys; a curated key and any update
// to an existing key are always admitted (the same rule MemStore enforces).
func OpenBoltStoreWithCap(path string, max int) (*BoltStore, error) {
	if max <= 0 {
		max = defaultMaxFacts
	}
	db, err := bbolt.Open(path, 0o600, &bbolt.Options{Timeout: openTimeout})
	if err != nil {
		return nil, fmt.Errorf("knowledge: open bolt store: %w", err)
	}
	s := &BoltStore{db: db, max: max}
	// create the bucket and derive the starting count once (a full scan, but only
	// at open), so every later capacity check is O(1) rather than a bucket walk.
	if err := db.Update(func(tx *bbolt.Tx) error {
		b, e := tx.CreateBucketIfNotExists(factsBucket)
		if e != nil {
			return e
		}
		s.count = b.Stats().KeyN
		return nil
	}); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("knowledge: init bolt store: %w", err)
	}
	return s, nil
}

// Close flushes and releases the underlying file. the store must not be used after.
func (s *BoltStore) Close() error { return s.db.Close() }

// Get returns the fact at id, decoded into memory and therefore fully isolated
// from store state (its Attrs map is freshly allocated by the decoder). a missing
// key or a row that fails to decode (corruption) is a miss - fail closed, so a
// corrupt fact can never certify a citation.
func (s *BoltStore) Get(id string) (Fact, bool) {
	var f Fact
	found := false
	_ = s.db.View(func(tx *bbolt.Tx) error {
		b := tx.Bucket(factsBucket)
		if b == nil {
			return nil
		}
		v := b.Get([]byte(id))
		if v == nil {
			return nil
		}
		if err := json.Unmarshal(v, &f); err != nil {
			return nil // corrupt row: treat as absent (fail closed)
		}
		found = true
		return nil
	})
	if !found {
		return Fact{}, false
	}
	return f, true
}

// Merge runs read-decide-write inside one bbolt write transaction, so the
// tier/poisoning rule the Registry supplies is applied atomically and cannot be
// raced (bbolt permits only one write txn at a time). decide MUST NOT call back
// into the store: it runs inside the txn, and re-entry would deadlock on the writer
// lock. the returned fact is isolated; Merge errors at ingest capacity.
func (s *BoltStore) Merge(id string, decide func(existing Fact, existed bool) (bool, Fact)) (Fact, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out Fact
	newKey := false
	err := s.db.Update(func(tx *bbolt.Tx) error {
		b := tx.Bucket(factsBucket)
		existing, existed, derr := decodeFact(b, id)
		if derr != nil {
			return derr
		}
		write, result := decide(existing, existed)
		if !write {
			if existed {
				out = existing
			} else {
				out = result
			}
			return nil
		}
		// same rule as MemStore: the cap bounds the attacker-influenceable ingest
		// tier only. a new CURATED key (human/CI-gated, authoritative) is ALWAYS
		// admitted, even over the cap, so an ingest flood can never starve a genuinely
		// curated fact; an update to an existing key is never a new key, so it is
		// never capped.
		if !existed && result.Trust != TrustCurated && s.count >= s.max {
			return fmt.Errorf("knowledge: store at ingest capacity (%d facts)", s.max)
		}
		enc, merr := json.Marshal(result)
		if merr != nil {
			return merr
		}
		if perr := b.Put([]byte(id), enc); perr != nil {
			return perr
		}
		out = result
		newKey = !existed
		return nil
	})
	if err != nil {
		return Fact{}, err
	}
	// bump the live count only after a fully committed insert of a NEW key, so a
	// rolled-back or failed-commit txn can never desync it.
	if newKey {
		s.count++
	}
	return out.clone(), nil
}

// Len reports how many facts are stored.
func (s *BoltStore) Len() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.count
}

// decodeFact reads and decodes the fact at id from bucket b. a missing key yields
// (zero, false, nil); a corrupt row is an error, so a write txn fails closed rather
// than mis-deciding the tier rule against garbage or silently clobbering it.
func decodeFact(b *bbolt.Bucket, id string) (Fact, bool, error) {
	v := b.Get([]byte(id))
	if v == nil {
		return Fact{}, false, nil
	}
	var f Fact
	if err := json.Unmarshal(v, &f); err != nil {
		return Fact{}, false, fmt.Errorf("knowledge: corrupt fact %q: %w", id, err)
	}
	return f, true, nil
}

// OpenStoreFromEnv selects the L0 backing store from the environment: when
// MAL_KNOWLEDGE_DB names a path it returns the persistent BoltStore (curated facts
// survive restarts); when unset it returns the in-memory MemStore, so the default
// deployment stays zero-config with nothing on disk. the returned close func
// releases the backend (a no-op for MemStore) and should be deferred by the caller.
func OpenStoreFromEnv() (store Store, closeFn func() error, err error) {
	noop := func() error { return nil }
	path := strings.TrimSpace(os.Getenv(EnvKnowledgeDB))
	if path == "" {
		return NewMemStore(), noop, nil
	}
	bs, err := OpenBoltStore(path)
	if err != nil {
		return nil, noop, err
	}
	return bs, bs.Close, nil
}
