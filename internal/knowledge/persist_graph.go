package knowledge

// persistent L1. this resolves TODO(persist-graph, ASK STORE-1) from persist.go:
// the relational graph - the attribution moat - lived only in MemGraph, so every
// node and edge the lab had learned was gone after a restart. BoltGraph is the
// durable GraphStore twin of BoltStore, in the same no-cgo bbolt discipline: one
// embedded file with a "nodes" and an "edges" bucket, plus an
// "out:<fromID>:<edgeID>" adjacency index written in the SAME transaction as its
// edge, so the index can never drift from the edge set - a crash between the two
// is impossible by construction.
//
// the security-critical properties carry over from MemGraph unchanged, with the
// bbolt write transaction as the critical section: MergeNode/MergeEdge run
// read-decide-write atomically (bbolt permits exactly one write txn at a time,
// so the poisoning guard cannot be raced), curated always wins, ingest NEVER
// overwrites curated, the capacity cap bounds only the attacker-influenceable
// ingest tier (nodes and edges separately), and the per-node out-degree cap
// keeps a hostile hub from making traversals expensive - counted from the
// on-disk index inside the write txn itself, so it holds across restarts for
// free. everything fails closed: a corrupt row is a miss on the read path and a
// hard error on the write path, never garbage and never silently overwritten.
//
// NOT wired into the orchestrator yet. to switch it on, change
// services/mal-orchestrator/main.go line 157 (the ASK STORE-1 comment) from
//
//	a.graph = knowledge.NewGraph(knowledge.NewMemGraph())
//
// to open OpenGraphFromEnv() next to the OpenStoreFromEnv call at line 144,
// defer the returned close func, and point MAL_KNOWLEDGE_GRAPH_DB at a file
// path. keep that a DIFFERENT file from MAL_KNOWLEDGE_DB: bbolt is
// single-writer per file, so a second open of the same path just times out on
// the file lock.

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"sync"

	"go.etcd.io/bbolt"
)

// EnvKnowledgeGraphDB is the env var that, when set to a file path, selects the
// persistent BoltGraph over the default in-memory MemGraph.
const EnvKnowledgeGraphDB = "MAL_KNOWLEDGE_GRAPH_DB"

var (
	// graphNodesBucket holds every node, keyed by node ID, value = JSON(Node).
	graphNodesBucket = []byte("nodes")
	// graphEdgesBucket holds every edge, keyed by edge ID, value = JSON(Edge).
	graphEdgesBucket = []byte("edges")
	// graphAdjBucket is the out-adjacency index: key "out:<fromID>:<edgeID>",
	// value unused (the edge ID rides in the key). every entry is written in
	// the same transaction as its edge, so the index never drifts.
	graphAdjBucket = []byte("adj")
)

func adjPrefix(from string) []byte { return []byte("out:" + from + ":") }

func adjKey(from, edgeID string) []byte { return []byte("out:" + from + ":" + edgeID) }

// BoltGraph is a persistent GraphStore backed by one BoltDB file. safe for
// concurrent use; like MemGraph it runs each merge's read-decide-write as one
// atomic critical section - here a bbolt write transaction, of which bbolt runs
// exactly one at a time, so the tier/poisoning rule cannot be raced. learned
// nodes and edges outlive the process (reopen the same file and they, and the
// adjacency index a traversal depends on, are still there).
type BoltGraph struct {
	db        *bbolt.DB
	mu        sync.Mutex // serializes the live-count maintenance around each write txn
	max       int
	outDegCap int // per-node out-degree cap on new ingest edges
	nodeCount int // live counts, so the capacity checks are O(1), not bucket scans
	edgeCount int
}

// OpenBoltGraph opens (creating if absent) a persistent graph at path with the
// default capacity.
func OpenBoltGraph(path string) (*BoltGraph, error) {
	return OpenBoltGraphWithCap(path, defaultMaxFacts)
}

// OpenBoltGraphWithCap opens a persistent graph whose ingest tier is bounded to
// max nodes and max edges, counted separately (<=0 means the default). the caps
// only reject NEW ingest keys; a curated key and any update to an existing key
// are always admitted (the same rule MemGraph enforces).
func OpenBoltGraphWithCap(path string, max int) (*BoltGraph, error) {
	if max <= 0 {
		max = defaultMaxFacts
	}
	db, err := bbolt.Open(path, 0o600, &bbolt.Options{Timeout: openTimeout})
	if err != nil {
		return nil, fmt.Errorf("knowledge: open bolt graph: %w", err)
	}
	g := &BoltGraph{db: db, max: max, outDegCap: maxIngestOutDegree}
	// create the buckets and derive the starting counts once (a scan, but only at
	// open), so every later capacity check is O(1) rather than a bucket walk.
	if err := db.Update(func(tx *bbolt.Tx) error {
		nb, e := tx.CreateBucketIfNotExists(graphNodesBucket)
		if e != nil {
			return e
		}
		eb, e := tx.CreateBucketIfNotExists(graphEdgesBucket)
		if e != nil {
			return e
		}
		if _, e := tx.CreateBucketIfNotExists(graphAdjBucket); e != nil {
			return e
		}
		g.nodeCount = nb.Stats().KeyN
		g.edgeCount = eb.Stats().KeyN
		return nil
	}); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("knowledge: init bolt graph: %w", err)
	}
	return g, nil
}

// Close flushes and releases the underlying file. the graph must not be used after.
func (g *BoltGraph) Close() error { return g.db.Close() }

// GetNode returns the node at id, decoded into memory and therefore fully
// isolated from store state (its Attrs map is freshly allocated by the
// decoder). a missing key or a row that fails to decode (corruption) is a miss
// - fail closed, so a corrupt node can never anchor an attribution.
func (g *BoltGraph) GetNode(id string) (Node, bool) {
	var n Node
	found := false
	_ = g.db.View(func(tx *bbolt.Tx) error {
		b := tx.Bucket(graphNodesBucket)
		if b == nil {
			return nil
		}
		v := b.Get([]byte(id))
		if v == nil {
			return nil
		}
		if err := json.Unmarshal(v, &n); err != nil {
			return nil // corrupt row: treat as absent (fail closed)
		}
		found = true
		return nil
	})
	if !found {
		return Node{}, false
	}
	return n, true
}

// MergeNode runs read-decide-write inside one bbolt write transaction, so the
// tier/poisoning rule the Graph supplies is applied atomically and cannot be
// raced. decide MUST NOT call back into the store: it runs inside the txn, and
// re-entry would deadlock on the writer lock. the returned node is isolated;
// MergeNode errors at ingest capacity and on a corrupt existing row (never
// mis-decided against, never silently overwritten).
func (g *BoltGraph) MergeNode(id string, decide func(existing Node, existed bool) (bool, Node)) (Node, error) {
	g.mu.Lock()
	defer g.mu.Unlock()
	var out Node
	newKey := false
	err := g.db.Update(func(tx *bbolt.Tx) error {
		b := tx.Bucket(graphNodesBucket)
		existing, existed, derr := decodeGraphNode(b, id)
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
		// same rule as MemGraph: the cap bounds the attacker-influenceable ingest
		// tier only. a new CURATED node (human/CI-gated, authoritative) is ALWAYS
		// admitted, even over the cap, so an ingest flood can never starve a
		// genuinely curated node; an update to an existing key is never a new key,
		// so it is never capped.
		if !existed && result.Trust != TrustCurated && g.nodeCount >= g.max {
			return fmt.Errorf("knowledge: graph at node capacity (%d)", g.max)
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
		return Node{}, err
	}
	// bump the live count only after a fully committed insert of a NEW key, so a
	// rolled-back or failed-commit txn can never desync it.
	if newKey {
		g.nodeCount++
	}
	return out.clone(), nil
}

// MergeEdge is the edge twin of MergeNode, with two extra ingest bounds: the
// edge capacity and the per-node out-degree cap (how big an attacker can grow a
// single hub, so a traversal's per-node fan-out stays bounded). the adjacency
// index entry is written in the SAME transaction as the edge, so a crash can
// never leave an edge without its index entry or the reverse.
func (g *BoltGraph) MergeEdge(id string, decide func(existing Edge, existed bool) (bool, Edge)) (Edge, error) {
	g.mu.Lock()
	defer g.mu.Unlock()
	var out Edge
	newKey := false
	err := g.db.Update(func(tx *bbolt.Tx) error {
		b := tx.Bucket(graphEdgesBucket)
		existing, existed, derr := decodeGraphEdge(b, id)
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
		if !existed && result.Trust != TrustCurated {
			if g.edgeCount >= g.max {
				return fmt.Errorf("knowledge: graph at edge capacity (%d)", g.max)
			}
			// the degree is counted from the on-disk index inside this same txn,
			// so it is race-free and automatically correct after a reopen; the
			// scan stops at the cap, so rejecting a huge hub costs at most
			// outDegCap key steps.
			if g.outDegree(tx, result.From) >= g.outDegCap {
				return fmt.Errorf("knowledge: node at ingest out-degree cap (%d)", g.outDegCap)
			}
		}
		enc, merr := json.Marshal(result)
		if merr != nil {
			return merr
		}
		if perr := b.Put([]byte(id), enc); perr != nil {
			return perr
		}
		if perr := tx.Bucket(graphAdjBucket).Put(adjKey(result.From, id), nil); perr != nil {
			return perr
		}
		out = result
		newKey = !existed
		return nil
	})
	if err != nil {
		return Edge{}, err
	}
	if newKey {
		g.edgeCount++
	}
	return out, nil
}

// OutEdges returns every edge leaving from, freshly decoded and isolated. a row
// that fails to decode is skipped (fail closed: a corrupt edge is never returned
// as garbage), as is an index entry whose edge row is missing (never fabricate).
func (g *BoltGraph) OutEdges(from string) []Edge {
	var out []Edge
	_ = g.db.View(func(tx *bbolt.Tx) error {
		ab := tx.Bucket(graphAdjBucket)
		eb := tx.Bucket(graphEdgesBucket)
		if ab == nil || eb == nil {
			return nil
		}
		prefix := adjPrefix(from)
		c := ab.Cursor()
		for k, _ := c.Seek(prefix); k != nil && bytes.HasPrefix(k, prefix); k, _ = c.Next() {
			v := eb.Get(k[len(prefix):])
			if v == nil {
				continue
			}
			var e Edge
			if err := json.Unmarshal(v, &e); err != nil {
				continue
			}
			out = append(out, e)
		}
		return nil
	})
	return out
}

// outDegree counts the adjacency entries of from inside tx, stopping at the cap
// so the count's cost is bounded by the cap itself. like MemGraph, the degree
// counts edges of BOTH tiers; only a new ingest edge is ever rejected on it.
func (g *BoltGraph) outDegree(tx *bbolt.Tx, from string) int {
	prefix := adjPrefix(from)
	c := tx.Bucket(graphAdjBucket).Cursor()
	n := 0
	for k, _ := c.Seek(prefix); k != nil && bytes.HasPrefix(k, prefix); k, _ = c.Next() {
		n++
		if n >= g.outDegCap {
			break
		}
	}
	return n
}

// NodeCount / EdgeCount report the graph size.
func (g *BoltGraph) NodeCount() int { g.mu.Lock(); defer g.mu.Unlock(); return g.nodeCount }
func (g *BoltGraph) EdgeCount() int { g.mu.Lock(); defer g.mu.Unlock(); return g.edgeCount }

// decodeGraphNode reads and decodes the node at id from bucket b. a missing key
// yields (zero, false, nil); a corrupt row is an error, so a write txn fails
// closed rather than mis-deciding the tier rule against garbage or silently
// clobbering it.
func decodeGraphNode(b *bbolt.Bucket, id string) (Node, bool, error) {
	v := b.Get([]byte(id))
	if v == nil {
		return Node{}, false, nil
	}
	var n Node
	if err := json.Unmarshal(v, &n); err != nil {
		return Node{}, false, fmt.Errorf("knowledge: corrupt graph node %q: %w", id, err)
	}
	return n, true, nil
}

// decodeGraphEdge is the edge twin of decodeGraphNode, with the same fail-closed
// contract.
func decodeGraphEdge(b *bbolt.Bucket, id string) (Edge, bool, error) {
	v := b.Get([]byte(id))
	if v == nil {
		return Edge{}, false, nil
	}
	var e Edge
	if err := json.Unmarshal(v, &e); err != nil {
		return Edge{}, false, fmt.Errorf("knowledge: corrupt graph edge %q: %w", id, err)
	}
	return e, true, nil
}

// OpenGraphFromEnv selects the L1 graph backing from the environment: when
// MAL_KNOWLEDGE_GRAPH_DB names a path it returns the persistent BoltGraph
// (learned nodes and edges survive restarts); when unset it returns the
// in-memory MemGraph, so the default deployment stays zero-config with nothing
// on disk. the returned close func is never nil, even on a failed open; it
// releases the backend (a no-op for MemGraph) and should be deferred by the
// caller.
func OpenGraphFromEnv() (store GraphStore, closeFn func() error, err error) {
	noop := func() error { return nil }
	path := strings.TrimSpace(os.Getenv(EnvKnowledgeGraphDB))
	if path == "" {
		return NewMemGraph(), noop, nil
	}
	bg, err := OpenBoltGraph(path)
	if err != nil {
		return nil, noop, err
	}
	return bg, bg.Close, nil
}
