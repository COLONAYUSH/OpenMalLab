package knowledge

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"
	"sync"
)

// tier L1 is the relational knowledge graph: the attribution moat. nodes are
// entities (samples, IOCs, families, techniques, campaigns, actors, rules) and
// edges are provenance-carrying relations, so the AI plane can ask "this C2
// belongs to which campaign, and what else has that actor used?" - context no
// single exact key expresses, compounded on-premise from the lab's own work.
//
// same discipline as L0/L0.5: nodes and edges carry a trust tier; a CURATED
// graph is the moat, an INGEST graph is auto-populated low-trust context; ingest
// can never overwrite curated (atomic poisoning guard); the capacity cap bounds
// only the ingest side so it can never starve curated out; traversal is bounded
// so a hostile, densely-linked graph cannot turn one query into unbounded work;
// and a traversal reports whether the ENTIRE path was curated, so an attribution
// resting partly on ingest edges is never mistaken for a trusted one. everything
// fails closed: unknown kind/relation, malformed key, or a cap hit is reported,
// never a silent pass.

// NodeKind is the type of a graph entity. unknown kinds are rejected.
type NodeKind string

const (
	NodeSample    NodeKind = "sample"
	NodeIOC       NodeKind = "ioc"
	NodeFamily    NodeKind = "family"
	NodeTechnique NodeKind = "technique"
	NodeCampaign  NodeKind = "campaign"
	NodeActor     NodeKind = "actor"
	NodeRule      NodeKind = "rule"
)

var knownNodeKinds = map[NodeKind]bool{
	NodeSample: true, NodeIOC: true, NodeFamily: true, NodeTechnique: true,
	NodeCampaign: true, NodeActor: true, NodeRule: true,
}

// RelKind is an edge relation. unknown relations are rejected (fail-closed).
type RelKind string

const (
	RelHasIOC       RelKind = "has-ioc"
	RelExhibits     RelKind = "exhibits"
	RelMemberOf     RelKind = "member-of"
	RelMatched      RelKind = "matched"
	RelSeenIn       RelKind = "seen-in"
	RelUses         RelKind = "uses"
	RelAttributedTo RelKind = "attributed-to"
	RelRelatedTo    RelKind = "related-to"
)

var knownRels = map[RelKind]bool{
	RelHasIOC: true, RelExhibits: true, RelMemberOf: true, RelMatched: true,
	RelSeenIn: true, RelUses: true, RelAttributedTo: true, RelRelatedTo: true,
}

// traversal bounds: a hostile graph cannot blow up a query.
const (
	defaultMaxDepth = 4
	defaultMaxNodes = 500
	// per-node out-degree cap for INGEST edges: bounds how big an attacker can
	// grow a hub, so a traversal's per-node work is bounded. curated edges are
	// operator-controlled and uncapped.
	maxIngestOutDegree = 4096
	// global edge budget per walk: a hard ceiling on edges examined, so even a
	// large (curated) graph cannot turn one query into unbounded work.
	maxTraversalEdges = 100_000
)

// Node is one graph entity. ID is derived from (kind, normalized key), so the
// same entity dedups and an edge is a stable content-bound handle to it.
type Node struct {
	ID     string
	Kind   NodeKind
	Key    string
	Label  string
	Attrs  map[string]string
	Trust  Trust
	Source string
}

func (n Node) clone() Node { n.Attrs = cloneAttrs(n.Attrs); return n }

// Edge is a provenance-carrying relation between two nodes, keyed by
// (from, rel, to) so a relation dedups and carries its own trust tier.
type Edge struct {
	ID     string
	From   string
	To     string
	Rel    RelKind
	Trust  Trust
	Source string
}

func nodeID(kind NodeKind, normKey string) string {
	sum := sha256.Sum256([]byte("n\x00" + string(kind) + "\x00" + normKey))
	return "kn_" + hex.EncodeToString(sum[:12])
}

func edgeID(from string, rel RelKind, to string) string {
	sum := sha256.Sum256([]byte("e\x00" + from + "\x00" + string(rel) + "\x00" + to))
	return "ke_" + hex.EncodeToString(sum[:12])
}

func normalizeNodeKey(kind NodeKind, key string) string {
	key = strings.TrimSpace(key)
	switch kind {
	case NodeFamily, NodeActor, NodeCampaign:
		return strings.ToLower(key)
	case NodeTechnique:
		return strings.ToUpper(key)
	default: // sample, ioc, rule: content is significant
		return key
	}
}

func validNodeKey(normKey string) bool {
	return normKey != "" && len(normKey) <= maxKeyLen && !hasControl(normKey)
}

// GraphStore persists nodes and edges. MergeNode/MergeEdge MUST run
// read-decide-write as one atomic critical section (a persistent backend uses a
// serializable transaction), and decide MUST NOT re-enter the store.
type GraphStore interface {
	GetNode(id string) (Node, bool)
	MergeNode(id string, decide func(existing Node, existed bool) (bool, Node)) (Node, error)
	MergeEdge(id string, decide func(existing Edge, existed bool) (bool, Edge)) (Edge, error)
	OutEdges(from string) []Edge
}

// Graph is the L1 relational layer over a GraphStore.
type Graph struct {
	store GraphStore
}

// NewGraph wraps a store as an L1 graph.
func NewGraph(store GraphStore) *Graph { return &Graph{store: store} }

func (g *Graph) putNode(kind NodeKind, key, label string, attrs map[string]string, source string, trust Trust, onlyIfAbsent bool) (Node, error) {
	if !knownNodeKinds[kind] {
		return Node{}, fmt.Errorf("knowledge: unknown node kind %q", kind)
	}
	norm := normalizeNodeKey(kind, key)
	if !validNodeKey(norm) {
		return Node{}, fmt.Errorf("knowledge: malformed key for node kind %q", kind)
	}
	if len(label) > maxLabelLen || len(source) > maxSourceLen || hasControl(label) || hasControl(source) {
		return Node{}, fmt.Errorf("knowledge: node label/source invalid")
	}
	if len(attrs) > maxAttrs {
		return Node{}, fmt.Errorf("knowledge: too many node attributes")
	}
	for k, v := range attrs {
		if len(k) > maxAttrLen || len(v) > maxAttrLen || hasControl(k) || hasControl(v) {
			return Node{}, fmt.Errorf("knowledge: node attribute invalid")
		}
	}
	incoming := Node{
		ID: nodeID(kind, norm), Kind: kind, Key: norm, Label: strings.TrimSpace(label),
		Attrs: cloneAttrs(attrs), Trust: trust, Source: source,
	}
	return g.store.MergeNode(incoming.ID, func(existing Node, existed bool) (bool, Node) {
		if existed {
			// never touch an existing node when only ensuring presence, and never
			// let ingest overwrite curated (the poisoning guard, atomic).
			if onlyIfAbsent || (existing.Trust == TrustCurated && trust == TrustIngest) {
				return false, existing
			}
		}
		return true, incoming
	})
}

// AddNode adds or upgrades a trusted (curated) node.
func (g *Graph) AddNode(kind NodeKind, key, label string, attrs map[string]string, source string) (Node, error) {
	return g.putNode(kind, key, label, attrs, source, TrustCurated, false)
}

// ObserveNode records a low-trust (ingest) node seen during an analysis.
func (g *Graph) ObserveNode(kind NodeKind, key, label, source string) (Node, error) {
	return g.putNode(kind, key, label, nil, source, TrustIngest, false)
}

// Node looks up an entity by (kind, key).
func (g *Graph) Node(kind NodeKind, key string) (Node, bool) {
	if !knownNodeKinds[kind] {
		return Node{}, false
	}
	norm := normalizeNodeKey(kind, key)
	if !validNodeKey(norm) {
		return Node{}, false
	}
	return g.store.GetNode(nodeID(kind, norm))
}

// link adds a relation, ensuring both endpoints exist (created at the edge's
// tier if absent, never mutating an existing node). the edge is atomic and
// poisoning-guarded: ingest can never overwrite a curated edge.
func (g *Graph) link(fromKind NodeKind, fromKey string, rel RelKind, toKind NodeKind, toKey, source string, trust Trust) (Edge, error) {
	if !knownRels[rel] {
		return Edge{}, fmt.Errorf("knowledge: unknown relation %q", rel)
	}
	if len(source) > maxSourceLen || hasControl(source) {
		return Edge{}, fmt.Errorf("knowledge: edge source invalid")
	}
	from, err := g.putNode(fromKind, fromKey, "", nil, source, trust, true)
	if err != nil {
		return Edge{}, fmt.Errorf("edge from-node: %w", err)
	}
	to, err := g.putNode(toKind, toKey, "", nil, source, trust, true)
	if err != nil {
		return Edge{}, fmt.Errorf("edge to-node: %w", err)
	}
	id := edgeID(from.ID, rel, to.ID)
	incoming := Edge{ID: id, From: from.ID, To: to.ID, Rel: rel, Trust: trust, Source: source}
	return g.store.MergeEdge(id, func(existing Edge, existed bool) (bool, Edge) {
		if existed && existing.Trust == TrustCurated && trust == TrustIngest {
			return false, existing
		}
		return true, incoming
	})
}

// Link adds a trusted (curated) relation between two entities.
func (g *Graph) Link(fromKind NodeKind, fromKey string, rel RelKind, toKind NodeKind, toKey, source string) (Edge, error) {
	return g.link(fromKind, fromKey, rel, toKind, toKey, source, TrustCurated)
}

// Observe adds a low-trust (ingest) relation seen during an analysis.
func (g *Graph) Observe(fromKind NodeKind, fromKey string, rel RelKind, toKind NodeKind, toKey, source string) (Edge, error) {
	return g.link(fromKind, fromKey, rel, toKind, toKey, source, TrustIngest)
}

// Reached is one node found by a traversal, with its distance and whether every
// edge on the shortest path to it was curated (so an ingest-tainted attribution
// is distinguishable from a trusted one).
type Reached struct {
	Node        Node
	Depth       int
	PathCurated bool
}

// TraversalResult is the outcome of Related. Truncated is true if a bound was
// hit before the reachable set was exhausted (fail-closed: report, never
// silently stop).
type TraversalResult struct {
	Reached   []Reached
	Truncated bool
}

// Related does a bounded breadth-first walk from (kind, key) following only the
// allowed relations (an empty rels slice allows all; a non-empty slice whose
// entries are all unknown reaches nothing), up to maxDepth hops and maxNodes
// reached nodes, within a global edge budget. it is deterministic (output
// ordered by depth then id) and cycle-safe; the start node is not in Reached.
// Truncated is set whenever a reachable node lies beyond ANY bound - never a
// silent stop. maxDepth/maxNodes <= 0 fall back to the defaults.
//
// PathCurated is computed from an INDEPENDENT curated-only walk, not from the
// shortest path, so an ingest shortcut can never evict or mask a genuinely
// curated attribution, and PathCurated=true always means a real fully-curated
// path exists within maxDepth.
func (g *Graph) Related(kind NodeKind, key string, rels []RelKind, maxDepth, maxNodes int) TraversalResult {
	start, ok := g.Node(kind, key)
	if !ok {
		return TraversalResult{}
	}
	if maxDepth <= 0 {
		maxDepth = defaultMaxDepth
	}
	if maxNodes <= 0 {
		maxNodes = defaultMaxNodes
	}
	filtered := len(rels) > 0
	allow := make(map[RelKind]bool, len(rels))
	for _, r := range rels {
		if knownRels[r] {
			allow[r] = true
		}
	}
	allDepth, tAll := g.walk(start.ID, allow, filtered, maxDepth, maxNodes, false)
	curated, _ := g.walk(start.ID, allow, filtered, maxDepth, maxNodes, true)

	res := TraversalResult{Truncated: tAll}
	ids := make([]string, 0, len(allDepth))
	for id := range allDepth {
		ids = append(ids, id)
	}
	sort.Slice(ids, func(i, j int) bool {
		if allDepth[ids[i]] != allDepth[ids[j]] {
			return allDepth[ids[i]] < allDepth[ids[j]]
		}
		return ids[i] < ids[j]
	})
	for _, id := range ids {
		n, ok := g.store.GetNode(id)
		if !ok {
			continue // dangling edge target: never fabricate a node
		}
		_, pc := curated[id]
		res.Reached = append(res.Reached, Reached{Node: n, Depth: allDepth[id], PathCurated: pc})
	}
	return res
}

// walk is one bounded BFS from startID (excluded), returning id->shortest-depth
// and whether a bound was hit. curatedOnly restricts to curated edges. it stops
// and reports Truncated on the maxNodes cap, the global edge budget, or a node
// reachable beyond the depth horizon.
func (g *Graph) walk(startID string, allow map[RelKind]bool, filtered bool, maxDepth, maxNodes int, curatedOnly bool) (map[string]int, bool) {
	depthOf := make(map[string]int)
	visited := map[string]bool{startID: true}
	type qi struct {
		id    string
		depth int
	}
	queue := []qi{{startID, 0}}
	edges := 0
	truncated := false
	for len(queue) > 0 {
		cur := queue[0]
		queue = queue[1:]
		out := g.store.OutEdges(cur.id)
		sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
		for _, e := range out {
			if filtered && !allow[e.Rel] {
				continue
			}
			if curatedOnly && e.Trust != TrustCurated {
				continue
			}
			if visited[e.To] {
				continue
			}
			edges++
			if edges > maxTraversalEdges {
				return depthOf, true
			}
			if cur.depth+1 > maxDepth {
				truncated = true // a reachable node lies beyond the depth horizon
				continue
			}
			if len(depthOf) >= maxNodes {
				return depthOf, true
			}
			visited[e.To] = true
			depthOf[e.To] = cur.depth + 1
			queue = append(queue, qi{e.To, cur.depth + 1})
		}
	}
	return depthOf, truncated
}

// MemGraph is an in-memory GraphStore, safe for concurrent use, with atomic
// merges, a capacity backstop that bounds only the ingest side, and an
// out-adjacency index for traversal.
type MemGraph struct {
	mu     sync.Mutex
	nodes  map[string]Node
	edges  map[string]Edge
	outAdj map[string]map[string]bool // fromID -> set of edge IDs
	max    int
}

// NewMemGraph returns an empty graph store with the default capacity.
func NewMemGraph() *MemGraph { return NewMemGraphWithCap(defaultMaxFacts) }

// NewMemGraphWithCap bounds ingest nodes+edges to max (<=0 means the default).
func NewMemGraphWithCap(max int) *MemGraph {
	if max <= 0 {
		max = defaultMaxFacts
	}
	return &MemGraph{
		nodes: make(map[string]Node), edges: make(map[string]Edge),
		outAdj: make(map[string]map[string]bool), max: max,
	}
}

func (m *MemGraph) GetNode(id string) (Node, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	n, ok := m.nodes[id]
	if !ok {
		return Node{}, false
	}
	return n.clone(), true
}

func (m *MemGraph) MergeNode(id string, decide func(Node, bool) (bool, Node)) (Node, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	existing, ok := m.nodes[id]
	write, result := decide(existing.clone(), ok)
	if !write {
		if ok {
			return existing.clone(), nil
		}
		return result.clone(), nil
	}
	if !ok && result.Trust == TrustIngest && len(m.nodes) >= m.max {
		return Node{}, fmt.Errorf("knowledge: graph at node capacity (%d)", m.max)
	}
	m.nodes[id] = result
	return result.clone(), nil
}

func (m *MemGraph) MergeEdge(id string, decide func(Edge, bool) (bool, Edge)) (Edge, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	existing, ok := m.edges[id]
	write, result := decide(existing, ok)
	if !write {
		if ok {
			return existing, nil
		}
		return result, nil
	}
	if !ok && result.Trust == TrustIngest {
		if len(m.edges) >= m.max {
			return Edge{}, fmt.Errorf("knowledge: graph at edge capacity (%d)", m.max)
		}
		// bound how big an attacker can grow a single hub via ingest, so a
		// traversal's per-node fan-out (and thus its per-query cost) is bounded.
		if len(m.outAdj[result.From]) >= maxIngestOutDegree {
			return Edge{}, fmt.Errorf("knowledge: node at ingest out-degree cap (%d)", maxIngestOutDegree)
		}
	}
	m.edges[id] = result
	if m.outAdj[result.From] == nil {
		m.outAdj[result.From] = make(map[string]bool)
	}
	m.outAdj[result.From][id] = true
	return result, nil
}

func (m *MemGraph) OutEdges(from string) []Edge {
	m.mu.Lock()
	defer m.mu.Unlock()
	ids := m.outAdj[from]
	out := make([]Edge, 0, len(ids))
	for id := range ids {
		if e, ok := m.edges[id]; ok {
			out = append(out, e)
		}
	}
	return out
}

// NodeCount / EdgeCount report the graph size.
func (m *MemGraph) NodeCount() int { m.mu.Lock(); defer m.mu.Unlock(); return len(m.nodes) }
func (m *MemGraph) EdgeCount() int { m.mu.Lock(); defer m.mu.Unlock(); return len(m.edges) }
