package aiplane

// the handshake ledger is a tamper-evident record of every AI-plane interaction.
// each entry is hash-chained to the one before it: change any field of any past
// handshake and its hash - and every hash after it - stops matching, so in-memory
// Verify() catches accidental corruption and any edit that is not also re-sealed.
//
// the chain is UNKEYED, so on its own it cannot defend a PERSISTED ledger against
// an actor with write access to the backing store, who could tail-truncate it or
// re-seal a wholly-rewritten chain and still pass Verify(). a persistence layer
// MUST therefore reload through VerifyAgainst(count, head), binding the check to
// an out-of-band anchor (the entry count and head hash, recorded where the store
// writer cannot forge them - the durable Temporal history, or an operator
// signature). that is what lets an operator trust the record long after the fact.

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sync"
)

// Handshake is one recorded AI-plane interaction. hashes bind the entry to what
// the model was shown (EvidenceHash) and what it returned (ProposalHash) without
// storing the raw, possibly-hostile content in the ledger itself.
type Handshake struct {
	Seq          int    `json:"seq"`
	SubmissionID string `json:"submission_id"`
	Provider     string `json:"provider"`
	EvidenceHash string `json:"evidence_hash"`           // sha256 of the evidence projection
	ProposalHash string `json:"proposal_hash,omitempty"` // sha256 of the raw model bytes ("" if none)
	Outcome      string `json:"outcome"`                 // gated | rejected | provider-error
	NeedsHuman   bool   `json:"needs_human"`
	Accepted     int    `json:"accepted"` // count of accepted (autonomous) hypotheses
	// retrieval provenance (design sec 09): which fact IDs the spine re-resolved and
	// verified, and which tiers answered - so the audit trail records not just the
	// outcome but the grounding it rested on.
	CitedFactIDs   []string `json:"cited_fact_ids,omitempty"`
	RetrievalTiers []string `json:"retrieval_tiers,omitempty"`
	PrevHash       string   `json:"prev_hash"`
	Hash           string   `json:"hash"` // sha256 over this entry with Hash blanked
}

// Ledger is an append-only, hash-chained log of handshakes, safe for concurrent
// use. it is deliberately time-free: the durable spine (Temporal history) owns
// the timestamps, and leaving wall-clock out keeps the chain deterministic and
// its hashes reproducible for verification.
type Ledger struct {
	mu       sync.Mutex
	entries  []Handshake
	lastHash string
}

// NewLedger returns an empty ledger. the genesis PrevHash is the empty string.
func NewLedger() *Ledger { return &Ledger{} }

// Append seals a handshake into the chain: it stamps the sequence number and the
// previous hash, computes this entry's hash, stores it, and returns the sealed
// copy. callers pass a Handshake with the content fields set; Seq/PrevHash/Hash
// are assigned here and any values they set for those are overwritten.
func (l *Ledger) Append(h Handshake) Handshake {
	l.mu.Lock()
	defer l.mu.Unlock()
	h.Seq = len(l.entries)
	h.PrevHash = l.lastHash
	h.Hash = hashHandshake(h)
	l.entries = append(l.entries, h)
	l.lastHash = h.Hash
	return h
}

// Verify walks the whole chain and confirms it has not been tampered with: every
// entry's stored hash must equal its recomputed hash, every PrevHash must equal
// the prior entry's hash, and sequence numbers must be dense and ascending.
func (l *Ledger) Verify() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	prev := ""
	for i, h := range l.entries {
		if h.Seq != i {
			return fmt.Errorf("ledger: entry %d has seq %d", i, h.Seq)
		}
		if h.PrevHash != prev {
			return fmt.Errorf("ledger: entry %d prev-hash breaks the chain", i)
		}
		want := hashHandshake(h)
		if h.Hash != want {
			return fmt.Errorf("ledger: entry %d hash mismatch (tampered)", i)
		}
		prev = h.Hash
	}
	// the recorded head must equal the last entry's hash: catches a partial edit
	// that truncates entries without also rewriting the head.
	if prev != l.lastHash {
		return fmt.Errorf("ledger: head does not match the last entry (chain truncated or head forged)")
	}
	return nil
}

// VerifyAgainst is the verification a persistence layer MUST use after reloading
// the ledger from an untrusted store. plain Verify proves only internal
// consistency, which an unkeyed chain a store-writer fully controls can fake by
// tail-truncating or re-sealing. binding the check to an out-of-band anchor - the
// entry count and head hash, recorded where the store writer cannot forge them -
// closes that: a truncated or rewritten chain no longer matches the anchor.
func (l *Ledger) VerifyAgainst(expectedCount int, expectedHead string) error {
	if err := l.Verify(); err != nil {
		return err
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if len(l.entries) != expectedCount {
		return fmt.Errorf("ledger: entry count %d != anchored %d (truncated or extended)", len(l.entries), expectedCount)
	}
	if l.lastHash != expectedHead {
		return fmt.Errorf("ledger: head %q != anchored head (tampered)", l.lastHash)
	}
	return nil
}

// Entries returns a copy of the chain, safe for the caller to keep.
func (l *Ledger) Entries() []Handshake {
	l.mu.Lock()
	defer l.mu.Unlock()
	return append([]Handshake(nil), l.entries...)
}

// Head returns the hash of the most recent entry (empty for an empty ledger).
func (l *Ledger) Head() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.lastHash
}

// hashHandshake computes the entry hash over the whole struct with Hash blanked,
// so Seq and PrevHash are bound into it (which is what chains the entries).
func hashHandshake(h Handshake) string {
	h.Hash = ""
	b, _ := json.Marshal(h) // Handshake holds only strings/ints/bools/string-slices: Marshal cannot fail
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// hashBytes returns the hex sha256 of raw bytes (used for the proposal hash).
func hashBytes(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// hashJSON returns the hex sha256 of a value's JSON encoding (used for the
// evidence hash). a marshal error yields "" - the caller still ledgers the entry.
func hashJSON(v any) string {
	b, err := json.Marshal(v)
	if err != nil {
		return ""
	}
	return hashBytes(b)
}
