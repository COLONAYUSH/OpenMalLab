package aiplane

// the handshake ledger is a tamper-evident record of every AI-plane interaction.
// each entry is hash-chained to the one before it, so the audit trail cannot be
// silently edited after the fact: change any field of any past handshake and its
// hash - and every hash after it - stops matching. this is what lets an operator
// trust the record of what the untrusted model was shown and what the gate did
// with its answer, long after the fact, even if the store beneath is not itself
// trusted.

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
	PrevHash     string `json:"prev_hash"`
	Hash         string `json:"hash"` // sha256 over this entry with Hash blanked
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
	b, _ := json.Marshal(h) // Handshake is all scalars: Marshal cannot fail
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
