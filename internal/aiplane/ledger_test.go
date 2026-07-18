package aiplane

import "testing"

func TestLedgerChainAndVerify(t *testing.T) {
	l := NewLedger()
	if l.Head() != "" {
		t.Fatal("empty ledger head should be empty")
	}
	a := l.Append(Handshake{SubmissionID: "s1", Outcome: "gated"})
	b := l.Append(Handshake{SubmissionID: "s2", Outcome: "rejected"})
	c := l.Append(Handshake{SubmissionID: "s3", Outcome: "provider-error"})

	if a.Seq != 0 || b.Seq != 1 || c.Seq != 2 {
		t.Fatalf("sequence not dense/ascending: %d %d %d", a.Seq, b.Seq, c.Seq)
	}
	if a.PrevHash != "" || b.PrevHash != a.Hash || c.PrevHash != b.Hash {
		t.Fatal("prev-hash chain not linked")
	}
	if l.Head() != c.Hash {
		t.Fatal("head is not the last hash")
	}
	if err := l.Verify(); err != nil {
		t.Fatalf("clean chain must verify: %v", err)
	}
}

func TestLedgerDetectsTampering(t *testing.T) {
	l := NewLedger()
	l.Append(Handshake{SubmissionID: "s1", Outcome: "gated"})
	l.Append(Handshake{SubmissionID: "s2", Outcome: "gated", NeedsHuman: false})
	l.Append(Handshake{SubmissionID: "s3", Outcome: "gated"})
	if err := l.Verify(); err != nil {
		t.Fatalf("baseline should verify: %v", err)
	}
	// edit a past entry's content in place: its recomputed hash no longer matches.
	l.entries[1].NeedsHuman = true
	if err := l.Verify(); err == nil {
		t.Fatal("content tampering must be detected")
	}
}

func TestLedgerDetectsChainBreak(t *testing.T) {
	l := NewLedger()
	l.Append(Handshake{SubmissionID: "s1"})
	l.Append(Handshake{SubmissionID: "s2"})
	// break the back-link without touching content hashes.
	l.entries[1].PrevHash = "deadbeef"
	if err := l.Verify(); err == nil {
		t.Fatal("prev-hash break must be detected")
	}
}
