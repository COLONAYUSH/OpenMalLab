package aiplane

import (
	"strings"
	"testing"
)

// TestDefangStripsInvisibleAndCombining covers finding #17: defang must also drop
// default-ignorable code points (invisible fillers used to spoof filenames) and
// combining marks (the zalgo carrier), not only C0/C1/Cf/variation-selectors.
func TestDefangStripsInvisibleAndCombining(t *testing.T) {
	cases := []struct {
		name string
		r    rune
	}{
		{"hangul-filler", 0x3164},
		{"hangul-choseong-filler", 0x115F},
		{"halfwidth-hangul-filler", 0xFFA0},
		{"combining-acute", 0x0301},
		{"combining-enclosing-circle", 0x20DD},
		{"variation-selector", 0xFE0F},
		{"zero-width-space", 0x200B},
	}
	for _, c := range cases {
		in := "svchost" + string(c.r) + ".exe"
		if out := defang(in); strings.ContainsRune(out, c.r) {
			t.Fatalf("%s (U+%04X) survived defang: %q", c.name, c.r, out)
		}
	}
	// a zalgo string collapses to its base text.
	zalgo := "n" + strings.Repeat(string(rune(0x0301)), 8) + "et"
	if got := defang(zalgo); got != "net" {
		t.Fatalf("zalgo not neutralized: %q", got)
	}
}

// TestDefangProtocolRelativeURL covers finding #17: a protocol-relative //host
// carries no "://" and so escaped the scheme defang, yet still renders live.
func TestDefangProtocolRelativeURL(t *testing.T) {
	for in, want := range map[string]string{
		"//evil.com/p":       "[//]evil.com/p",       // bare protocol-relative
		"see //evil.com now": "see [//]evil.com now", // at a word boundary
		"http://x/y":         "http[://]x/y",         // scheme form still bracketed, unaffected
		"a path x//y here":   "a path x//y here",     // mid-token // (no boundary) left alone
	} {
		if got := defang(in); got != want {
			t.Fatalf("defang(%q) = %q, want %q", in, got, want)
		}
	}
}

// TestLedgerSealedHashIsTheStableAnchor covers finding #22: a caller must record
// the SEALED hash Append returned, not a later Ledger().Head() read - because a
// concurrent append advances the head, so a re-read would misattribute a different
// entry's hash as this one's anchor.
func TestLedgerSealedHashIsTheStableAnchor(t *testing.T) {
	l := NewLedger()
	h1 := l.Append(Handshake{Provider: "a", Outcome: "gated"})
	h2 := l.Append(Handshake{Provider: "b", Outcome: "gated"}) // a later (e.g. concurrent) append

	if h1.Hash == "" || h2.Hash == "" || h1.Hash == h2.Hash {
		t.Fatalf("each entry must seal a distinct, non-empty hash: %q vs %q", h1.Hash, h2.Hash)
	}
	// the head now points at h2 - so a Head() read after h2 lands would record h2's
	// hash as h1's anchor. h1.Hash (the sealed return) is immune to that race.
	if l.Head() == h1.Hash {
		t.Fatal("head equals h1 after a 2nd append - a Head() re-read cannot be h1's stable anchor")
	}
	if l.Head() != h2.Hash {
		t.Fatalf("head must equal the last sealed hash: %q != %q", l.Head(), h2.Hash)
	}
}
