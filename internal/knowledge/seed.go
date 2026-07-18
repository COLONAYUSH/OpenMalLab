package knowledge

// L0 pre-seeding (design sec 08). the exact-key registry must not be empty on day
// one, or the confidence gate can ground nothing and every hypothesis escalates.
// this loads a bundled, curated starter corpus (ATT&CK techniques + tactics,
// common packer signatures, well-known family names) so citations resolve
// immediately. SeedJSON is the extensible path: point it at the vendored capa/MBC
// metadata, a Malpedia export, or an abuse.ch pull (see ASK.md SEED-2/3) to widen
// L0 without code changes. curated writes only - seeds are trusted authority.

import (
	"bytes"
	"embed"
	"encoding/json"
	"fmt"
)

//go:embed seeddata/starter.json
var seedFS embed.FS

// SeedFact is one curated fact in a corpus file.
type SeedFact struct {
	Kind  string            `json:"kind"`
	Key   string            `json:"key"`
	Label string            `json:"label"`
	Attrs map[string]string `json:"attrs,omitempty"`
}

type seedCorpus struct {
	Source string     `json:"source"`
	Facts  []SeedFact `json:"facts"`
}

// SeedStarter curates the bundled starter corpus so L0 is populated on first boot.
// idempotent: Curate refreshes an existing fact, so re-seeding is a no-op on
// content. returns how many facts were curated and how many were skipped as
// malformed (a bad entry never aborts the seed).
func (r *Registry) SeedStarter() (curated, skipped int, err error) {
	b, err := seedFS.ReadFile("seeddata/starter.json")
	if err != nil {
		return 0, 0, fmt.Errorf("knowledge: read starter corpus: %w", err)
	}
	return r.SeedJSON(b)
}

// SeedJSON curates every well-formed fact in a corpus blob. it strictly decodes
// the envelope (unknown fields rejected) but is TOLERANT per-fact: a single
// malformed entry (bad kind, malformed key, oversize label) is skipped and
// counted, never fatal, so one bad row in a large public corpus cannot deny the
// whole seed. the corpus Source (or "bundled:starter") is recorded as provenance.
func (r *Registry) SeedJSON(b []byte) (curated, skipped int, err error) {
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	var c seedCorpus
	if err := dec.Decode(&c); err != nil {
		return 0, 0, fmt.Errorf("knowledge: decode corpus: %w", err)
	}
	if dec.More() {
		return 0, 0, fmt.Errorf("knowledge: trailing data after corpus")
	}
	src := c.Source
	if src == "" {
		src = "bundled:starter"
	}
	for _, f := range c.Facts {
		if _, e := r.Curate(Kind(f.Kind), f.Key, f.Label, f.Attrs, src); e != nil {
			skipped++
			continue
		}
		curated++
	}
	return curated, skipped, nil
}
