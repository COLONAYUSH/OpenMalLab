// Package export renders a finished submission into the interchange formats
// the rest of a soc speaks: a stix 2.1 bundle and a misp event. this is the
// first slice of phase 4 (reporting and interop) from docs/ROADMAP.md.
//
// the package is deliberately pure: it imports the pipeline contract
// read-only, takes a rolled-up SubmissionResult, and hands bytes back. no
// wiring, no state, no clock, no new dependencies. the gateway route that
// will serve these, added in a later change:
//
//	GET /v1/submissions/{id}/export?format=stix|misp
//
// determinism is a feature here. the same result always renders to the same
// bytes, so an export can be content-addressed, cached, and diffed. every id
// is a uuidv5 derived from content, and timestamps are a fixed epoch
// sentinel, because a result carries no timeline of its own and a wall clock
// would break the same-input-same-bytes guarantee.
package export

import (
	"crypto/sha1"
	"fmt"
	"regexp"
	"strings"

	"github.com/COLONAYUSH/OpenMalLab/internal/pipeline"
)

const (
	// product names this tool in both export formats.
	product = "openmallab"

	// sentinelTime and sentinelDate are the fixed timestamps stamped on
	// exported objects. stamping the wall clock would make two exports of
	// the same verdict differ byte for byte, so the epoch stands in as an
	// explicit "no time known" marker.
	sentinelTime = "1970-01-01T00:00:00.000Z"
	sentinelDate = "1970-01-01"
)

// exportNamespace is the uuidv5 namespace every export id lives in:
// uuidv5(dns namespace, "openmallab.export"), fixed forever so ids stay
// stable across releases and re-exports.
var exportNamespace = uuidv5raw(
	[16]byte{0x6b, 0xa7, 0xb8, 0x10, 0x9d, 0xad, 0x11, 0xd1, 0x80, 0xb4, 0x00, 0xc0, 0x4f, 0xd4, 0x30, 0xc8},
	"openmallab.export",
)

// uuidv5 derives the deterministic rfc 4122 version-5 uuid for a name in the
// export namespace. content-derived ids are what make a re-export
// byte-identical and let a downstream store dedupe on ingest. sha-1 here is
// the digest rfc 4122 prescribes for v5, not a security control.
func uuidv5(name string) string {
	return formatUUID(uuidv5raw(exportNamespace, name))
}

func formatUUID(u [16]byte) string {
	return fmt.Sprintf("%x-%x-%x-%x-%x", u[0:4], u[4:6], u[6:8], u[8:10], u[10:16])
}

func uuidv5raw(ns [16]byte, name string) [16]byte {
	h := sha1.New()
	h.Write(ns[:])
	h.Write([]byte(name))
	var u [16]byte
	copy(u[:], h.Sum(nil))
	u[6] = (u[6] & 0x0f) | 0x50 // version 5
	u[8] = (u[8] & 0x3f) | 0x80 // rfc 4122 variant
	return u
}

var sha256Hex = regexp.MustCompile(`^[0-9a-fA-F]{64}$`)

// sampleSHA canonicalizes the result's sha-256, or returns "" when the field
// does not hold one. the field is written by trusted code, but an exporter
// that renders whatever it is handed would let one corrupt record forge
// hash-shaped lies for every downstream consumer.
func sampleSHA(res pipeline.SubmissionResult) string {
	if sha256Hex.MatchString(res.SHA256) {
		return strings.ToLower(res.SHA256)
	}
	return ""
}

// shortSHA is the display prefix used in object names and event titles.
func shortSHA(sha string) string {
	if len(sha) >= 12 {
		return sha[:12]
	}
	if sha == "" {
		return "unknown"
	}
	return sha
}

// displayString bounds a hostile display-only string to printable ascii
// before it lands in an export other tools will render verbatim.
func displayString(s string, max int) string {
	var b strings.Builder
	for i := 0; i < len(s) && b.Len() < max; i++ {
		c := s[i]
		if c >= 0x20 && c < 0x7f {
			b.WriteByte(c)
		} else {
			b.WriteByte('.')
		}
	}
	return b.String()
}

// stixResult maps the verdict lattice onto the stix malware-analysis result
// vocabulary. UNKNOWN stays "unknown": the export must never soften what the
// pipeline refused to call clean.
func stixResult(v pipeline.Verdict) string {
	switch v {
	case pipeline.Benign:
		return "benign"
	case pipeline.Suspicious:
		return "suspicious"
	case pipeline.Malicious:
		return "malicious"
	default:
		return "unknown"
	}
}
