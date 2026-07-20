package export

import (
	"encoding/json"
	"strings"

	"github.com/COLONAYUSH/OpenMalLab/internal/pipeline"
)

// identityID names this tool as the producer on every sdo.
var identityID = "identity--" + uuidv5("identity:"+product)

// sdo assembles the common required properties every stix domain object
// shares. maps marshal with sorted keys, which is exactly the determinism
// this package promises.
func sdo(typ, id string, extra map[string]any) map[string]any {
	o := map[string]any{
		"type":           typ,
		"spec_version":   "2.1",
		"id":             id,
		"created":        sentinelTime,
		"modified":       sentinelTime,
		"created_by_ref": identityID,
	}
	for k, v := range extra {
		o[k] = v
	}
	return o
}

func relationship(relType, src, dst string) map[string]any {
	return sdo("relationship", "relationship--"+uuidv5("relationship:"+relType+":"+src+":"+dst), map[string]any{
		"relationship_type": relType,
		"source_ref":        src,
		"target_ref":        dst,
	})
}

// stixEscape makes a value safe inside a stix pattern string literal.
func stixEscape(s string) string {
	s = strings.ReplaceAll(s, `\`, `\\`)
	return strings.ReplaceAll(s, `'`, `\'`)
}

// stixPattern renders the match expression for one ioc.
func stixPattern(c ioc) string {
	v := stixEscape(c.value)
	switch c.kind {
	case kindSHA256:
		return "[file:hashes.'SHA-256' = '" + v + "']"
	case kindDomain:
		return "[domain-name:value = '" + v + "']"
	case kindIPv4:
		return "[ipv4-addr:value = '" + v + "']"
	case kindIPv6:
		return "[ipv6-addr:value = '" + v + "']"
	default:
		return "[url:value = '" + v + "']"
	}
}

// scoNamespace is the oasis-fixed uuidv5 namespace stix 2.1 section 2.9
// prescribes for deterministic sco ids. deriving the file id there, over
// the id-contributing properties, means our file object gets the SAME id
// any conformant producer derives for the same sha-256, so downstream
// stores dedupe across products, not just across our own re-exports.
var scoNamespace = [16]byte{0x00, 0xab, 0xed, 0xb4, 0xaa, 0x42, 0x46, 0x6c, 0x9c, 0x01, 0xfe, 0xd2, 0x33, 0x15, 0xa9, 0xb7}

// fileID keys the file object: the spec-blessed sco derivation when we
// have the hash, otherwise a private-namespace id from the submission so
// two hashless exports cannot collide.
func fileID(res pipeline.SubmissionResult, sha string) string {
	if sha != "" {
		return "file--" + formatUUID(uuidv5raw(scoNamespace, `{"hashes":{"SHA-256":"`+sha+`"}}`))
	}
	return "file--" + uuidv5("file:submission:"+res.SubmissionID+":"+displayString(res.Filename, 256))
}

// ToSTIX renders the result as a stix 2.1 bundle: the sample as a file
// object, the verdict as a malware-analysis, an indicator per ioc, an
// attack-pattern stub per att&ck technique, and relationships tying them
// together. benign and unknown results export the file and the analysis
// only: an indicator asserts badness, and this exporter will not assert
// what the pipeline did not conclude.
func ToSTIX(res pipeline.SubmissionResult) ([]byte, error) {
	ex := extract(res)
	sha := sampleSHA(res)

	identity := map[string]any{
		"type":           "identity",
		"spec_version":   "2.1",
		"id":             identityID,
		"created":        sentinelTime,
		"modified":       sentinelTime,
		"name":           product,
		"identity_class": "system",
	}

	fileRef := fileID(res, sha)
	file := map[string]any{
		"type":         "file",
		"spec_version": "2.1",
		"id":           fileRef,
	}
	if sha != "" {
		file["hashes"] = map[string]any{"SHA-256": sha}
	}
	if name := displayString(res.Filename, 256); name != "" {
		file["name"] = name
	} else if sha == "" {
		file["name"] = "unknown-sample"
	}

	analysis := sdo("malware-analysis",
		"malware-analysis--"+uuidv5("malware-analysis:"+res.SubmissionID+":"+sha),
		map[string]any{
			"product":                 product,
			"result":                  stixResult(res.Verdict),
			"sample_ref":              fileRef,
			"x_openmallab_score":      res.Score,
			"x_openmallab_confidence": res.Confidence.String(),
		})
	if res.Incomplete {
		analysis["x_openmallab_incomplete"] = true
	}
	if ex.truncated {
		analysis["x_openmallab_ioc_truncated"] = true
	}

	objects := []any{identity, file, analysis}

	if res.Verdict >= pipeline.Suspicious {
		malwareID := "malware--" + uuidv5("malware:"+res.SubmissionID+":"+sha)
		objects = append(objects, sdo("malware", malwareID, map[string]any{
			"name":        "sample-" + shortSHA(sha),
			"is_family":   false,
			"sample_refs": []any{fileRef},
		}))
		for _, t := range ex.techniques {
			apID := "attack-pattern--" + uuidv5("attack-pattern:"+t)
			objects = append(objects, sdo("attack-pattern", apID, map[string]any{
				"name": t,
				"external_references": []any{map[string]any{
					"source_name": "mitre-attack",
					"external_id": t,
				}},
			}))
			objects = append(objects, relationship("uses", malwareID, apID))
		}
		for _, c := range ex.iocs {
			indID := "indicator--" + uuidv5("indicator:"+c.kind.String()+":"+c.value)
			objects = append(objects, sdo("indicator", indID, map[string]any{
				"name":            c.kind.String() + " " + c.value,
				"pattern":         stixPattern(c),
				"pattern_type":    "stix",
				"valid_from":      sentinelTime,
				"indicator_types": []any{"malicious-activity"},
			}))
			objects = append(objects, relationship("indicates", indID, malwareID))
		}
	}

	bundle := map[string]any{
		"type":    "bundle",
		"id":      "bundle--" + uuidv5("bundle:"+res.SubmissionID+":"+sha+":"+stixResult(res.Verdict)),
		"objects": objects,
	}
	return json.MarshalIndent(bundle, "", "  ")
}
