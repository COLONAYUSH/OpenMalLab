package export

import (
	"encoding/json"
	"fmt"

	"github.com/COLONAYUSH/OpenMalLab/internal/pipeline"
)

// mispDocument is the {"Event": {...}} envelope a misp import expects.
type mispDocument struct {
	Event mispEvent `json:"Event"`
}

type mispEvent struct {
	UUID          string          `json:"uuid"`
	Info          string          `json:"info"`
	Date          string          `json:"date"`
	ThreatLevelID string          `json:"threat_level_id"`
	Analysis      string          `json:"analysis"`
	Distribution  string          `json:"distribution"`
	Published     bool            `json:"published"`
	Attribute     []mispAttribute `json:"Attribute"`
	Tag           []mispTag       `json:"Tag,omitempty"`
}

type mispAttribute struct {
	UUID     string `json:"uuid"`
	Type     string `json:"type"`
	Category string `json:"category"`
	ToIDS    bool   `json:"to_ids"`
	Value    string `json:"value"`
}

type mispTag struct {
	Name string `json:"name"`
}

// mispType maps an ioc kind onto the misp attribute type and category pair.
func mispType(k iocKind) (string, string) {
	switch k {
	case kindSHA256:
		return "sha256", "Payload delivery"
	case kindDomain:
		return "domain", "Network activity"
	case kindIPv4, kindIPv6:
		return "ip-dst", "Network activity"
	default:
		return "url", "Network activity"
	}
}

// mispThreatLevel maps the verdict lattice onto misp threat levels.
func mispThreatLevel(v pipeline.Verdict) string {
	switch v {
	case pipeline.Malicious:
		return "1" // high
	case pipeline.Suspicious:
		return "2" // medium
	case pipeline.Benign:
		return "3" // low
	default:
		return "4" // undefined: UNKNOWN is not benign, it is unscored
	}
}

// mispAnalysis maps completeness onto the misp analysis stage: 2 is
// complete, 1 is ongoing (something was truncated or an engine failed).
func mispAnalysis(res pipeline.SubmissionResult) string {
	if res.Incomplete {
		return "1"
	}
	return "2"
}

// ToMISP renders the result as a misp event: one attribute per ioc with the
// correct type and category, the verdict in the event info and threat
// level, and att&ck techniques as galaxy tags. attributes are observations,
// so they are present for every verdict; to_ids only arms at suspicious or
// worse, so a benign export can never feed a detection rule.
func ToMISP(res pipeline.SubmissionResult) ([]byte, error) {
	ex := extract(res)
	sha := sampleSHA(res)
	eventSeed := "misp-event:" + res.SubmissionID + ":" + sha

	info := fmt.Sprintf("%s verdict for sample %s: %s (score %d/100)",
		product, shortSHA(sha), res.Verdict.String(), res.Score)
	if res.Incomplete {
		info += " [incomplete analysis]"
	}

	armed := res.Verdict >= pipeline.Suspicious
	attrs := make([]mispAttribute, 0, len(ex.iocs))
	for _, c := range ex.iocs {
		typ, cat := mispType(c.kind)
		attrs = append(attrs, mispAttribute{
			UUID:     uuidv5("misp-attribute:" + eventSeed + ":" + typ + ":" + c.value),
			Type:     typ,
			Category: cat,
			ToIDS:    armed,
			Value:    c.value,
		})
	}

	tags := []mispTag{{Name: product + `:verdict="` + res.Verdict.String() + `"`}}
	if armed {
		// technique tags are assertions, so like stix attack-patterns they
		// only appear once the pipeline concluded suspicious or worse. the
		// tag lives in our own namespace on purpose: a misp-galaxy cluster
		// tag only binds when it carries the exact technique NAME alongside
		// the id, which an air-gapped exporter cannot promise for every id,
		// and a tag that pretends to bind but does not is worse than an
		// honest one. the stix side carries the mitre external_id, which
		// graph stores merge correctly.
		for _, t := range ex.techniques {
			tags = append(tags, mispTag{Name: product + `:attck="` + t + `"`})
		}
	}
	if ex.truncated {
		tags = append(tags, mispTag{Name: product + ":ioc-truncated"})
	}

	doc := mispDocument{Event: mispEvent{
		UUID:          uuidv5(eventSeed),
		Info:          info,
		Date:          sentinelDate,
		ThreatLevelID: mispThreatLevel(res.Verdict),
		Analysis:      mispAnalysis(res),
		Distribution:  "0", // this org only; the operator widens sharing on import
		Published:     false,
		Attribute:     attrs,
		Tag:           tags,
	}}
	return json.MarshalIndent(doc, "", "  ")
}
