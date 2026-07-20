package export

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
	"testing"

	"github.com/COLONAYUSH/OpenMalLab/internal/pipeline"
)

// sha256 of the ascii string "test", a well-known vector.
const testSHA = "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"

// sha256 of the empty input, standing in for an extracted child artifact.
const childSHA = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

// uuidv5 shape: version nibble 5, rfc 4122 variant.
var uuidV5Re = regexp.MustCompile(`^[a-z-]+--[0-9a-f]{8}-[0-9a-f]{4}-5[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)

func maliciousResult() pipeline.SubmissionResult {
	return pipeline.SubmissionResult{
		SubmissionID: "sub-0001",
		SHA256:       testSHA,
		Filename:     "dropper.elf",
		FileType:     "elf",
		Verdict:      pipeline.Malicious,
		Score:        91,
		Confidence:   pipeline.ConfHigh,
		Findings: []pipeline.Finding{
			// a yara match in the engine's real evidence() shape: metadata
			// first (whose reference url must never be mined), then the
			// matched pattern embedding a defanged c2 url.
			{Engine: "mal-static-yara", Type: "yara",
				Detail:  `Backdoor_Generic [community] #apt - description: generic backdoor beacon - reference: https://intel.vendor.example/report | $s1@0x1a2b "hxxps://c2[.]badcorp[.]example/gate.php"`,
				Attck:   "T1059",
				Verdict: pipeline.Malicious, Confidence: pipeline.ConfHigh},
			// detonation findings arrive defanged by the wrapper.
			{Engine: "mal-detonate", Type: "net-connect",
				Detail:  "outbound connection attempt to 203[.]0[.]113.7:443",
				Attck:   "T1071",
				Verdict: pipeline.Suspicious, Confidence: pipeline.ConfMedium},
			// duplicate domain (also the url host above) plus a lowercase
			// duplicate technique: both must dedupe.
			{Engine: "mal-detonate", Type: "net-connect",
				Detail:  "outbound connection attempt to c2[.]badcorp.example:443",
				Attck:   "t1071",
				Verdict: pipeline.Suspicious, Confidence: pipeline.ConfMedium},
			// slirp plumbing: private space never becomes an indicator,
			// whether it appears as a bare address or wearing a scheme.
			{Engine: "mal-detonate", Type: "net-connect",
				Detail:  "outbound connection attempt to 10[.]0[.]2.2:80",
				Verdict: pipeline.Suspicious, Confidence: pipeline.ConfMedium},
			{Engine: "mal-detonate", Type: "net-connect",
				Detail:  "fetched hxxp://10[.]0[.]2[.]2:8080/stage2",
				Verdict: pipeline.Suspicious, Confidence: pipeline.ConfMedium},
			// non-network finding types are never mined for iocs, and a
			// malformed technique id is dropped.
			{Engine: "mal-floss", Type: "decoded-string",
				Detail:  "config at ignore-me.example plus junk",
				Attck:   "T99",
				Verdict: pipeline.Unknown, Confidence: pipeline.ConfLow},
			{Engine: "mal-detonate", Type: "exec",
				Detail:  "executed /tmp/payload.sh (dropped payload)",
				Verdict: pipeline.Suspicious, Confidence: pipeline.ConfMedium},
			// an extracted child's hash is an ioc of its own.
			{Engine: "mal-orchestrator", Type: "artifact-sha256",
				Detail: "sha256=" + childSHA, Path: "dropper.elf!stage2.bin",
				Verdict: pipeline.Unknown, Confidence: pipeline.ConfLow},
		},
	}
}

func benignResult() pipeline.SubmissionResult {
	return pipeline.SubmissionResult{
		SubmissionID: "sub-0002",
		SHA256:       strings.Repeat("ab", 32),
		Filename:     "hello.txt",
		Verdict:      pipeline.Benign,
		Score:        0,
		Confidence:   pipeline.ConfLow,
		Findings: []pipeline.Finding{
			{Engine: "mal-ident", Type: "file-type", Detail: "text/plain",
				Verdict: pipeline.Unknown, Confidence: pipeline.ConfLow},
		},
	}
}

func reversedFindings(res pipeline.SubmissionResult) pipeline.SubmissionResult {
	out := res
	out.Findings = make([]pipeline.Finding, len(res.Findings))
	for i, f := range res.Findings {
		out.Findings[len(res.Findings)-1-i] = f
	}
	return out
}

func objectsByType(t *testing.T, raw []byte) (map[string][]map[string]any, []map[string]any) {
	t.Helper()
	var bundle map[string]any
	if err := json.Unmarshal(raw, &bundle); err != nil {
		t.Fatalf("bundle is not valid json: %v", err)
	}
	if bundle["type"] != "bundle" {
		t.Fatalf("top-level type = %v, want bundle", bundle["type"])
	}
	rawObjs, ok := bundle["objects"].([]any)
	if !ok {
		t.Fatalf("bundle has no objects array")
	}
	byType := map[string][]map[string]any{}
	var all []map[string]any
	for _, o := range rawObjs {
		obj, ok := o.(map[string]any)
		if !ok {
			t.Fatalf("object is not a json object: %v", o)
		}
		typ, _ := obj["type"].(string)
		byType[typ] = append(byType[typ], obj)
		all = append(all, obj)
	}
	return byType, all
}

func TestToSTIXMalicious(t *testing.T) {
	res := maliciousResult()
	raw, err := ToSTIX(res)
	if err != nil {
		t.Fatalf("ToSTIX: %v", err)
	}

	// deterministic: same input, byte-identical output; finding order must
	// not matter either.
	again, err := ToSTIX(res)
	if err != nil {
		t.Fatalf("ToSTIX second call: %v", err)
	}
	if !bytes.Equal(raw, again) {
		t.Fatalf("two exports of the same result differ")
	}
	shuffled, err := ToSTIX(reversedFindings(res))
	if err != nil {
		t.Fatalf("ToSTIX reversed findings: %v", err)
	}
	if !bytes.Equal(raw, shuffled) {
		t.Fatalf("export depends on finding order")
	}

	byType, all := objectsByType(t, raw)
	wantCounts := map[string]int{
		"identity":         1,
		"file":             1,
		"malware-analysis": 1,
		"malware":          1,
		"attack-pattern":   2, // T1059, T1071 (deduped)
		"indicator":        5, // root sha256, child sha256, domain, ipv4, url (deduped)
		"relationship":     7, // 5 indicates + 2 uses
	}
	for typ, want := range wantCounts {
		if got := len(byType[typ]); got != want {
			t.Errorf("%s count = %d, want %d", typ, got, want)
		}
	}

	// the sample file object carries the hash and the display name.
	file := byType["file"][0]
	hashes, _ := file["hashes"].(map[string]any)
	if hashes["SHA-256"] != testSHA {
		t.Errorf("file SHA-256 = %v, want %s", hashes["SHA-256"], testSHA)
	}
	if file["name"] != "dropper.elf" {
		t.Errorf("file name = %v", file["name"])
	}

	// the malware-analysis carries the verdict and the score.
	analysis := byType["malware-analysis"][0]
	if analysis["result"] != "malicious" {
		t.Errorf("analysis result = %v, want malicious", analysis["result"])
	}
	if analysis["product"] != product {
		t.Errorf("analysis product = %v", analysis["product"])
	}
	if analysis["x_openmallab_score"] != float64(91) {
		t.Errorf("analysis score = %v, want 91", analysis["x_openmallab_score"])
	}
	if analysis["sample_ref"] != byType["file"][0]["id"] {
		t.Errorf("analysis sample_ref does not point at the file object")
	}

	// exactly the expected patterns, refanged and deduped.
	wantPatterns := map[string]bool{
		"[file:hashes.'SHA-256' = '" + testSHA + "']":         false,
		"[file:hashes.'SHA-256' = '" + childSHA + "']":        false,
		"[domain-name:value = 'c2.badcorp.example']":          false,
		"[ipv4-addr:value = '203.0.113.7']":                   false,
		"[url:value = 'https://c2.badcorp.example/gate.php']": false,
	}
	for _, ind := range byType["indicator"] {
		p, _ := ind["pattern"].(string)
		if _, ok := wantPatterns[p]; !ok {
			t.Errorf("unexpected indicator pattern %q", p)
			continue
		}
		wantPatterns[p] = true
	}
	for p, seen := range wantPatterns {
		if !seen {
			t.Errorf("missing indicator pattern %q", p)
		}
	}

	// attack-pattern stubs reference mitre by external id.
	gotTech := map[string]bool{}
	for _, ap := range byType["attack-pattern"] {
		gotTech[ap["name"].(string)] = true
	}
	if !gotTech["T1059"] || !gotTech["T1071"] {
		t.Errorf("attack patterns = %v, want T1059 and T1071", gotTech)
	}

	// hostile and internal values must never leak into the export: no
	// slirp plumbing (bare or in a url), no rule-metadata intel links, no
	// mined paths, no malformed techniques.
	text := string(raw)
	for _, banned := range []string{"10.0.2.2", "intel.vendor", "ignore-me", "payload.sh", "T99\""} {
		if strings.Contains(text, banned) {
			t.Errorf("export leaked %q", banned)
		}
	}

	// every id is a deterministic uuidv5 and unique; every reference
	// resolves inside the bundle.
	ids := map[string]bool{}
	for _, obj := range all {
		id, _ := obj["id"].(string)
		if !uuidV5Re.MatchString(id) {
			t.Errorf("id %q is not a uuidv5 stix id", id)
		}
		if ids[id] {
			t.Errorf("duplicate id %q", id)
		}
		ids[id] = true
	}
	for _, obj := range all {
		for _, key := range []string{"created_by_ref", "sample_ref", "source_ref", "target_ref"} {
			if ref, ok := obj[key].(string); ok && !ids[ref] {
				t.Errorf("%s %q does not resolve inside the bundle", key, ref)
			}
		}
		if refs, ok := obj["sample_refs"].([]any); ok {
			for _, r := range refs {
				if !ids[r.(string)] {
					t.Errorf("sample_refs %v does not resolve inside the bundle", r)
				}
			}
		}
	}
}

func TestToSTIXBenignIsEmptyish(t *testing.T) {
	raw, err := ToSTIX(benignResult())
	if err != nil {
		t.Fatalf("ToSTIX: %v", err)
	}
	again, _ := ToSTIX(benignResult())
	if !bytes.Equal(raw, again) {
		t.Fatalf("benign export is not deterministic")
	}
	byType, all := objectsByType(t, raw)
	if len(all) != 3 {
		t.Fatalf("benign bundle has %d objects, want 3 (identity, file, analysis)", len(all))
	}
	if byType["malware-analysis"][0]["result"] != "benign" {
		t.Errorf("analysis result = %v, want benign", byType["malware-analysis"][0]["result"])
	}
	for _, typ := range []string{"indicator", "malware", "attack-pattern", "relationship"} {
		if len(byType[typ]) != 0 {
			t.Errorf("benign bundle contains %s objects", typ)
		}
	}
}

func TestToSTIXZeroValueNeverPanics(t *testing.T) {
	raw, err := ToSTIX(pipeline.SubmissionResult{})
	if err != nil {
		t.Fatalf("ToSTIX zero value: %v", err)
	}
	byType, _ := objectsByType(t, raw)
	file := byType["file"][0]
	if file["name"] != "unknown-sample" {
		t.Errorf("hashless file name = %v, want unknown-sample", file["name"])
	}
	if _, ok := file["hashes"]; ok {
		t.Errorf("zero value export must not fabricate hashes")
	}
	// the lattice's zero value is BENIGN by design (optimistic bottom).
	if byType["malware-analysis"][0]["result"] != "benign" {
		t.Errorf("zero value result = %v", byType["malware-analysis"][0]["result"])
	}
}

func TestToMISPMalicious(t *testing.T) {
	res := maliciousResult()
	raw, err := ToMISP(res)
	if err != nil {
		t.Fatalf("ToMISP: %v", err)
	}
	again, _ := ToMISP(res)
	if !bytes.Equal(raw, again) {
		t.Fatalf("two exports of the same result differ")
	}
	shuffled, _ := ToMISP(reversedFindings(res))
	if !bytes.Equal(raw, shuffled) {
		t.Fatalf("export depends on finding order")
	}

	var doc struct {
		Event struct {
			UUID          string `json:"uuid"`
			Info          string `json:"info"`
			ThreatLevelID string `json:"threat_level_id"`
			Analysis      string `json:"analysis"`
			Attribute     []struct {
				UUID     string `json:"uuid"`
				Type     string `json:"type"`
				Category string `json:"category"`
				ToIDS    bool   `json:"to_ids"`
				Value    string `json:"value"`
			} `json:"Attribute"`
			Tag []struct {
				Name string `json:"name"`
			} `json:"Tag"`
		} `json:"Event"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("event is not valid json: %v", err)
	}
	ev := doc.Event
	if !strings.Contains(ev.Info, "MALICIOUS") || !strings.Contains(ev.Info, testSHA[:12]) {
		t.Errorf("event info %q lacks the verdict or the sample", ev.Info)
	}
	if ev.ThreatLevelID != "1" {
		t.Errorf("threat_level_id = %q, want 1", ev.ThreatLevelID)
	}
	if ev.Analysis != "2" {
		t.Errorf("analysis = %q, want 2 (complete)", ev.Analysis)
	}

	type attrKey struct{ typ, cat, val string }
	got := map[attrKey]bool{}
	for _, a := range ev.Attribute {
		if !a.ToIDS {
			t.Errorf("attribute %q not armed on a malicious event", a.Value)
		}
		if !regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-5[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`).MatchString(a.UUID) {
			t.Errorf("attribute uuid %q is not a uuidv5", a.UUID)
		}
		got[attrKey{a.Type, a.Category, a.Value}] = true
	}
	want := []attrKey{
		{"sha256", "Payload delivery", testSHA},
		{"sha256", "Payload delivery", childSHA},
		{"domain", "Network activity", "c2.badcorp.example"},
		{"ip-dst", "Network activity", "203.0.113.7"},
		{"url", "Network activity", "https://c2.badcorp.example/gate.php"},
	}
	if len(ev.Attribute) != len(want) {
		t.Errorf("attribute count = %d, want %d (dedupe)", len(ev.Attribute), len(want))
	}
	for _, w := range want {
		if !got[w] {
			t.Errorf("missing attribute %+v", w)
		}
	}

	tags := map[string]bool{}
	for _, tag := range ev.Tag {
		tags[tag.Name] = true
	}
	for _, w := range []string{
		`openmallab:verdict="MALICIOUS"`,
		`openmallab:attck="T1059"`,
		`openmallab:attck="T1071"`,
	} {
		if !tags[w] {
			t.Errorf("missing tag %q in %v", w, tags)
		}
	}
}

func TestToMISPBenign(t *testing.T) {
	raw, err := ToMISP(benignResult())
	if err != nil {
		t.Fatalf("ToMISP: %v", err)
	}
	var doc mispDocument
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("event is not valid json: %v", err)
	}
	ev := doc.Event
	if ev.ThreatLevelID != "3" {
		t.Errorf("threat_level_id = %q, want 3", ev.ThreatLevelID)
	}
	if !strings.Contains(ev.Info, "BENIGN") {
		t.Errorf("event info %q lacks the verdict", ev.Info)
	}
	if len(ev.Attribute) != 1 || ev.Attribute[0].Type != "sha256" {
		t.Fatalf("benign event attributes = %+v, want just the sha256", ev.Attribute)
	}
	if ev.Attribute[0].ToIDS {
		t.Errorf("a benign export must never arm to_ids")
	}
	if len(ev.Tag) != 1 || ev.Tag[0].Name != `openmallab:verdict="BENIGN"` {
		t.Errorf("benign tags = %+v, want only the verdict tag", ev.Tag)
	}
}

func TestToMISPZeroValueNeverPanics(t *testing.T) {
	raw, err := ToMISP(pipeline.SubmissionResult{})
	if err != nil {
		t.Fatalf("ToMISP zero value: %v", err)
	}
	var doc mispDocument
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("event is not valid json: %v", err)
	}
	if len(doc.Event.Attribute) != 0 {
		t.Errorf("zero value event fabricated attributes: %+v", doc.Event.Attribute)
	}
}

func TestExtractParsingTable(t *testing.T) {
	cases := []struct {
		name   string
		typ    string
		detail string
		want   []ioc
		absent []string
	}{
		{
			name:   "refangs defanged url and derives the host",
			typ:    "net-connect",
			detail: "beacon to hxxp://evil[.]badcorp[.]example/x?id=1",
			want: []ioc{
				{kindDomain, "evil.badcorp.example"},
				{kindURL, "http://evil.badcorp.example/x?id=1"},
			},
		},
		{
			name:   "bare defanged domain with a port",
			typ:    "dns",
			detail: "resolved c2[.]badcorp[.]example:8443",
			want:   []ioc{{kindDomain, "c2.badcorp.example"}},
		},
		{
			name:   "sentence period after a domain is not part of it",
			typ:    "dns",
			detail: "resolved c2.badcorp.example.",
			want:   []ioc{{kindDomain, "c2.badcorp.example"}},
		},
		{
			name:   "shared library is not a domain",
			typ:    "net-connect",
			detail: "opened /lib/x86-64/libc.so.6 then connected",
			want:   nil,
			absent: []string{"libc.so"},
		},
		{
			name:   "script path is not a domain",
			typ:    "net-connect",
			detail: "fetched stage2.sh from somewhere",
			want:   nil,
			absent: []string{"stage2.sh"},
		},
		{
			name:   "head of a longer dotted run is not an ip",
			typ:    "net-connect",
			detail: "version 1.2.3.4.5 seen",
			want:   nil,
			absent: []string{"1.2.3.4"},
		},
		{
			name:   "public ipv4 with the last dot left fanged",
			typ:    "net-connect",
			detail: "outbound connection attempt to 203[.]0[.]113.7:443",
			want:   []ioc{{kindIPv4, "203.0.113.7"}},
		},
		{
			name:   "private, loopback and unspecified addresses are noise",
			typ:    "net-connect",
			detail: "tried 10.0.2.2 then 127.0.0.1 then 0.0.0.0 then 192.168.1.9",
			want:   nil,
		},
		{
			name:   "ipv6 is validated by the parser, not a regex",
			typ:    "net-connect",
			detail: "connected to 2001:db8::5 port 443, uptime 12:30:45",
			want:   []ioc{{kindIPv6, "2001:db8::5"}},
		},
		{
			name:   "non-network finding types are never mined",
			typ:    "decoded-string",
			detail: "contains evil.badcorp.example and hxxp://x[.]badcorp[.]example/",
			want:   nil,
		},
		{
			name:   "extracted child hash becomes an ioc",
			typ:    "artifact-sha256",
			detail: "sha256=" + strings.ToUpper(childSHA),
			want:   []ioc{{kindSHA256, childSHA}},
		},
		{
			name:   "63 hex chars is not a hash and half a sha-512 is not a hash",
			typ:    "artifact-sha256",
			detail: "sha256=" + childSHA[:63] + " and " + childSHA + childSHA,
			want:   nil,
		},
		{
			name:   "private and loopback hosts are filtered even inside urls",
			typ:    "net-connect",
			detail: "fetched hxxp://10[.]0[.]2[.]2:8080/stage2 then http://127.0.0.1:9050/control and http://192.168.1.50/panel",
			want:   nil,
		},
		{
			name:   "urls with garbage or single-label hosts are not iocs",
			typ:    "net-connect",
			detail: "hit http://evil_host/gate then http://x/beacon then http://evil.com]junk/x",
			want:   nil,
		},
		{
			name:   "public url keeps working and yields exactly url plus host",
			typ:    "net-connect",
			detail: "beacon to https://c2.badcorp.example/x and hxxp://203[.]0[.]113.9/y",
			want: []ioc{
				{kindDomain, "c2.badcorp.example"},
				{kindIPv4, "203.0.113.9"},
				{kindURL, "http://203.0.113.9/y"},
				{kindURL, "https://c2.badcorp.example/x"},
			},
		},
		{
			name:   "leading labels of an fqdn never become an address",
			typ:    "dns",
			detail: "resolved 8[.]8[.]8[.]8[.]cdn-evil[.]example fast-flux",
			want:   []ioc{{kindDomain, "8.8.8.8.cdn-evil.example"}},
		},
		{
			name:   "version tokens never become addresses",
			typ:    "net-connect",
			detail: "agent v1.2.3.4 build 5.6.7.8b reporting",
			want:   nil,
		},
		{
			name:   "windows path components are not domains",
			typ:    "yara",
			detail: "$s1@0x10 \"wrote C:\\Users\\bob\\update.hta and D:\\drop\\evil.msi\"",
			want:   nil,
		},
		{
			name:   "dropper filenames with file-ish extensions are not domains",
			typ:    "net-connect",
			detail: "dropped installer.msi payload.docm evil.hta unit.service data.db",
			want:   nil,
		},
		{
			name:   "yara rule metadata urls are never mined, matched patterns are",
			typ:    "yara",
			detail: `SusRule [community] #apt - description: beacons out - reference: https://blog.vendor.example/apt | $s1@0x10 "hxxp://real-c2[.]badcorp[.]example/p"`,
			want: []ioc{
				{kindDomain, "real-c2.badcorp.example"},
				{kindURL, "http://real-c2.badcorp.example/p"},
			},
			absent: []string{"blog.vendor.example"},
		},
		{
			name:   "a value cut by the yara match preview is never exported",
			typ:    "yara",
			detail: `Trojan_X | $s1@0x40 "hxxp://cut-off[.]badcorp[.]exam"..`,
			want:   nil,
			absent: []string{"cut-off"},
		},
		{
			name:   "non-http scheme still yields the blockable host, never a url",
			typ:    "net-connect",
			detail: "pulled ftp://files.badcorp.example/drop.bin",
			want:   []ioc{{kindDomain, "files.badcorp.example"}},
		},
		{
			name:   "cgnat, broadcast and zero-net addresses are noise",
			typ:    "net-connect",
			detail: "sent to 100.64.0.7 and 255.255.255.255 and 0.1.2.3 and 240.1.2.3",
			want:   nil,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			res := pipeline.SubmissionResult{
				Verdict:  pipeline.Suspicious,
				Findings: []pipeline.Finding{{Engine: "mal-detonate", Type: tc.typ, Detail: tc.detail}},
			}
			ex := extract(res)
			got := map[ioc]bool{}
			for _, c := range ex.iocs {
				got[c] = true
			}
			if len(ex.iocs) != len(tc.want) {
				t.Errorf("extracted %v, want %v", ex.iocs, tc.want)
			}
			for _, w := range tc.want {
				if !got[w] {
					t.Errorf("missing ioc %v in %v", w, ex.iocs)
				}
			}
			for _, a := range tc.absent {
				for c := range got {
					if strings.Contains(c.value, a) {
						t.Errorf("ioc %v leaked banned fragment %q", c, a)
					}
				}
			}
		})
	}
}

func TestExtractTechniqueValidation(t *testing.T) {
	res := pipeline.SubmissionResult{Findings: []pipeline.Finding{
		{Attck: " t1059.003 "},
		{Attck: "T1071"},
		{Attck: "T1071"},   // duplicate
		{Attck: "T99"},     // too short
		{Attck: "T123456"}, // too long
		{Attck: "T1059.3"}, // malformed subtechnique
		{Attck: "bogus"},
	}}
	ex := extract(res)
	want := []string{"T1059.003", "T1071"}
	if len(ex.techniques) != len(want) {
		t.Fatalf("techniques = %v, want %v", ex.techniques, want)
	}
	for i, w := range want {
		if ex.techniques[i] != w {
			t.Fatalf("techniques = %v, want %v", ex.techniques, want)
		}
	}
}

func TestIOCCapIsSurfacedNotSilent(t *testing.T) {
	var b strings.Builder
	for i := 0; i < maxIOCsPerKind+50; i++ {
		fmt.Fprintf(&b, "d%03d.badcorp.example ", i)
	}
	res := pipeline.SubmissionResult{
		SubmissionID: "sub-cap",
		SHA256:       testSHA,
		Verdict:      pipeline.Suspicious,
		Score:        55,
		Findings: []pipeline.Finding{
			{Engine: "mal-detonate", Type: "dns", Detail: b.String(),
				Verdict: pipeline.Suspicious, Confidence: pipeline.ConfMedium},
		},
	}
	ex := extract(res)
	if !ex.truncated {
		t.Fatalf("cap overflow not marked truncated")
	}
	domains := 0
	for _, c := range ex.iocs {
		if c.kind == kindDomain {
			domains++
		}
	}
	if domains != maxIOCsPerKind {
		t.Fatalf("kept %d domains, want %d", domains, maxIOCsPerKind)
	}

	stix, err := ToSTIX(res)
	if err != nil {
		t.Fatalf("ToSTIX: %v", err)
	}
	if !strings.Contains(string(stix), `"x_openmallab_ioc_truncated": true`) {
		t.Errorf("stix export hides the ioc truncation")
	}
	misp, err := ToMISP(res)
	if err != nil {
		t.Fatalf("ToMISP: %v", err)
	}
	if !strings.Contains(string(misp), "openmallab:ioc-truncated") {
		t.Errorf("misp export hides the ioc truncation")
	}
}

func TestOversizeURLDropIsSurfaced(t *testing.T) {
	long := "http://big.badcorp.example/" + strings.Repeat("a", maxURLLen)
	res := pipeline.SubmissionResult{
		Verdict:  pipeline.Suspicious,
		Findings: []pipeline.Finding{{Engine: "mal-detonate", Type: "net-connect", Detail: "fetched " + long}},
	}
	ex := extract(res)
	if !ex.truncated {
		t.Fatalf("oversize url drop was not surfaced as truncation")
	}
	hostSalvaged := false
	for _, c := range ex.iocs {
		if c.kind == kindURL {
			t.Fatalf("oversize url was exported (%d bytes)", len(c.value))
		}
		if c.kind == kindDomain && c.value == "big.badcorp.example" {
			hostSalvaged = true
		}
	}
	if !hostSalvaged {
		t.Fatalf("host was not salvaged from the oversize url; got %v", ex.iocs)
	}
}

// the package promises id stability across releases (export.go): these are
// known answers, not shape checks. if one fails, the change broke every
// downstream consumer's dedup; update a pin only when that break is
// intended and called out in the commit.
func TestGoldenIDsAndBytes(t *testing.T) {
	if got, want := uuidv5("x"), "72c3d5d8-17c7-57a4-b4b5-7c50a689f7e2"; got != want {
		t.Errorf("uuidv5(x) = %s, want %s", got, want)
	}
	if got, want := identityID, "identity--3b8430b4-1406-5698-a970-bb40e035def2"; got != want {
		t.Errorf("identityID = %s, want %s", got, want)
	}
	if got, want := fileID(maliciousResult(), testSHA), "file--a7928fbf-e7c8-52e1-9d22-c8c4d008ad01"; got != want {
		t.Errorf("file sco id = %s, want %s", got, want)
	}
	stix, err := ToSTIX(maliciousResult())
	if err != nil {
		t.Fatalf("ToSTIX: %v", err)
	}
	if got, want := fmt.Sprintf("%x", sha256.Sum256(stix)), "d21706b5660a8e62c4a25db93a04f5ccbfdb4574be7985f8d7bee43e8e3836d1"; got != want {
		t.Errorf("stix bundle bytes drifted: sha256 = %s, want %s", got, want)
	}
	misp, err := ToMISP(maliciousResult())
	if err != nil {
		t.Fatalf("ToMISP: %v", err)
	}
	if got, want := fmt.Sprintf("%x", sha256.Sum256(misp)), "d88931ad5ce53d7fcc9381b1c0b371b0de0d66cf41eead4becc2f8f7e49a7aec"; got != want {
		t.Errorf("misp event bytes drifted: sha256 = %s, want %s", got, want)
	}
}

func TestUUIDv5DeterministicShape(t *testing.T) {
	a, b := uuidv5("x"), uuidv5("x")
	if a != b {
		t.Fatalf("uuidv5 is not deterministic: %s vs %s", a, b)
	}
	if a == uuidv5("y") {
		t.Fatalf("distinct names collided")
	}
	if !regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-5[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`).MatchString(a) {
		t.Fatalf("uuidv5 %q has the wrong shape", a)
	}
}
