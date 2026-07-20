package export

import (
	"net"
	"net/url"
	"regexp"
	"sort"
	"strings"

	"github.com/COLONAYUSH/OpenMalLab/internal/pipeline"
)

// iocKind orders the export: hash first, then names, addresses, urls. the
// fixed rank plus a value sort is what keeps the output deterministic no
// matter which engine reported first.
type iocKind int

const (
	kindSHA256 iocKind = iota
	kindDomain
	kindIPv4
	kindIPv6
	kindURL
)

func (k iocKind) String() string {
	switch k {
	case kindSHA256:
		return "sha256"
	case kindDomain:
		return "domain"
	case kindIPv4:
		return "ipv4"
	case kindIPv6:
		return "ipv6"
	default:
		return "url"
	}
}

type ioc struct {
	kind  iocKind
	value string
}

const (
	// maxIOCsPerKind bounds what one submission can export. a hostile sample
	// can stuff thousands of lookalike strings into its own bytes; the cap
	// keeps the export bounded, and the truncation is surfaced in both
	// formats, never silent.
	maxIOCsPerKind = 128

	// maxParsedDetail bounds regex work on any single finding detail. broker
	// caps bound details long before this; it exists so this package stays
	// safe even if it is ever fed unbrokered input.
	maxParsedDetail = 16 << 10

	// maxURLLen bounds one exported url value. a longer candidate is hostile
	// padding; its host is still exported and the drop is surfaced.
	maxURLLen = 2048
)

// extraction is everything exportable that was pulled out of one result.
type extraction struct {
	iocs       []ioc
	techniques []string
	truncated  bool
}

// networkish reports whether a finding type plausibly carries network
// observables in its detail: engine ioc types (domain, url, dns), the
// detonation network types (net-connect), and yara matches whose rule
// strings often embed c2 endpoints. everything else (paths, hashes,
// capability names) is skipped, so a file write to /etc/rc.local never gets
// mined for lookalike domains.
func networkish(findingType string) bool {
	t := strings.ToLower(findingType)
	for _, marker := range []string{"net", "dns", "url", "domain", "http", "c2", "beacon", "ioc", "yara", "deton"} {
		if strings.Contains(t, marker) {
			return true
		}
	}
	return false
}

// engines defang anything attacker-controlled before it reaches a finding
// detail (hxxp, [.], and friends; see services/mal-detonate/wrapper.py), and
// third-party rule metadata often arrives pre-defanged too. refang undoes
// the common schemes so the export carries machine-usable values; what
// actually counts as an ioc is decided by the validators below, never by
// the hostile text itself.
var refangSteps = []struct {
	re  *regexp.Regexp
	rep string
}{
	{regexp.MustCompile(`(?i)hxxps`), "https"},
	{regexp.MustCompile(`(?i)hxxp`), "http"},
	{regexp.MustCompile(`(?i)\[\s*:\s*//\s*\]`), "://"},
	{regexp.MustCompile(`(?i)\[\s*\.\s*\]|\(\s*\.\s*\)|\{\s*\.\s*\}|\[dot\]|\(dot\)`), "."},
	{regexp.MustCompile(`(?i)\[\s*:\s*\]`), ":"},
	{regexp.MustCompile(`(?i)\[\s*at\s*\]|\(\s*at\s*\)`), "@"},
}

func refang(s string) string {
	for _, step := range refangSteps {
		s = step.re.ReplaceAllString(s, step.rep)
	}
	return s
}

var (
	urlRe = regexp.MustCompile(`(?i)\bhttps?://[a-z0-9._~:/?#@!$&'()*+,;=%\[\]-]+`)

	// schemeHostRe catches host material behind NON-http schemes (ftp, tcp,
	// ws, ...) that urlRe deliberately skips. only the host is exported from
	// these, never a url ioc.
	schemeHostRe = regexp.MustCompile(`(?i)\b[a-z][a-z0-9+.-]{1,15}://[^\s"'<>]+`)

	// ipv4 candidates: a dotted quad preceded by nothing token-ish; the
	// trailing context is checked in code so the head of a longer token
	// (1.2.3.4.5, 8.8.8.8.evil.example, v1.2.3.4b) is never torn off and
	// exported as an address.
	ipv4Re = regexp.MustCompile(`(?:^|[^0-9A-Za-z._-])((?:[0-9]{1,3}\.){3}[0-9]{1,3})`)

	// domain candidates: dotted labels with an alphabetic tld, not preceded
	// by a path separator (unix or windows) or a mid-token character.
	// trailing context is checked in code (libc.so out of libc.so.6 is not
	// a domain).
	domainRe = regexp.MustCompile(`(?i)(?:^|[^a-z0-9._/\\-])((?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,24})`)

	// domainShapeRe re-checks the full shape when a candidate arrives whole
	// (a url hostname) instead of torn out of prose.
	domainShapeRe = regexp.MustCompile(`^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,24}$`)

	attckRe = regexp.MustCompile(`^T[0-9]{4}(?:\.[0-9]{3})?$`)

	// sha256TokenRe pulls a whole 64-hex token out of an artifact-sha256
	// detail. word boundaries mean half of a sha-512 can never match.
	sha256TokenRe = regexp.MustCompile(`(?i)\b[0-9a-f]{64}\b`)
)

// fileExtTLDs are final labels that read as file extensions in tool output
// far more often than as real tlds. some (.sh, .py, .pl, .run) are genuine
// tlds, but losing the rare c2 hosted there beats exporting every script
// path and dropper filename as an indicator: a wrong entry pushed into a
// soc blocklist does real harm.
var fileExtTLDs = map[string]bool{
	"apk": true, "arpa": true, "asp": true, "aspx": true, "avi": true,
	"bak": true, "bash": true, "bat": true, "bin": true, "bmp": true,
	"cab": true, "cfg": true, "chm": true, "class": true, "cmd": true,
	"conf": true, "core": true, "cpl": true, "cpp": true, "crt": true,
	"cs": true, "css": true, "csv": true, "dat": true, "db": true,
	"deb": true, "desktop": true, "dll": true, "dmg": true, "doc": true,
	"docm": true, "docx": true, "dotm": true, "drv": true, "dylib": true,
	"elf": true, "exe": true, "gif": true, "go": true, "gz": true,
	"hpp": true, "hta": true, "htm": true, "html": true, "ico": true,
	"img": true, "inf": true, "ini": true, "internal": true, "iso": true,
	"jar": true, "jpeg": true, "jpg": true, "js": true, "jse": true,
	"json": true, "jsp": true, "ko": true, "lan": true, "lnk": true,
	"local": true, "localdomain": true, "log": true, "md": true,
	"mp3": true, "mp4": true, "msi": true, "msu": true, "mui": true,
	"ocx": true, "old": true, "out": true, "pdf": true, "pem": true,
	"php": true, "pif": true, "pkg": true, "pl": true, "plist": true,
	"png": true, "ppt": true, "pptm": true, "pptx": true, "py": true,
	"pyc": true, "rar": true, "rb": true, "reg": true, "rpm": true,
	"rs": true, "rtf": true, "run": true, "scr": true, "sct": true,
	"service": true, "sh": true, "so": true, "socket": true, "sql": true,
	"svg": true, "sys": true, "tar": true, "tgz": true, "tmp": true,
	"toml": true, "ts": true, "txt": true, "vbe": true, "vbs": true,
	"war": true, "wav": true, "wsf": true, "xls": true, "xlsm": true,
	"xlsx": true, "xml": true, "xz": true, "yaml": true, "yml": true,
	"zip": true,
}

// validDomain is the last gate before a dotted token becomes an ioc. the
// shape (label charset, lengths, alphabetic tld) is enforced by the regexes;
// this adds the semantic checks.
func validDomain(d string) bool {
	if len(d) < 4 || len(d) > 253 {
		return false
	}
	labels := strings.Split(d, ".")
	if len(labels) < 2 {
		return false
	}
	return !fileExtTLDs[labels[len(labels)-1]]
}

// trimIOC strips the punctuation a value drags along when torn out of prose
// ("see http://x/y)." style).
func trimIOC(s string) string {
	return strings.TrimRight(s, `.,;:!?)]}'"`)
}

// admissibleIP decides whether an address could be a remote indicator.
// loopback, private, cgnat, reserved, and link-local noise would teach a
// soc to block itself, and the qemu-user slirp network (10.0.2.x) lives
// inside private space, so detonation plumbing can never leak into an
// export. IsGlobalUnicast alone covers unspecified, loopback, multicast,
// link-local, and the v4 broadcast; the v4 switch adds the ranges go does
// not classify.
func admissibleIP(ip net.IP) bool {
	if ip == nil || !ip.IsGlobalUnicast() || ip.IsPrivate() {
		return false
	}
	if v4 := ip.To4(); v4 != nil {
		switch {
		case v4[0] == 0: // 0.0.0.0/8 "this network"
			return false
		case v4[0] == 100 && v4[1]&0xc0 == 64: // 100.64.0.0/10 cgnat
			return false
		case v4[0] == 192 && v4[1] == 0 && v4[2] == 0: // 192.0.0.0/24 ietf
			return false
		case v4[0] >= 240: // 240.0.0.0/4 reserved
			return false
		}
	}
	return true
}

func addIP(ip net.IP, add func(ioc)) {
	if !admissibleIP(ip) {
		return
	}
	if v4 := ip.To4(); v4 != nil {
		add(ioc{kindIPv4, v4.String()})
		return
	}
	add(ioc{kindIPv6, ip.String()})
}

// addURL vets one refanged url candidate. the HOST is judged first, by the
// same rules as a bare address or name: a url whose host we would filter
// (loopback, rfc1918, the slirp gateway, a garbage token) must not ride
// into the export just because it wears a scheme. only when the host is
// itself exportable does the url become an ioc too, and the host is added
// alongside it so the blockable atom always survives.
func addURL(raw string, add func(ioc), mark func()) {
	raw = trimIOC(raw)
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return
	}
	scheme := strings.ToLower(u.Scheme)
	if scheme != "http" && scheme != "https" {
		return
	}
	u.Scheme = scheme
	u.Host = strings.ToLower(u.Host)
	host := u.Hostname()
	if ip := net.ParseIP(host); ip != nil {
		if !admissibleIP(ip) {
			return
		}
		addIP(ip, add)
	} else if domainShapeRe.MatchString(host) && validDomain(host) {
		add(ioc{kindDomain, host})
	} else {
		return
	}
	if len(raw) > maxURLLen {
		mark() // hostile padding: the host survived, the drop is surfaced
		return
	}
	add(ioc{kindURL, u.String()})
}

// scanIPv6 finds v6 addresses with a token pass rather than a regex:
// free-text ipv6 matching is hopelessly noisy, and net.ParseIP is the only
// judge that counts.
func scanIPv6(s string, add func(ioc)) {
	for _, tok := range strings.FieldsFunc(s, func(r rune) bool {
		return !(r == ':' || r == '.' || ('0' <= r && r <= '9') ||
			('a' <= r && r <= 'f') || ('A' <= r && r <= 'F'))
	}) {
		if strings.Count(tok, ":") < 2 {
			continue
		}
		tok = strings.TrimRight(tok, ".:")
		ip := net.ParseIP(tok)
		if ip == nil && len(tok) > 1 && tok[0] == ':' && tok[1] != ':' {
			ip = net.ParseIP(tok[1:]) // shed one leading colon from prose like "at:2001:db8::1"
		}
		if ip != nil && ip.To4() == nil {
			addIP(ip, add)
		}
	}
}

func isWordish(c byte) bool {
	return c == '-' || c == '_' || ('0' <= c && c <= '9') ||
		('a' <= c && c <= 'z') || ('A' <= c && c <= 'Z')
}

func byteAt(s string, i int) byte {
	if i < len(s) {
		return s[i]
	}
	return 0
}

// tokenBoundary rejects a candidate that is really the head of a longer
// token: "libc.so" out of "libc.so.6", "8.8.8.8" out of
// "8.8.8.8.evil.example", "1.2.3.4" out of "v1.2.3.4b". a plain sentence
// period after the value is fine.
func tokenBoundary(c, next byte) bool {
	if isWordish(c) {
		return false
	}
	if c == '.' && isWordish(next) {
		return false
	}
	return true
}

// previewCut reports whether a candidate ends exactly where the yara
// engine's bounded match preview was cut ("..): the value is provably
// incomplete and exporting the fragment would arm a wrong indicator.
func previewCut(s string, end int) bool {
	return byteAt(s, end) == '"' && byteAt(s, end+1) == '.' && byteAt(s, end+2) == '.'
}

// yaraStripMeta removes the rule-metadata segments from a yara evidence
// detail before mining. description and reference carry the rule AUTHOR'S
// prose and threat-intel links (see evidence() in services/mal-static-yara);
// exporting a vendor blog url as attack infrastructure would poison the
// feed with exactly the kind of entry a soc trusts us never to ship. the
// matched-pattern section after the first " | " is what the sample itself
// contained, so that is what gets mined.
func yaraStripMeta(detail string) string {
	head, tail := detail, ""
	if i := strings.Index(detail, " | "); i >= 0 {
		head, tail = detail[:i], detail[i:]
	}
	for _, marker := range []string{" - description: ", " - reference: "} {
		if i := strings.Index(head, marker); i >= 0 {
			head = head[:i]
		}
	}
	return head + tail
}

// parseDetail mines one refanged detail string for network observables.
func parseDetail(s string, add func(ioc), mark func()) {
	for _, idx := range urlRe.FindAllStringIndex(s, -1) {
		if previewCut(s, idx[1]) {
			continue
		}
		addURL(s[idx[0]:idx[1]], add, mark)
	}
	for _, idx := range ipv4Re.FindAllStringSubmatchIndex(s, -1) {
		start, end := idx[2], idx[3]
		if end < len(s) && !tokenBoundary(s[end], byteAt(s, end+1)) {
			continue
		}
		if previewCut(s, end) {
			continue
		}
		if ip := net.ParseIP(s[start:end]); ip != nil {
			addIP(ip, add)
		}
	}
	scanIPv6(s, add)
	for _, idx := range schemeHostRe.FindAllStringIndex(s, -1) {
		if previewCut(s, idx[1]) {
			continue
		}
		u, err := url.Parse(trimIOC(s[idx[0]:idx[1]]))
		if err != nil || u.Host == "" {
			continue
		}
		host := strings.ToLower(u.Hostname())
		if net.ParseIP(host) != nil {
			continue // the address passes above are the judges for ip hosts
		}
		if domainShapeRe.MatchString(host) && validDomain(host) {
			add(ioc{kindDomain, host})
		}
	}
	for _, idx := range domainRe.FindAllStringSubmatchIndex(s, -1) {
		start, end := idx[2], idx[3]
		if end < len(s) && !tokenBoundary(s[end], byteAt(s, end+1)) {
			continue
		}
		if previewCut(s, end) {
			continue
		}
		d := strings.ToLower(s[start:end])
		if validDomain(d) {
			add(ioc{kindDomain, d})
		}
	}
}

// extract pulls every exportable observable out of a result: the sample and
// child-artifact hashes, validated att&ck technique ids, and network iocs
// parsed defensively out of network-ish finding details. everything is
// deduped, sorted, and capped, so the export stays deterministic and
// bounded no matter what a hostile sample stuffed into its strings.
func extract(res pipeline.SubmissionResult) extraction {
	var ex extraction
	seen := map[ioc]bool{}
	techniques := map[string]bool{}
	add := func(c ioc) {
		if c.value == "" || seen[c] {
			return
		}
		seen[c] = true
		ex.iocs = append(ex.iocs, c)
	}
	mark := func() { ex.truncated = true }
	if sha := sampleSHA(res); sha != "" {
		add(ioc{kindSHA256, sha})
	}
	for _, f := range res.Findings {
		if t := strings.ToUpper(strings.TrimSpace(f.Attck)); t != "" && attckRe.MatchString(t) {
			techniques[t] = true
		}
		// extracted children get their own hash iocs: the bundled payload's
		// sha-256 is the ioc a soc actually blocklists, not just the outer
		// container's. the orchestrator re-hashes staged bytes before writing
		// these findings, but the value is still parsed, never trusted.
		if f.Type == "artifact-sha256" {
			for _, h := range sha256TokenRe.FindAllString(f.Detail, -1) {
				add(ioc{kindSHA256, strings.ToLower(h)})
			}
			continue
		}
		if !networkish(f.Type) {
			continue
		}
		detail := f.Detail
		if f.Type == "yara" {
			detail = yaraStripMeta(detail)
		}
		if len(detail) > maxParsedDetail {
			detail = detail[:maxParsedDetail]
			ex.truncated = true
		}
		parseDetail(refang(detail), add, mark)
	}
	for t := range techniques {
		ex.techniques = append(ex.techniques, t)
	}
	sort.Strings(ex.techniques)
	sort.Slice(ex.iocs, func(i, j int) bool {
		if ex.iocs[i].kind != ex.iocs[j].kind {
			return ex.iocs[i].kind < ex.iocs[j].kind
		}
		return ex.iocs[i].value < ex.iocs[j].value
	})
	ex.iocs, ex.truncated = capPerKind(ex.iocs, ex.truncated)
	return ex
}

func capPerKind(iocs []ioc, truncated bool) ([]ioc, bool) {
	counts := map[iocKind]int{}
	kept := iocs[:0]
	for _, c := range iocs {
		if counts[c.kind] >= maxIOCsPerKind {
			truncated = true
			continue
		}
		counts[c.kind]++
		kept = append(kept, c)
	}
	return kept, truncated
}
