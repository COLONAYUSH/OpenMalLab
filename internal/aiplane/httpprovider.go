package aiplane

// HTTPProvider is a Provider for an OpenAI-compatible chat-completions endpoint,
// which is what a local vLLM server exposes and what most cloud model gateways
// speak. it is air-gapped by default: NewLocalProvider refuses any non-loopback
// host, and reaching the outside is a separate, explicit act (NewCloudProvider).
// so an air-gapped build simply never constructs a cloud provider - egress is a
// code-level decision, not a config typo.

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// HTTPProvider talks to an OpenAI-compatible /v1/chat/completions endpoint.
type HTTPProvider struct {
	baseURL  string
	model    string
	client   *http.Client
	system   string
	minimize bool // cloud egress gate: send only minimized evidence, never raw hostile bytes
}

// NewLocalProvider builds a provider for a SOVEREIGN, OpenAI-compatible model
// server: one reachable only on the box or a no-egress private network (loopback
// like vLLM on 127.0.0.1, a private/link-local IP, or a dotless container/service
// name like "ollama" on an internal compose network). it refuses a public FQDN or
// public IP: reaching the outside world is a separate, explicit opt-in via
// NewCloudProvider, so the platform stays air-gapped by default and a misconfigured
// URL fails closed rather than quietly shipping evidence off-box.
func NewLocalProvider(baseURL, model string) (*HTTPProvider, error) {
	if err := requireSovereignHost(baseURL); err != nil {
		return nil, err
	}
	return newHTTP(baseURL, model), nil
}

// NewCloudProvider builds a provider that MAY reach a non-loopback host. it is the
// guarded escape hatch: calling it is the explicit acknowledgement that this
// analyst talks to the outside world. the operator remains responsible for egress
// allow-listing at the network layer; this constructor is the code-level opt-in.
func NewCloudProvider(baseURL, model string) *HTTPProvider {
	p := newHTTP(baseURL, model)
	p.minimize = true // a cloud model only ever sees minimized, redacted evidence
	return p
}

// minimizeEvidence is the cloud egress gate (design sec 10/11): a cloud model only
// receives the structured, minimized fields reasoning needs - NEVER the raw,
// hostile-derived free text (detail/path) and never the sample identity
// (submission id / sha256). local providers send the full, defanged evidence.
func minimizeEvidence(ev Evidence) Evidence {
	m := Evidence{
		FileType:   ev.FileType,
		Verdict:    ev.Verdict,
		Score:      ev.Score,
		Confidence: ev.Confidence,
		Incomplete: ev.Incomplete,
	}
	for _, it := range ev.Items {
		m.Items = append(m.Items, EvidenceItem{
			Engine:     it.Engine,
			Type:       it.Type,
			Attck:      it.Attck,
			Verdict:    it.Verdict,
			Confidence: it.Confidence,
			// Detail and Path (hostile-derived bytes) are withheld from cloud egress
		})
	}
	return m
}

func newHTTP(baseURL, model string) *HTTPProvider {
	return &HTTPProvider{
		baseURL: strings.TrimRight(baseURL, "/"),
		model:   model,
		client:  &http.Client{Timeout: 120 * time.Second},
		system:  AnalystSystemPrompt,
	}
}

// requireSovereignHost rejects a base URL whose host could reach off the box / LAN.
// a host is SOVEREIGN (no explicit cloud opt-in needed) when it is loopback, an
// RFC1918 / ULA private IP (a container or LAN address on a no-egress network), or
// a hostname that is dotless (a container / compose service name like "ollama",
// never a public FQDN) or an internal suffix (.local / .internal / .lan). a dotted
// public FQDN or a public IP is refused here; that egress is the explicit
// NewCloudProvider opt-in. link-local (169.254 / fe80) is deliberately NOT
// sovereign - it is the cloud-metadata SSRF vector, never a real model host.
func requireSovereignHost(raw string) error {
	u, err := url.Parse(raw)
	if err != nil {
		return fmt.Errorf("aiplane: bad base url: %w", err)
	}
	host := u.Hostname()
	if host == "" {
		return fmt.Errorf("aiplane: base url has no host: %q", raw)
	}
	if strings.EqualFold(host, "localhost") {
		return nil
	}
	if ip := net.ParseIP(host); ip != nil {
		if isSovereignIP(ip) {
			return nil
		}
		return fmt.Errorf("aiplane: local provider requires a loopback/private host, got public IP %q (use NewCloudProvider to allow egress)", host)
	}
	if isSovereignHostname(host) {
		return nil
	}
	return fmt.Errorf("aiplane: local provider requires a loopback/private/container host, got %q (use NewCloudProvider to allow egress)", host)
}

// isSovereignIP is true for addresses confined to the box or a no-egress private
// network: loopback and RFC1918/ULA private. link-local is excluded on purpose
// (169.254.169.254 is the cloud-metadata SSRF target, never a real model host).
func isSovereignIP(ip net.IP) bool {
	return ip.IsLoopback() || ip.IsPrivate()
}

// isSovereignHostname treats a dotless single-label name (a container/compose
// service like "ollama") or an internal-suffix name as sovereign; a dotted public
// FQDN is not.
func isSovereignHostname(host string) bool {
	h := strings.ToLower(host)
	if !strings.Contains(h, ".") {
		return true
	}
	return strings.HasSuffix(h, ".local") || strings.HasSuffix(h, ".internal") || strings.HasSuffix(h, ".lan")
}

// Name identifies the provider in errors and the handshake ledger.
func (h *HTTPProvider) Name() string { return "http:" + h.model }

type chatMessage struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

type chatRequest struct {
	Model       string        `json:"model"`
	Messages    []chatMessage `json:"messages"`
	Temperature float64       `json:"temperature"`
	Stream      bool          `json:"stream"`
}

type chatResponse struct {
	Choices []struct {
		Message chatMessage `json:"message"`
	} `json:"choices"`
}

// Analyze marshals the (already defanged, bounded) evidence and sends it to the
// model as DATA inside a delimited block - never concatenated into the system
// instruction. the response body read is length-bounded so a hostile or runaway
// model cannot exhaust memory; whatever content comes back is returned raw for
// Validate to judge.
func (h *HTTPProvider) Analyze(ctx context.Context, ev Evidence) ([]byte, error) {
	payload := ev
	if h.minimize {
		payload = minimizeEvidence(ev) // cloud egress: strip hostile bytes + identity
	}
	evJSON, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("aiplane: marshal evidence: %w", err)
	}
	user := "<EVIDENCE>\n" + string(evJSON) + "\n</EVIDENCE>\nReturn ONLY the JSON proposal object."
	reqBody, err := json.Marshal(chatRequest{
		Model:       h.model,
		Temperature: 0,
		Messages: []chatMessage{
			{Role: "system", Content: h.system},
			{Role: "user", Content: user},
		},
	})
	if err != nil {
		return nil, fmt.Errorf("aiplane: marshal request: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, h.baseURL+"/v1/chat/completions", bytes.NewReader(reqBody))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := h.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("aiplane: request: %w", err)
	}
	defer resp.Body.Close()
	// bound the read: model output above the proposal cap is rejected anyway, and
	// this stops a hostile endpoint from streaming unbounded bytes at us.
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxProposalBytes+1))
	if err != nil {
		return nil, fmt.Errorf("aiplane: read response: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("aiplane: model returned status %d", resp.StatusCode)
	}
	var cr chatResponse
	if err := json.Unmarshal(body, &cr); err != nil {
		return nil, fmt.Errorf("aiplane: decode response envelope: %w", err)
	}
	if len(cr.Choices) == 0 {
		return nil, fmt.Errorf("aiplane: model returned no choices")
	}
	return []byte(cr.Choices[0].Message.Content), nil
}
