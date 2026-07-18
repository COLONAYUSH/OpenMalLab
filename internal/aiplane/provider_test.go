package aiplane

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/COLONAYUSH/OpenMalLab/internal/knowledge"
)

func TestAnalystRoundTripAccepts(t *testing.T) {
	r := knowledge.NewRegistry(knowledge.NewMemStore())
	f, err := r.Curate(knowledge.KindAttck, "T1055", "Process Injection", nil, "seed")
	if err != nil {
		t.Fatal(err)
	}
	// a model response citing the curated fact, on an allow-listed kind.
	raw := []byte(fmt.Sprintf(
		`{"summary":"injects code into a remote process","hypotheses":[{"kind":"technique","claim":"process injection","confidence":"LOW","citations":[{"fact_id":%q,"kind":"attck","key":"T1055"}]}]}`,
		f.ID))

	res, err := NewAnalyst(MockProvider{Raw: raw}, NewGate(r)).
		Analyze(context.Background(), Evidence{SubmissionID: "sub-1"})
	if err != nil {
		t.Fatalf("round trip failed: %v", err)
	}
	if res.SubmissionID != "sub-1" {
		t.Fatalf("submission id not from evidence: %q", res.SubmissionID)
	}
	if len(res.Hypotheses) != 1 || res.Hypotheses[0].Disposition != DispAccept {
		t.Fatalf("grounded hypothesis should accept end-to-end: %+v", res.Hypotheses)
	}
}

func TestAnalystFailsClosedOnHostileOutput(t *testing.T) {
	r := knowledge.NewRegistry(knowledge.NewMemStore())
	gate := NewGate(r)
	cases := map[string][]byte{
		"invalid json":  []byte("{not json"),
		"unknown field": []byte(`{"summary":"x","evil":1}`),
		"empty object":  []byte("{}"),
		"trailing data": []byte(`{"summary":"x"}{"more":1}`),
		"oversize":      make([]byte, maxProposalBytes+1),
	}
	for name, raw := range cases {
		if _, err := NewAnalyst(MockProvider{Raw: raw}, gate).Analyze(context.Background(), Evidence{}); err == nil {
			t.Fatalf("%s: hostile output must fail closed at Validate", name)
		}
	}
}

func TestAnalystPropagatesProviderError(t *testing.T) {
	gate := NewGate(knowledge.NewRegistry(knowledge.NewMemStore()))
	_, err := NewAnalyst(MockProvider{Err: fmt.Errorf("model down")}, gate).Analyze(context.Background(), Evidence{})
	if err == nil {
		t.Fatal("provider error must propagate")
	}
}

func TestAnalystUnconfigured(t *testing.T) {
	if _, err := (&Analyst{}).Analyze(context.Background(), Evidence{}); err == nil {
		t.Fatal("unconfigured analyst must error")
	}
}

func TestHTTPProviderRoundTrip(t *testing.T) {
	var gotBody string
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		b, _ := io.ReadAll(req.Body)
		gotBody = string(b)
		content := `{"summary":"a downloader","needs_review":true}`
		env := chatResponse{Choices: []struct {
			Message chatMessage `json:"message"`
		}{{Message: chatMessage{Role: "assistant", Content: content}}}}
		_ = json.NewEncoder(w).Encode(env)
	}))
	defer ts.Close()

	// the LOCAL provider sends the full defanged evidence (loopback httptest URL).
	p, err := NewLocalProvider(ts.URL, "test-model")
	if err != nil {
		t.Fatalf("local provider (loopback httptest): %v", err)
	}
	raw, err := p.Analyze(context.Background(), Evidence{SubmissionID: "s", Items: []EvidenceItem{{Detail: "x"}}})
	if err != nil {
		t.Fatalf("http provider: %v", err)
	}
	if strings.TrimSpace(string(raw)) != `{"summary":"a downloader","needs_review":true}` {
		t.Fatalf("content not returned raw: %q", raw)
	}
	// inspect the DECODED request (what the model actually sees): the system prompt
	// is message 0, and the evidence is carried as DATA in a delimited block in the
	// user message - never concatenated into the instruction.
	var sent chatRequest
	if err := json.Unmarshal([]byte(gotBody), &sent); err != nil {
		t.Fatalf("request body not decodable: %v", err)
	}
	if len(sent.Messages) != 2 || !strings.Contains(sent.Messages[0].Content, "containment-aware") {
		t.Fatalf("system prompt missing: %+v", sent.Messages)
	}
	if !strings.Contains(sent.Messages[1].Content, "<EVIDENCE>") || !strings.Contains(sent.Messages[1].Content, "submission_id") {
		t.Fatalf("evidence not carried as delimited data: %q", sent.Messages[1].Content)
	}
	// and the returned bytes still pass the contract.
	if _, err := Validate(raw); err != nil {
		t.Fatalf("returned content should validate: %v", err)
	}
}

func TestHTTPProviderErrors(t *testing.T) {
	// non-200 fails closed.
	bad := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer bad.Close()
	if _, err := NewCloudProvider(bad.URL, "m").Analyze(context.Background(), Evidence{}); err == nil {
		t.Fatal("non-200 must error")
	}
	// no choices fails closed.
	empty := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"choices":[]}`))
	}))
	defer empty.Close()
	if _, err := NewCloudProvider(empty.URL, "m").Analyze(context.Background(), Evidence{}); err == nil {
		t.Fatal("empty choices must error")
	}
}

func TestCloudProviderMinimizesEgress(t *testing.T) {
	var body string
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		b, _ := io.ReadAll(req.Body)
		body = string(b)
		env := chatResponse{Choices: []struct {
			Message chatMessage `json:"message"`
		}{{Message: chatMessage{Content: `{"summary":"x"}`}}}}
		_ = json.NewEncoder(w).Encode(env)
	}))
	defer ts.Close()

	ev := Evidence{
		SubmissionID: "sub-secret-id", SHA256: "deadbeefdeadbeef", FileType: "pebin", Verdict: "MALICIOUS",
		Items: []EvidenceItem{{Engine: "mal-floss", Type: "decoded-string", Detail: "beacon acme-secret-c2-host", Verdict: "UNKNOWN", Path: "outer.zip!inner.exe"}},
	}
	if _, err := NewCloudProvider(ts.URL, "m").Analyze(context.Background(), ev); err != nil {
		t.Fatal(err)
	}
	// the egress gate withholds hostile-derived free text AND sample identity.
	for _, leaked := range []string{"acme-secret-c2-host", "outer.zip", "sub-secret-id", "deadbeefdeadbeef"} {
		if strings.Contains(body, leaked) {
			t.Fatalf("cloud egress leaked %q: %s", leaked, body)
		}
	}
	// but the structured fields reasoning needs still cross.
	if !strings.Contains(body, "mal-floss") || !strings.Contains(body, "MALICIOUS") {
		t.Fatalf("cloud egress dropped needed structured fields: %s", body)
	}
}

func TestLocalProviderLoopbackGuard(t *testing.T) {
	ok := []string{"http://127.0.0.1:8000", "http://localhost:1234/v1", "http://[::1]:8000"}
	for _, u := range ok {
		if _, err := NewLocalProvider(u, "m"); err != nil {
			t.Fatalf("loopback %q should be allowed: %v", u, err)
		}
	}
	bad := []string{"http://evil.example.com", "http://10.0.0.5:8000", "https://api.openai.com", "http://169.254.169.254"}
	for _, u := range bad {
		if _, err := NewLocalProvider(u, "m"); err == nil {
			t.Fatalf("non-loopback %q must be refused by the local provider", u)
		}
	}
}
