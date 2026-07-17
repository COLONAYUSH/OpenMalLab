// mal-gateway is the front door. it takes a submission over http, stores the
// bytes content-addressed, and starts a durable SubmissionWorkflow on temporal.
// it never parses the hostile bytes itself: it only hashes and stores them.
// oidc auth, opa, the tamper-evident audit log, and the real vault land next.
package main

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/COLONAYUSH/OpenMalLab/internal/pipeline"
	"go.temporal.io/api/enums/v1"
	"go.temporal.io/api/workflowservice/v1"
	"go.temporal.io/sdk/client"
)

const (
	taskQueue      = "openmallab-m0"
	workflowName   = "SubmissionWorkflow"
	maxUploadBytes = 256 << 20 // 256 MiB cap so a huge upload cannot exhaust the box
	maxFilename    = 255       // hostile input: cap it, and it is defanged on display
	queueSize      = 60        // most recent submissions shown in the triage queue
)

func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func newID() string {
	b := make([]byte, 8)
	_, _ = rand.Read(b)
	return "sub-" + hex.EncodeToString(b)
}

type server struct {
	tc    client.Client
	vault string // scratch vault dir (the real envelope-encrypted WORM vault comes next)
}

func (s *server) handleSubmit(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxUploadBytes)
	f, hdr, err := r.FormFile("file")
	if err != nil {
		http.Error(w, "expected multipart field 'file'", http.StatusBadRequest)
		return
	}
	defer f.Close()

	// the submitted filename is hostile input. keep only its base name, bound
	// the length, and never trust it as a path; the console defangs it too.
	name := ""
	if hdr != nil {
		name = filepath.Base(hdr.Filename)
		if len(name) > maxFilename {
			name = name[:maxFilename]
		}
	}

	// stream to a temp file while hashing. we do not read the bytes as anything
	// other than opaque data here.
	tmp, err := os.CreateTemp(s.vault, "incoming-*")
	if err != nil {
		http.Error(w, "storage error", http.StatusInternalServerError)
		return
	}
	tmpName := tmp.Name()
	h := sha256.New()
	if _, err := io.Copy(io.MultiWriter(tmp, h), f); err != nil {
		tmp.Close()
		os.Remove(tmpName)
		http.Error(w, "read error", http.StatusBadRequest)
		return
	}
	tmp.Close()
	sum := hex.EncodeToString(h.Sum(nil))

	// content-address the stored bytes, restrictive perms.
	dst := filepath.Join(s.vault, sum)
	if err := os.Rename(tmpName, dst); err != nil {
		os.Remove(tmpName)
		http.Error(w, "storage error", http.StatusInternalServerError)
		return
	}
	_ = os.Chmod(dst, 0o600)

	id := newID()
	in := pipeline.SubmissionInput{
		SubmissionID: id,
		DomainID:     "default",
		SHA256:       sum,
		ScratchPath:  dst,
		Filename:     name,
	}
	_, err = s.tc.ExecuteWorkflow(r.Context(),
		client.StartWorkflowOptions{ID: id, TaskQueue: taskQueue},
		workflowName, in)
	if err != nil {
		http.Error(w, "could not start analysis", http.StatusInternalServerError)
		return
	}
	log.Printf("submission %s sha256=%s started", id, sum)
	writeJSON(w, http.StatusAccepted, map[string]string{
		"submission_id": id, "sha256": sum, "status": "accepted",
	})
}

func (s *server) handleGet(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimPrefix(r.URL.Path, "/v1/submissions/")
	if id == "" {
		http.Error(w, "missing submission id", http.StatusBadRequest)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
	defer cancel()

	var res pipeline.SubmissionResult
	if err := s.tc.GetWorkflow(ctx, id, "").Get(ctx, &res); err != nil {
		// still running or not found: report pending, do not guess a verdict.
		writeJSON(w, http.StatusOK, map[string]string{"submission_id": id, "status": "running"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"submission_id": res.SubmissionID,
		"sha256":        res.SHA256,
		"name":          res.Filename,
		"file_type":     res.FileType,
		"verdict":       res.Verdict.String(),
		"score":         res.Score,
		"confidence":    res.Confidence.String(),
		"incomplete":    res.Incomplete,
		"findings":      res.Findings,
	})
}

// summary is one row of the triage queue.
type summary struct {
	SubmissionID string `json:"submission_id"`
	Name         string `json:"name,omitempty"`
	SHA256       string `json:"sha256,omitempty"`
	FileType     string `json:"file_type,omitempty"`
	Verdict      string `json:"verdict"`
	Score        int    `json:"score"`
	Confidence   string `json:"confidence"`
	Incomplete   bool   `json:"incomplete"`
	Status       string `json:"status"`
	Received     string `json:"received,omitempty"`
}

// handleQueue lists the most recent submissions for the triage view, ranked
// by severity then score. it reads the durable Temporal store (no separate
// index), so the queue survives a gateway restart. completed workflows carry
// their verdict; running ones surface as pending.
func (s *server) handleQueue(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 20*time.Second)
	defer cancel()

	// filter by our workflow type only. the basic visibility store returns
	// newest-first and does not support an ORDER BY clause; we rank the result
	// ourselves below, so recency default ordering is all we need here.
	list, err := s.tc.ListWorkflow(ctx, &workflowservice.ListWorkflowExecutionsRequest{
		PageSize: queueSize,
		Query:    "WorkflowType = '" + workflowName + "'",
	})
	if err != nil {
		// visibility not ready or query unsupported: an empty queue, not a 500.
		log.Printf("queue: list workflows: %v", err)
		writeJSON(w, http.StatusOK, []summary{})
		return
	}

	out := make([]summary, 0, len(list.GetExecutions()))
	for _, e := range list.GetExecutions() {
		id := e.GetExecution().GetWorkflowId()
		row := summary{SubmissionID: id, Verdict: "UNKNOWN", Confidence: "LOW", Status: "running"}
		if t := e.GetStartTime(); t != nil {
			row.Received = humanAge(t.AsTime())
		}
		if e.GetStatus() == enums.WORKFLOW_EXECUTION_STATUS_COMPLETED {
			var res pipeline.SubmissionResult
			gctx, gcancel := context.WithTimeout(ctx, 4*time.Second)
			if err := s.tc.GetWorkflow(gctx, id, e.GetExecution().GetRunId()).Get(gctx, &res); err == nil {
				row.Name = res.Filename
				row.SHA256 = res.SHA256
				row.FileType = res.FileType
				row.Verdict = res.Verdict.String()
				row.Score = res.Score
				row.Confidence = res.Confidence.String()
				row.Incomplete = res.Incomplete
				row.Status = "done"
			}
			gcancel()
		}
		out = append(out, row)
	}
	// rank by severity, then score: the most-needs-attention first.
	sort.SliceStable(out, func(i, j int) bool {
		if verdictRank[out[i].Verdict] != verdictRank[out[j].Verdict] {
			return verdictRank[out[i].Verdict] > verdictRank[out[j].Verdict]
		}
		return out[i].Score > out[j].Score
	})
	writeJSON(w, http.StatusOK, out)
}

var verdictRank = map[string]int{"MALICIOUS": 3, "SUSPICIOUS": 2, "UNKNOWN": 1, "BENIGN": 0}

// humanAge renders a coarse "Nm ago" style age for the queue.
func humanAge(t time.Time) string {
	d := time.Since(t)
	switch {
	case d < time.Minute:
		return "just now"
	case d < time.Hour:
		return itoa(int(d.Minutes())) + "m ago"
	case d < 24*time.Hour:
		return itoa(int(d.Hours())) + "h ago"
	default:
		return itoa(int(d.Hours()/24)) + "d ago"
	}
}

func itoa(n int) string {
	if n <= 0 {
		return "0"
	}
	var b [20]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	return string(b[i:])
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func main() {
	vault := envOr("MAL_VAULT_DIR", filepath.Join(os.TempDir(), "openmallab-vault"))
	if err := os.MkdirAll(vault, 0o700); err != nil {
		log.Fatalf("vault dir: %v", err)
	}

	tc, err := client.Dial(client.Options{
		HostPort:  envOr("TEMPORAL_ADDRESS", "localhost:7233"),
		Namespace: envOr("TEMPORAL_NAMESPACE", "openmallab"),
	})
	if err != nil {
		log.Fatalf("temporal dial: %v", err)
	}
	defer tc.Close()

	s := &server{tc: tc, vault: vault}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("ok")) })
	mux.HandleFunc("POST /v1/submissions", s.handleSubmit)
	mux.HandleFunc("GET /v1/submissions/{id}", s.handleGet)
	mux.HandleFunc("GET /v1/queue", s.handleQueue)

	addr := envOr("MAL_GATEWAY_ADDR", ":8080")
	log.Printf("mal-gateway listening on %s (vault=%s)", addr, vault)
	log.Fatal(http.ListenAndServe(addr, mux))
}
