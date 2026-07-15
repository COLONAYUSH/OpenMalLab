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
	"strings"
	"time"

	"github.com/COLONAYUSH/OpenMalLab/internal/pipeline"
	"go.temporal.io/sdk/client"
)

const (
	taskQueue      = "openmallab-m0"
	workflowName   = "SubmissionWorkflow"
	maxUploadBytes = 256 << 20 // 256 MiB cap so a huge upload cannot exhaust the box
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
	tc     client.Client
	vault  string // scratch vault dir (the real envelope-encrypted WORM vault comes next)
}

func (s *server) handleSubmit(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxUploadBytes)
	f, _, err := r.FormFile("file")
	if err != nil {
		http.Error(w, "expected multipart field 'file'", http.StatusBadRequest)
		return
	}
	defer f.Close()

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
		"file_type":     res.FileType,
		"verdict":       res.Verdict.String(),
		"incomplete":    res.Incomplete,
		"findings":      res.Findings,
	})
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

	addr := envOr("MAL_GATEWAY_ADDR", ":8080")
	log.Printf("mal-gateway listening on %s (vault=%s)", addr, vault)
	log.Fatal(http.ListenAndServe(addr, mux))
}
