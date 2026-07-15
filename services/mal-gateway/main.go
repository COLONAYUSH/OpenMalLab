// mal-gateway is the front door. it takes a submission over http, checks auth,
// writes an audit line, and hands the sample to the orchestrator. it never
// parses hostile bytes itself.
//
// this is the M0 skeleton: the submit and health endpoints exist and round-trip.
// the real oidc auth, the opa check, the vault write, and the temporal handoff
// get wired in as those pieces land. see docs/M0-FIRST-COMMIT.md.
package main

import (
	"encoding/json"
	"log"
	"net/http"
	"os"
)

type submitResponse struct {
	SubmissionID string `json:"submission_id"`
	Status       string `json:"status"`
}

func main() {
	mux := http.NewServeMux()

	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})

	// POST /v1/submissions takes a file and returns a submission id.
	// M0 stub: it does not persist or dispatch yet.
	mux.HandleFunc("POST /v1/submissions", func(w http.ResponseWriter, _ *http.Request) {
		// TODO(M0): oidc auth, opa check, audit log, stream to the vault, start the workflow.
		resp := submitResponse{SubmissionID: "stub-not-wired-yet", Status: "accepted"}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
	})

	addr := os.Getenv("MAL_GATEWAY_ADDR")
	if addr == "" {
		addr = ":8080"
	}
	log.Printf("mal-gateway listening on %s", addr)
	log.Fatal(http.ListenAndServe(addr, mux))
}
