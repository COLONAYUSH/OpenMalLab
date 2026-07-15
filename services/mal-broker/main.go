// mal-broker is the guard on the worker-to-control boundary. it reads a worker's
// result from stdin (hostile-derived bytes), decodes it under hard caps in a
// process that itself runs network-dead and unprivileged, and writes a
// validated, typed result to stdout. the orchestrator reads only the broker's
// output and never decodes raw worker bytes. fail-closed: any violation exits
// nonzero, and the node floors to SUSPICIOUS upstream. see DESIGN-AUDIT RC-2.
package main

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
)

const (
	maxInputBytes = 1 << 20 // 1 MiB, well under the durable-store payload limit
	maxFindings   = 1000
	maxStringLen  = 8192
)

type finding struct {
	Engine  string `json:"engine"`
	Type    string `json:"type"`
	Detail  string `json:"detail"`
	Attck   string `json:"attck"`
	Verdict string `json:"verdict"`
}

type report struct {
	Engine     string    `json:"engine"`
	Findings   []finding `json:"findings"`
	Verdict    string    `json:"verdict"`
	Incomplete bool      `json:"incomplete"`
}

func validVerdict(v string) bool {
	switch v {
	case "BENIGN", "UNKNOWN", "SUSPICIOUS", "MALICIOUS":
		return true
	}
	return false
}

func checkStr(field, s string) {
	if len(s) > maxStringLen {
		reject("%s exceeds %d bytes", field, maxStringLen)
	}
}

func main() {
	// bound the read; reject unknown fields so a compromised worker cannot smuggle
	// extra structure past us.
	dec := json.NewDecoder(io.LimitReader(os.Stdin, maxInputBytes))
	dec.DisallowUnknownFields()

	var r report
	if err := dec.Decode(&r); err != nil {
		reject("decode: %v", err)
	}
	if dec.More() {
		reject("unexpected trailing data after one result")
	}
	if !validVerdict(r.Verdict) {
		reject("bad top-level verdict %q", r.Verdict)
	}
	if len(r.Findings) > maxFindings {
		reject("too many findings: %d", len(r.Findings))
	}
	checkStr("engine", r.Engine)
	for i, f := range r.Findings {
		if !validVerdict(f.Verdict) {
			reject("finding %d has bad verdict %q", i, f.Verdict)
		}
		checkStr("finding.engine", f.Engine)
		checkStr("finding.type", f.Type)
		checkStr("finding.detail", f.Detail)
		checkStr("finding.attck", f.Attck)
	}

	// validated: re-emit the typed result. this, and only this, is what a trusted
	// process reads.
	if err := json.NewEncoder(os.Stdout).Encode(&r); err != nil {
		reject("encode: %v", err)
	}
}

func reject(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "mal-broker reject: "+format+"\n", args...)
	os.Exit(1)
}
