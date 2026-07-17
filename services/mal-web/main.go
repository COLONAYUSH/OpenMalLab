// mal-web serves the read-only analyst console and nothing else. it embeds the
// static console at build time (so the image is self-contained and offline),
// serves it at /, and reverse-proxies the /v1 API to the gateway so the browser
// talks to a single origin. it holds no credentials, touches no hostile bytes,
// and never spawns anything; it is the thinnest possible front door for reading
// verdicts. a strict-ish CSP and the usual hardening headers go on every
// response, because the console renders specimen-derived (hostile) text.
package main

import (
	"embed"
	"io/fs"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"time"
)

//go:embed web
var webFS embed.FS

func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

// securityHeaders locks the console down: it is self-contained (inline styles
// and script, no external anything), so connect/img/etc. stay on 'self', it
// cannot be framed, and it never leaks a referrer. 'unsafe-inline' is required
// only because the single-file console inlines its own style and script.
func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Security-Policy",
			"default-src 'none'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; "+
				"img-src 'self' data:; connect-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Referrer-Policy", "no-referrer")
		next.ServeHTTP(w, r)
	})
}

func main() {
	gwRaw := envOr("MAL_GATEWAY_URL", "http://gateway:8080")
	gwURL, err := url.Parse(gwRaw)
	if err != nil {
		log.Fatalf("bad MAL_GATEWAY_URL %q: %v", gwRaw, err)
	}

	// the /v1 API is proxied to the gateway so the console is one origin.
	proxy := httputil.NewSingleHostReverseProxy(gwURL)
	proxy.ErrorHandler = func(w http.ResponseWriter, _ *http.Request, _ error) {
		// gateway not reachable: the console falls back to its own empty/preview
		// state, so a plain 502 is enough here.
		w.WriteHeader(http.StatusBadGateway)
	}

	sub, err := fs.Sub(webFS, "web")
	if err != nil {
		log.Fatalf("embed: %v", err)
	}
	static := http.FileServer(http.FS(sub))

	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("ok")) })
	mux.Handle("/v1/", proxy) // read API -> gateway
	mux.Handle("/", static)   // the console (index.html) and its assets

	srv := &http.Server{
		Addr:              envOr("MAL_WEB_ADDR", ":8090"),
		Handler:           securityHeaders(mux),
		ReadHeaderTimeout: 10 * time.Second,
	}
	log.Printf("mal-web serving the console on %s (gateway=%s)", srv.Addr, gwURL.Redacted())
	log.Fatal(srv.ListenAndServe())
}
