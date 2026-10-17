package main

import (
	"encoding/json"
	"io"
	"log"
	"net/http"
	"os"

	"github.com/PrPlanIT/zitadel-flatroles/src/signing"
	"github.com/PrPlanIT/zitadel-flatroles/src/version"
)

const maxBody = 1 << 20

func env(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

// rolesFrom: user_grants may be []grant or {"grants":[...]}; each grant's keys
// come from the first non-empty of roles|role_keys|roleKeys. Zitadel has already
// limited user_grants to the active grants of the token's role audience, so every
// grant in the payload counts.
func rolesFrom(p map[string]any) []string {
	out := []string{}
	seen := map[string]bool{}
	var grants []any
	switch g := p["user_grants"].(type) {
	case []any:
		grants = g
	case map[string]any:
		if gg, ok := g["grants"].([]any); ok {
			grants = gg
		}
	}
	for _, gi := range grants {
		g, ok := gi.(map[string]any)
		if !ok {
			continue
		}
		var keys []any
		for _, f := range []string{"roles", "role_keys", "roleKeys"} {
			if ks, ok := g[f].([]any); ok && len(ks) > 0 {
				keys = ks
				break
			}
		}
		for _, ki := range keys {
			if r, ok := ki.(string); ok && !seen[r] {
				seen[r] = true
				out = append(out, r)
			}
		}
	}
	return out
}

// newMux builds the HTTP handler. When signingKey is non-empty, every POST to
// the target endpoint must carry a valid ZITADEL-Signature header; otherwise
// request-signature verification is disabled (network-layer authz only).
func newMux(claim, signingKey string) *http.ServeMux {
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.Write([]byte("ok"))
	})
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.NotFound(w, r)
			return
		}
		// Read the raw body first: the signature is computed over these exact
		// bytes, so verification must happen before (and decode after) it.
		body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxBody))
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		if signingKey != "" {
			if err := signing.Validate(body, r.Header.Get(signing.SigningHeader), signingKey); err != nil {
				log.Printf("rejected unsigned/invalid request: %v", err)
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
		}
		var p map[string]any
		if err := json.Unmarshal(body, &p); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		roles := rolesFrom(p)
		w.Header().Set("Content-Type", "application/json")
		if len(roles) == 0 {
			w.Write([]byte("{}"))
		} else {
			json.NewEncoder(w).Encode(map[string]any{
				"append_claims": []map[string]any{{"key": claim, "value": roles}},
			})
		}
		fn, _ := p["function"].(string)
		if fn == "" {
			fn = "?"
		}
		log.Printf("%s: %d roles", fn, len(roles))
	})
	return mux
}

func main() {
	addr := ":" + env("PORT", "8080")
	claim := env("CLAIM_NAME", "roles")
	signingKey := os.Getenv("SIGNING_KEY")

	verify := "ENABLED"
	if signingKey == "" {
		verify = "DISABLED (network-layer authz only)"
	}
	log.Printf("flatroles %s (%s) listening on %s (claim=%s, signature-verify=%s)",
		version.Version, version.Commit, addr, claim, verify)
	log.Fatal(http.ListenAndServe(addr, newMux(claim, signingKey)))
}
