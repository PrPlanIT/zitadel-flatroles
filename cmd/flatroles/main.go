package main

import (
	"encoding/json"
	"log"
	"net/http"
	"os"

	"github.com/PrPlanIT/zitadel-flatroles/src/version"
)

func env(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

// rolesFrom: user_grants may be []grant or {"grants":[...]}; each grant's keys
// come from the first non-empty of roles|role_keys|roleKeys.
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

func main() {
	addr := ":" + env("PORT", "8080")
	claim := env("CLAIM_NAME", "roles")

	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.Write([]byte("ok"))
	})
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.NotFound(w, r)
			return
		}
		var p map[string]any
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&p); err != nil {
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
		fn, _ := p["function_name"].(string)
		if fn == "" {
			fn = "?"
		}
		log.Printf("%s: %d roles", fn, len(roles))
	})

	log.Printf("flatroles %s (%s) listening on %s (claim=%s)", version.Version, version.Commit, addr, claim)
	log.Fatal(http.ListenAndServe(addr, mux))
}
