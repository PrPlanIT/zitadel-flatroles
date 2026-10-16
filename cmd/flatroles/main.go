package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/PrPlanIT/zitadel-flatroles/src/directory"
	"github.com/PrPlanIT/zitadel-flatroles/src/signing"
	"github.com/PrPlanIT/zitadel-flatroles/src/version"
)

const maxBody = 1 << 20

// Grant states from Zitadel's domain.UserGrantState: only unspecified/active grants
// carry roles; inactive and removed grants never do.
const (
	grantInactive = 2
	grantRemoved  = 3
)

// mode selects which grants feed the claim.
type mode string

const (
	// modeProject emits only the roles granted in the requesting application's own
	// project, so a role key means "this role in this app" and never leaks in from
	// another project that happens to use the same key.
	modeProject mode = "project"
	// modeReport emits every grant's roles, exactly as modeAll does, and logs what
	// modeProject would drop. It exists to prove a switch to modeProject is safe.
	modeReport mode = "report"
	// modeAll emits the roles of every grant the user holds, across all projects.
	modeAll mode = "all"
)

// resolver maps an OIDC client ID to the project that owns the application.
type resolver interface {
	Project(ctx context.Context, clientID string) (string, bool)
	Ready() bool
}

type config struct {
	claims     []string
	signingKey string
	mode       mode
	dir        resolver // nil in modeAll
}

func env(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

type grant struct {
	project string
	roles   []string
}

// grantsFrom reads the active grants from the payload. user_grants may be []grant or
// {"grants":[...]}; each grant's keys come from the first non-empty of
// roles|role_keys|roleKeys and its project from project_id|projectId.
func grantsFrom(p map[string]any) []grant {
	var raw []any
	switch g := p["user_grants"].(type) {
	case []any:
		raw = g
	case map[string]any:
		if gg, ok := g["grants"].([]any); ok {
			raw = gg
		}
	}
	var out []grant
	for _, gi := range raw {
		g, ok := gi.(map[string]any)
		if !ok {
			continue
		}
		if inactive(g["state"]) {
			continue
		}
		var keys []any
		for _, f := range []string{"roles", "role_keys", "roleKeys"} {
			if ks, ok := g[f].([]any); ok && len(ks) > 0 {
				keys = ks
				break
			}
		}
		gr := grant{project: firstString(g, "project_id", "projectId")}
		for _, ki := range keys {
			if r, ok := ki.(string); ok {
				gr.roles = append(gr.roles, r)
			}
		}
		out = append(out, gr)
	}
	return out
}

// inactive reports whether a grant state is inactive or removed, in either the numeric
// form the Actions payload carries or the enum-name form the Zitadel API uses.
func inactive(state any) bool {
	switch s := state.(type) {
	case float64:
		return s == grantInactive || s == grantRemoved
	case string:
		return s == "USER_GRANT_STATE_INACTIVE" || s == "USER_GRANT_STATE_REMOVED"
	}
	return false
}

// flatten returns the de-duplicated role keys of the grants keep accepts, in order of
// first appearance; keep == nil accepts every grant.
func flatten(grants []grant, keep func(project string) bool) []string {
	out := []string{}
	seen := map[string]bool{}
	for _, g := range grants {
		if keep != nil && !keep(g.project) {
			continue
		}
		for _, r := range g.roles {
			if !seen[r] {
				seen[r] = true
				out = append(out, r)
			}
		}
	}
	return out
}

func minus(all, keep []string) []string {
	in := map[string]bool{}
	for _, k := range keep {
		in[k] = true
	}
	out := []string{}
	for _, a := range all {
		if !in[a] {
			out = append(out, a)
		}
	}
	return out
}

func firstString(m map[string]any, keys ...string) string {
	for _, k := range keys {
		if s, ok := m[k].(string); ok && s != "" {
			return s
		}
	}
	return ""
}

func nested(p map[string]any, outer string, keys ...string) string {
	if m, ok := p[outer].(map[string]any); ok {
		return firstString(m, keys...)
	}
	return ""
}

// newMux builds the HTTP handler. When cfg.signingKey is non-empty, every POST to the
// target endpoint must carry a valid ZITADEL-Signature header; otherwise request
// signature verification is disabled (network-layer authz only).
func newMux(cfg config) *http.ServeMux {
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.Write([]byte("ok"))
	})
	// Ready once the client → project directory has synced; in modeAll there is none.
	mux.HandleFunc("/readyz", func(w http.ResponseWriter, _ *http.Request) {
		if cfg.dir != nil && !cfg.dir.Ready() {
			http.Error(w, "client directory not synced", http.StatusServiceUnavailable)
			return
		}
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
		if cfg.signingKey != "" {
			if err := signing.Validate(body, r.Header.Get(signing.SigningHeader), cfg.signingKey); err != nil {
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

		fn := firstString(p, "function", "function_name")
		if fn == "" {
			fn = "?"
		}
		clientID := nested(p, "application", "client_id", "clientId")
		user := nested(p, "user", "id")
		grants := grantsFrom(p)
		all := flatten(grants, nil)

		roles := all
		if cfg.mode != modeAll {
			project, ok := cfg.dir.Project(r.Context(), clientID)
			scoped := []string{}
			if ok {
				scoped = flatten(grants, func(pid string) bool { return pid == project })
			}
			if cfg.mode == modeProject {
				roles = scoped
			}
			verb := "dropped"
			if cfg.mode == modeReport {
				verb = "would drop"
			}
			switch dropped := minus(all, scoped); {
			case !ok && len(all) > 0:
				log.Printf("%s user=%s client=%q: no project for this client; %s all %d roles %v", fn, user, clientID, verb, len(all), all)
			case len(dropped) > 0:
				log.Printf("%s user=%s client=%s project=%s: %s %v from other projects, kept %v", fn, user, clientID, project, verb, dropped, scoped)
			}
		}

		w.Header().Set("Content-Type", "application/json")
		if len(roles) == 0 {
			w.Write([]byte("{}"))
		} else {
			claims := make([]map[string]any, 0, len(cfg.claims))
			for _, c := range cfg.claims {
				claims = append(claims, map[string]any{"key": c, "value": roles})
			}
			json.NewEncoder(w).Encode(map[string]any{"append_claims": claims})
		}
		log.Printf("%s: %d roles", fn, len(roles))
	})
	return mux
}

func loadConfig() (config, *directory.Directory, error) {
	if os.Getenv("CLAIM_NAME") != "" {
		return config{}, nil, fmt.Errorf("CLAIM_NAME was replaced by CLAIM_NAMES, a comma-separated list (e.g. CLAIM_NAMES=roles or CLAIM_NAMES=roles,groups)")
	}
	cfg := config{signingKey: os.Getenv("SIGNING_KEY"), mode: mode(env("MODE", string(modeProject)))}
	for _, c := range strings.Split(env("CLAIM_NAMES", "roles"), ",") {
		if c = strings.TrimSpace(c); c != "" {
			cfg.claims = append(cfg.claims, c)
		}
	}
	if len(cfg.claims) == 0 {
		return config{}, nil, fmt.Errorf("CLAIM_NAMES names no claim")
	}
	switch cfg.mode {
	case modeAll:
		return cfg, nil, nil
	case modeProject, modeReport:
	default:
		return config{}, nil, fmt.Errorf("MODE=%q: want project, report or all", cfg.mode)
	}
	url, token := os.Getenv("ZITADEL_API_URL"), os.Getenv("ZITADEL_TOKEN")
	if url == "" || token == "" {
		return config{}, nil, fmt.Errorf("MODE=%s resolves each client's project through the Zitadel API and needs ZITADEL_API_URL and ZITADEL_TOKEN (a read-only instance token); MODE=all flattens every grant without it", cfg.mode)
	}
	dir := directory.New(strings.TrimRight(url, "/"), os.Getenv("ZITADEL_HOST"), token, time.Minute)
	cfg.dir = dir
	return cfg, dir, nil
}

func main() {
	addr := ":" + env("PORT", "8080")
	cfg, dir, err := loadConfig()
	if err != nil {
		log.Fatal(err)
	}

	verify := "ENABLED"
	if cfg.signingKey == "" {
		verify = "DISABLED (network-layer authz only)"
	}
	log.Printf("flatroles %s (%s) listening on %s (claims=%s, mode=%s, signature-verify=%s)",
		version.Version, version.Commit, addr, strings.Join(cfg.claims, ","), cfg.mode, verify)

	if dir != nil {
		interval, err := time.ParseDuration(env("RESYNC_INTERVAL", "5m"))
		if err != nil {
			log.Fatalf("RESYNC_INTERVAL: %v", err)
		}
		ctx := context.Background()
		go func() {
			for {
				if err := dir.Sync(ctx); err != nil {
					log.Printf("client directory sync failed, retrying in 10s: %v", err)
					time.Sleep(10 * time.Second)
					continue
				}
				log.Printf("client directory synced: %d clients", dir.Size())
				dir.Run(ctx, interval, log.Printf)
				return
			}
		}()
	}
	log.Fatal(http.ListenAndServe(addr, newMux(cfg)))
}
