package directory

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

// fakeZitadel serves the three v1 _search endpoints the directory reads.
type fakeZitadel struct {
	mu       sync.Mutex
	orgs     map[string][]string         // org -> projects
	apps     map[string][]map[string]any // project -> app results
	calls    int
	fail     bool
	seenHost string
}

func (f *fakeZitadel) handler(t *testing.T) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		f.calls++
		f.seenHost = r.Host
		if r.Header.Get("Authorization") != "Bearer tok" {
			http.Error(w, "unauthenticated", http.StatusUnauthorized)
			return
		}
		if f.fail {
			http.Error(w, "boom", http.StatusInternalServerError)
			return
		}
		var req struct {
			Query struct {
				Offset string `json:"offset"`
				Limit  int    `json:"limit"`
			} `json:"query"`
		}
		json.NewDecoder(r.Body).Decode(&req)
		offset, _ := strconv.Atoi(req.Query.Offset)
		org := r.Header.Get("x-zitadel-orgid")

		var all []any
		switch {
		case r.URL.Path == "/admin/v1/orgs/_search":
			for o := range f.orgs {
				all = append(all, map[string]any{"id": o})
			}
		case r.URL.Path == "/management/v1/projects/_search":
			if org == "" {
				t.Errorf("projects search without x-zitadel-orgid")
			}
			for _, p := range f.orgs[org] {
				all = append(all, map[string]any{"id": p})
			}
		case strings.HasPrefix(r.URL.Path, "/management/v1/projects/") && strings.HasSuffix(r.URL.Path, "/apps/_search"):
			p := strings.TrimSuffix(strings.TrimPrefix(r.URL.Path, "/management/v1/projects/"), "/apps/_search")
			for _, a := range f.apps[p] {
				all = append(all, a)
			}
		default:
			http.NotFound(w, r)
			return
		}
		end := min(offset+req.Query.Limit, len(all))
		page := []any{}
		if offset < len(all) {
			page = all[offset:end]
		}
		json.NewEncoder(w).Encode(map[string]any{
			"details": map[string]any{"totalResult": strconv.Itoa(len(all))},
			"result":  page,
		})
	})
}

func oidcApp(client string) map[string]any {
	return map[string]any{"oidcConfig": map[string]any{"clientId": client}}
}

func newFake() *fakeZitadel {
	return &fakeZitadel{
		orgs: map[string][]string{"org-a": {"security", "ipam"}, "org-b": {"games"}},
		apps: map[string][]map[string]any{
			"security": {oidcApp("wazuh")},
			"ipam":     {oidcApp("netbox"), {"apiConfig": map[string]any{"clientId": "ipam-api"}}, {"samlConfig": map[string]any{}}},
			"games":    {oidcApp("romm")},
		},
	}
}

func TestSync_MapsEveryClientAcrossOrgs(t *testing.T) {
	f := newFake()
	srv := httptest.NewServer(f.handler(t))
	defer srv.Close()

	d := New(srv.URL, "sso.example.com", "tok", time.Minute)
	if d.Ready() {
		t.Fatal("ready before first sync")
	}
	if err := d.Sync(context.Background()); err != nil {
		t.Fatal(err)
	}
	for client, want := range map[string]string{"wazuh": "security", "netbox": "ipam", "ipam-api": "ipam", "romm": "games"} {
		if got, ok := d.Project(context.Background(), client); !ok || got != want {
			t.Errorf("%s: got %q,%v want %q", client, got, ok, want)
		}
	}
	if !d.Ready() || d.Size() != 4 {
		t.Fatalf("ready=%v size=%d", d.Ready(), d.Size())
	}
	if f.seenHost != "sso.example.com" {
		t.Fatalf("Host override not sent: %q", f.seenHost)
	}
}

func TestSync_Paginates(t *testing.T) {
	f := newFake()
	var projects []string
	for i := 0; i < 2*pageSize+7; i++ {
		p := fmt.Sprintf("p%d", i)
		projects = append(projects, p)
		f.apps[p] = []map[string]any{oidcApp("c" + p)}
	}
	f.orgs["org-big"] = projects
	srv := httptest.NewServer(f.handler(t))
	defer srv.Close()

	d := New(srv.URL, "", "tok", time.Minute)
	if err := d.Sync(context.Background()); err != nil {
		t.Fatal(err)
	}
	if got, ok := d.Project(context.Background(), fmt.Sprintf("cp%d", 2*pageSize+6)); !ok || got != fmt.Sprintf("p%d", 2*pageSize+6) {
		t.Fatalf("last project on the third page not mapped: %q %v", got, ok)
	}
}

func TestProject_MissResyncsAtMostOncePerInterval(t *testing.T) {
	f := newFake()
	srv := httptest.NewServer(f.handler(t))
	defer srv.Close()

	d := New(srv.URL, "", "tok", time.Hour)
	if err := d.Sync(context.Background()); err != nil {
		t.Fatal(err)
	}
	// An application created after the sync is found once the interval allows a resync.
	f.mu.Lock()
	f.apps["security"] = append(f.apps["security"], oidcApp("new-app"))
	before := f.calls
	f.mu.Unlock()

	if _, ok := d.Project(context.Background(), "new-app"); ok {
		t.Fatal("resynced before minResync elapsed")
	}
	if f.calls != before {
		t.Fatalf("a miss inside minResync must not call the API (%d calls)", f.calls-before)
	}

	d.mu.Lock()
	d.lastSync = time.Now().Add(-2 * time.Hour)
	d.mu.Unlock()
	if got, ok := d.Project(context.Background(), "new-app"); !ok || got != "security" {
		t.Fatalf("miss after minResync should resync and resolve: %q %v", got, ok)
	}
}

func TestSync_FailureKeepsPreviousSnapshot(t *testing.T) {
	f := newFake()
	srv := httptest.NewServer(f.handler(t))
	defer srv.Close()

	d := New(srv.URL, "", "tok", time.Minute)
	if err := d.Sync(context.Background()); err != nil {
		t.Fatal(err)
	}
	f.mu.Lock()
	f.fail = true
	f.mu.Unlock()
	if err := d.Sync(context.Background()); err == nil {
		t.Fatal("expected sync error")
	}
	if got, ok := d.lookup("wazuh"); !ok || got != "security" {
		t.Fatalf("failed sync emptied the snapshot: %q %v", got, ok)
	}
}

func TestSync_RejectedTokenIsAnError(t *testing.T) {
	srv := httptest.NewServer(newFake().handler(t))
	defer srv.Close()
	d := New(srv.URL, "", "wrong", time.Minute)
	err := d.Sync(context.Background())
	if err == nil || !strings.Contains(err.Error(), "HTTP 401") {
		t.Fatalf("want HTTP 401 error, got %v", err)
	}
	if d.Ready() {
		t.Fatal("ready after a failed first sync")
	}
}
