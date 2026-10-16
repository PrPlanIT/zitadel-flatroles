// Package directory maps an OIDC client ID to the Zitadel project that owns the
// application it belongs to.
//
// Zitadel's Actions v2 payload names the requesting application only by client ID,
// while every user grant names its project. Joining the two needs the client → project
// relationship, which only the Zitadel API knows. The directory reads it by walking
// every organization, every project in it, and every application in each project,
// then answers lookups from memory. It resyncs on an interval and, when asked about a
// client it has never seen (an application created since the last sync), resyncs
// early — at most once per minResync, so unknown or bogus client IDs cannot turn
// into a flood of API calls.
//
// Stdlib only, like the rest of the binary, so the image stays distroless-static.
package directory

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"sync"
	"time"
)

const pageSize = 100

// Directory resolves client IDs to project IDs from a periodically synced snapshot.
type Directory struct {
	api       *client
	minResync time.Duration

	mu       sync.RWMutex
	byClient map[string]string
	synced   bool
	lastSync time.Time

	syncMu sync.Mutex
}

// New returns a Directory reading from the Zitadel API at baseURL. host, when set,
// overrides the HTTP Host header: Zitadel routes by instance domain, so an in-cluster
// caller reaching the service directly must still present the public domain.
func New(baseURL, host, token string, minResync time.Duration) *Directory {
	return &Directory{
		api:       &client{base: baseURL, host: host, token: token, http: &http.Client{Timeout: 15 * time.Second}},
		minResync: minResync,
		byClient:  map[string]string{},
	}
}

// Ready reports whether at least one full sync has completed.
func (d *Directory) Ready() bool {
	d.mu.RLock()
	defer d.mu.RUnlock()
	return d.synced
}

// Size returns the number of client IDs currently known.
func (d *Directory) Size() int {
	d.mu.RLock()
	defer d.mu.RUnlock()
	return len(d.byClient)
}

// Project returns the project owning clientID. A miss triggers an early resync when
// the last one is older than minResync, then the lookup is retried once.
func (d *Directory) Project(ctx context.Context, clientID string) (string, bool) {
	if clientID == "" {
		return "", false
	}
	if p, ok := d.lookup(clientID); ok {
		return p, true
	}
	d.mu.RLock()
	stale := time.Since(d.lastSync) >= d.minResync
	d.mu.RUnlock()
	if !stale {
		return "", false
	}
	if err := d.Sync(ctx); err != nil {
		return "", false
	}
	return d.lookup(clientID)
}

func (d *Directory) lookup(clientID string) (string, bool) {
	d.mu.RLock()
	defer d.mu.RUnlock()
	p, ok := d.byClient[clientID]
	return p, ok
}

// Sync rebuilds the snapshot from the API and swaps it in whole. On error the
// previous snapshot is kept, so a transient API failure never empties the map.
func (d *Directory) Sync(ctx context.Context) error {
	d.syncMu.Lock()
	defer d.syncMu.Unlock()

	m, err := d.api.clientProjects(ctx)
	d.mu.Lock()
	defer d.mu.Unlock()
	d.lastSync = time.Now()
	if err != nil {
		return err
	}
	d.byClient = m
	d.synced = true
	return nil
}

// Run syncs every interval until ctx ends.
func (d *Directory) Run(ctx context.Context, interval time.Duration, logf func(string, ...any)) {
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if err := d.Sync(ctx); err != nil {
				logf("directory resync failed (keeping %d known clients): %v", d.Size(), err)
			}
		}
	}
}

// ── Zitadel API ──────────────────────────────────────────────────────────────

type client struct {
	base, host, token string
	http              *http.Client
}

type listDetails struct {
	TotalResult flexUint `json:"totalResult"`
}

type idResult struct {
	ID string `json:"id"`
}

type appResult struct {
	OIDCConfig *struct {
		ClientID string `json:"clientId"`
	} `json:"oidcConfig"`
	APIConfig *struct {
		ClientID string `json:"clientId"`
	} `json:"apiConfig"`
}

func (c *client) clientProjects(ctx context.Context) (map[string]string, error) {
	orgs, err := c.listIDs(ctx, "/admin/v1/orgs/_search", "")
	if err != nil {
		return nil, fmt.Errorf("listing organizations: %w", err)
	}
	m := map[string]string{}
	for _, org := range orgs {
		projects, err := c.listIDs(ctx, "/management/v1/projects/_search", org)
		if err != nil {
			return nil, fmt.Errorf("listing projects of org %s: %w", org, err)
		}
		for _, project := range projects {
			apps, err := c.listApps(ctx, project, org)
			if err != nil {
				return nil, fmt.Errorf("listing applications of project %s: %w", project, err)
			}
			for _, a := range apps {
				for _, id := range []string{oidcClient(a), apiClient(a)} {
					if id != "" {
						m[id] = project
					}
				}
			}
		}
	}
	return m, nil
}

func oidcClient(a appResult) string {
	if a.OIDCConfig == nil {
		return ""
	}
	return a.OIDCConfig.ClientID
}

func apiClient(a appResult) string {
	if a.APIConfig == nil {
		return ""
	}
	return a.APIConfig.ClientID
}

func (c *client) listIDs(ctx context.Context, path, org string) ([]string, error) {
	var out []string
	err := c.paginate(ctx, path, org, func(raw json.RawMessage) (int, error) {
		var page []idResult
		if err := json.Unmarshal(raw, &page); err != nil {
			return 0, err
		}
		for _, r := range page {
			out = append(out, r.ID)
		}
		return len(page), nil
	})
	return out, err
}

func (c *client) listApps(ctx context.Context, project, org string) ([]appResult, error) {
	var out []appResult
	err := c.paginate(ctx, "/management/v1/projects/"+project+"/apps/_search", org, func(raw json.RawMessage) (int, error) {
		var page []appResult
		if err := json.Unmarshal(raw, &page); err != nil {
			return 0, err
		}
		out = append(out, page...)
		return len(page), nil
	})
	return out, err
}

// paginate POSTs a v1 _search request page by page until totalResult is reached or a
// short page arrives, handing each page's raw result array to take.
func (c *client) paginate(ctx context.Context, path, org string, take func(json.RawMessage) (int, error)) error {
	for offset := 0; ; {
		body, _ := json.Marshal(map[string]any{"query": map[string]any{"offset": strconv.Itoa(offset), "limit": pageSize}})
		var resp struct {
			Details listDetails     `json:"details"`
			Result  json.RawMessage `json:"result"`
		}
		if err := c.post(ctx, path, org, body, &resp); err != nil {
			return err
		}
		n := 0
		if len(resp.Result) > 0 {
			var err error
			if n, err = take(resp.Result); err != nil {
				return fmt.Errorf("decoding %s: %w", path, err)
			}
		}
		offset += n
		if n < pageSize || uint64(offset) >= uint64(resp.Details.TotalResult) {
			return nil
		}
	}
}

func (c *client) post(ctx context.Context, path, org string, body []byte, out any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.base+path, bytes.NewReader(body))
	if err != nil {
		return err
	}
	if c.host != "" {
		req.Host = c.host
	}
	req.Header.Set("Authorization", "Bearer "+c.token)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	if org != "" {
		req.Header.Set("x-zitadel-orgid", org)
	}
	res, err := c.http.Do(req)
	if err != nil {
		return err
	}
	defer res.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(res.Body, 16<<20))
	if err != nil {
		return err
	}
	if res.StatusCode != http.StatusOK {
		return &StatusError{Path: path, Code: res.StatusCode, Body: string(bytes.TrimSpace(raw[:min(len(raw), 300)]))}
	}
	return json.Unmarshal(raw, out)
}

// StatusError is a non-200 answer from the Zitadel API.
type StatusError struct {
	Path string
	Code int
	Body string
}

func (e *StatusError) Error() string {
	return fmt.Sprintf("%s: HTTP %d: %s", e.Path, e.Code, e.Body)
}

// flexUint decodes Zitadel's uint64 fields, which grpc-gateway renders as strings.
type flexUint uint64

func (f *flexUint) UnmarshalJSON(b []byte) error {
	s := string(bytes.Trim(b, `"`))
	if s == "" || s == "null" {
		*f = 0
		return nil
	}
	v, err := strconv.ParseUint(s, 10, 64)
	if err != nil {
		return err
	}
	*f = flexUint(v)
	return nil
}
