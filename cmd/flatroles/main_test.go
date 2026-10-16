package main

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/PrPlanIT/zitadel-flatroles/src/signing"
)

func TestFlattenAllGrants(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want []string
	}{
		{"list form", `{"user_grants":[{"roles":["a","b"]},{"roles":["b","c"]}]}`, []string{"a", "b", "c"}},
		{"grants-object form", `{"user_grants":{"grants":[{"role_keys":["x"]}]}}`, []string{"x"}},
		{"roleKeys fallback", `{"user_grants":[{"roleKeys":["z"]}]}`, []string{"z"}},
		{"first non-empty wins", `{"user_grants":[{"roles":["r"],"role_keys":["ignored"]}]}`, []string{"r"}},
		{"empty", `{"user_grants":[]}`, []string{}},
		{"no grants key", `{}`, []string{}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			var p map[string]any
			if err := json.Unmarshal([]byte(c.in), &p); err != nil {
				t.Fatal(err)
			}
			if got := flatten(grantsFrom(p), nil); !reflect.DeepEqual(got, c.want) {
				t.Fatalf("got %v, want %v", got, c.want)
			}
		})
	}
}

func allMode(claim, key string) config {
	return config{claims: []string{claim}, signingKey: key, mode: modeAll}
}

func post(t *testing.T, mux *http.ServeMux, body string, hdr map[string]string) (*http.Response, string) {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(body))
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	res := rec.Result()
	b, _ := io.ReadAll(res.Body)
	return res, string(b)
}

func TestHealthz(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	rec := httptest.NewRecorder()
	newMux(allMode("roles", "")).ServeHTTP(rec, req)
	if rec.Code != 200 || rec.Body.String() != "ok" {
		t.Fatalf("healthz: code=%d body=%q", rec.Code, rec.Body.String())
	}
}

func TestHandler_NoVerify_AppendsClaims(t *testing.T) {
	res, body := post(t, newMux(allMode("roles", "")), `{"user_grants":[{"roles":["admin","viewer"]}]}`, nil)
	if res.StatusCode != 200 {
		t.Fatalf("status %d", res.StatusCode)
	}
	want := `{"append_claims":[{"key":"roles","value":["admin","viewer"]}]}`
	if strings.TrimSpace(body) != want {
		t.Fatalf("body=%s want=%s", body, want)
	}
}

func TestHandler_NoRoles_ReturnsEmptyObject(t *testing.T) {
	res, body := post(t, newMux(allMode("roles", "")), `{"user_grants":[]}`, nil)
	if res.StatusCode != 200 || strings.TrimSpace(body) != "{}" {
		t.Fatalf("status=%d body=%q", res.StatusCode, body)
	}
}

func TestHandler_CustomClaimName(t *testing.T) {
	_, body := post(t, newMux(allMode("groups", "")), `{"user_grants":[{"roles":["a"]}]}`, nil)
	if !strings.Contains(body, `"key":"groups"`) {
		t.Fatalf("expected custom claim name, got %s", body)
	}
}

func TestHandler_GET_NotFound(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()
	newMux(allMode("roles", "")).ServeHTTP(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("want 404, got %d", rec.Code)
	}
}

func TestHandler_Verify_ValidSignature(t *testing.T) {
	const key = "s3cr3t"
	body := `{"user_grants":[{"roles":["admin"]}]}`
	hdr := map[string]string{signing.SigningHeader: signing.ComputeHeader(time.Now(), []byte(body), key)}
	res, out := post(t, newMux(allMode("roles", key)), body, hdr)
	if res.StatusCode != 200 {
		t.Fatalf("status %d", res.StatusCode)
	}
	if !strings.Contains(out, `"admin"`) {
		t.Fatalf("expected claim, got %s", out)
	}
}

func TestHandler_Verify_MissingSignature_401(t *testing.T) {
	res, _ := post(t, newMux(allMode("roles", "s3cr3t")), `{"user_grants":[]}`, nil)
	if res.StatusCode != http.StatusUnauthorized {
		t.Fatalf("want 401, got %d", res.StatusCode)
	}
}

func TestHandler_Verify_BadSignature_401(t *testing.T) {
	const key = "s3cr3t"
	body := `{"user_grants":[{"roles":["admin"]}]}`
	// signature computed over a different body → must be rejected
	hdr := map[string]string{signing.SigningHeader: signing.ComputeHeader(time.Now(), []byte(`{}`), key)}
	res, _ := post(t, newMux(allMode("roles", key)), body, hdr)
	if res.StatusCode != http.StatusUnauthorized {
		t.Fatalf("want 401, got %d", res.StatusCode)
	}
}

func TestHandler_Verify_WrongKey_401(t *testing.T) {
	body := `{"user_grants":[]}`
	hdr := map[string]string{signing.SigningHeader: signing.ComputeHeader(time.Now(), []byte(body), "attacker-key")}
	res, _ := post(t, newMux(allMode("roles", "real-key")), body, hdr)
	if res.StatusCode != http.StatusUnauthorized {
		t.Fatalf("want 401, got %d", res.StatusCode)
	}
}

func TestHandler_BadJSON_400(t *testing.T) {
	res, _ := post(t, newMux(allMode("roles", "")), `{not json`, nil)
	if res.StatusCode != http.StatusBadRequest {
		t.Fatalf("want 400, got %d", res.StatusCode)
	}
}

func TestHandler_BodyTooLarge_400(t *testing.T) {
	// Exceed maxBody (1 MiB): MaxBytesReader makes io.ReadAll error before decode.
	big := strings.Repeat("a", maxBody+10)
	res, _ := post(t, newMux(allMode("roles", "")), big, nil)
	if res.StatusCode != http.StatusBadRequest {
		t.Fatalf("want 400 for oversized body, got %d", res.StatusCode)
	}
}

// fakeDir is a static resolver for handler tests.
type fakeDir struct {
	m     map[string]string
	ready bool
}

func (f fakeDir) Project(_ context.Context, c string) (string, bool) { p, ok := f.m[c]; return p, ok }
func (f fakeDir) Ready() bool                                        { return f.ready }

// payload mirrors Zitadel's ContextInfo: application.client_id and per-grant project_id.
const payload = `{"function":"function/preuserinfo","user":{"id":"u1"},
 "application":{"client_id":"wazuh-client"},
 "user_grants":[
  {"project_id":"security","roles":["operator"]},
  {"project_id":"ipam","roles":["admin"]},
  {"project_id":"security","roles":["group-prplanit"],"state":1},
  {"project_id":"security","roles":["revoked"],"state":2},
  {"project_id":"security","roles":["gone"],"state":3},
  {"project_id":"security","roles":["named-inactive"],"state":"USER_GRANT_STATE_INACTIVE"},
  {"project_id":"security","roles":["named-active"],"state":"USER_GRANT_STATE_ACTIVE"}]}`

func scopedMode(m mode, claims ...string) config {
	return config{claims: claims, mode: m, dir: fakeDir{m: map[string]string{"wazuh-client": "security"}, ready: true}}
}

func TestGrantsFrom_SkipsInactiveAndRemoved(t *testing.T) {
	var p map[string]any
	if err := json.Unmarshal([]byte(payload), &p); err != nil {
		t.Fatal(err)
	}
	got := flatten(grantsFrom(p), nil)
	want := []string{"operator", "admin", "group-prplanit", "named-active"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v, want %v", got, want)
	}
}

func TestProjectMode_EmitsOnlyTheAppsProject(t *testing.T) {
	_, body := post(t, newMux(scopedMode(modeProject, "roles")), payload, nil)
	want := `{"append_claims":[{"key":"roles","value":["operator","group-prplanit","named-active"]}]}`
	if strings.TrimSpace(body) != want {
		t.Fatalf("body=%s want=%s", body, want)
	}
}

func TestProjectMode_UnknownClientEmitsNothing(t *testing.T) {
	cfg := scopedMode(modeProject, "roles")
	cfg.dir = fakeDir{m: map[string]string{}, ready: true}
	_, body := post(t, newMux(cfg), payload, nil)
	if strings.TrimSpace(body) != "{}" {
		t.Fatalf("unresolved client must get no roles, got %s", body)
	}
}

func TestProjectMode_NoClientIDEmitsNothing(t *testing.T) {
	_, body := post(t, newMux(scopedMode(modeProject, "roles")), `{"user_grants":[{"project_id":"security","roles":["operator"]}]}`, nil)
	if strings.TrimSpace(body) != "{}" {
		t.Fatalf("payload without client_id must get no roles, got %s", body)
	}
}

func TestReportMode_EmitsEverything(t *testing.T) {
	_, body := post(t, newMux(scopedMode(modeReport, "roles")), payload, nil)
	want := `{"append_claims":[{"key":"roles","value":["operator","admin","group-prplanit","named-active"]}]}`
	if strings.TrimSpace(body) != want {
		t.Fatalf("body=%s want=%s", body, want)
	}
}

func TestMultipleClaimNames(t *testing.T) {
	_, body := post(t, newMux(scopedMode(modeProject, "roles", "groups")), payload, nil)
	want := `{"append_claims":[{"key":"roles","value":["operator","group-prplanit","named-active"]},{"key":"groups","value":["operator","group-prplanit","named-active"]}]}`
	if strings.TrimSpace(body) != want {
		t.Fatalf("body=%s want=%s", body, want)
	}
}

func TestReadyz(t *testing.T) {
	for _, c := range []struct {
		name string
		cfg  config
		code int
	}{
		{"all mode needs no directory", allMode("roles", ""), 200},
		{"directory synced", scopedMode(modeProject, "roles"), 200},
		{"directory not synced", config{claims: []string{"roles"}, mode: modeProject, dir: fakeDir{}}, 503},
	} {
		t.Run(c.name, func(t *testing.T) {
			rec := httptest.NewRecorder()
			newMux(c.cfg).ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/readyz", nil))
			if rec.Code != c.code {
				t.Fatalf("readyz: want %d, got %d", c.code, rec.Code)
			}
		})
	}
}

func TestLoadConfig(t *testing.T) {
	cases := []struct {
		name    string
		env     map[string]string
		wantErr string
	}{
		{"default is project mode and needs the API", map[string]string{}, "needs ZITADEL_API_URL and ZITADEL_TOKEN"},
		{"all mode needs nothing", map[string]string{"MODE": "all"}, ""},
		{"project mode with API", map[string]string{"ZITADEL_API_URL": "http://z", "ZITADEL_TOKEN": "t"}, ""},
		{"old CLAIM_NAME is refused", map[string]string{"MODE": "all", "CLAIM_NAME": "roles"}, "CLAIM_NAME was replaced by CLAIM_NAMES"},
		{"unknown mode", map[string]string{"MODE": "everything"}, `want project, report or all`},
		{"empty claim list", map[string]string{"MODE": "all", "CLAIM_NAMES": " , "}, "names no claim"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			for _, k := range []string{"MODE", "CLAIM_NAME", "CLAIM_NAMES", "ZITADEL_API_URL", "ZITADEL_TOKEN"} {
				t.Setenv(k, c.env[k])
			}
			_, _, err := loadConfig()
			if c.wantErr == "" && err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if c.wantErr != "" && (err == nil || !strings.Contains(err.Error(), c.wantErr)) {
				t.Fatalf("want error containing %q, got %v", c.wantErr, err)
			}
		})
	}
}
