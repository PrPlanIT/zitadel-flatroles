package main

import (
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

func TestRolesFrom(t *testing.T) {
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
			if got := rolesFrom(p); !reflect.DeepEqual(got, c.want) {
				t.Fatalf("got %v, want %v", got, c.want)
			}
		})
	}
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
	newMux("roles", "").ServeHTTP(rec, req)
	if rec.Code != 200 || rec.Body.String() != "ok" {
		t.Fatalf("healthz: code=%d body=%q", rec.Code, rec.Body.String())
	}
}

func TestHandler_NoVerify_AppendsClaims(t *testing.T) {
	res, body := post(t, newMux("roles", ""), `{"user_grants":[{"roles":["admin","viewer"]}]}`, nil)
	if res.StatusCode != 200 {
		t.Fatalf("status %d", res.StatusCode)
	}
	want := `{"append_claims":[{"key":"roles","value":["admin","viewer"]}]}`
	if strings.TrimSpace(body) != want {
		t.Fatalf("body=%s want=%s", body, want)
	}
}

func TestHandler_NoRoles_ReturnsEmptyObject(t *testing.T) {
	res, body := post(t, newMux("roles", ""), `{"user_grants":[]}`, nil)
	if res.StatusCode != 200 || strings.TrimSpace(body) != "{}" {
		t.Fatalf("status=%d body=%q", res.StatusCode, body)
	}
}

func TestHandler_CustomClaimName(t *testing.T) {
	_, body := post(t, newMux("groups", ""), `{"user_grants":[{"roles":["a"]}]}`, nil)
	if !strings.Contains(body, `"key":"groups"`) {
		t.Fatalf("expected custom claim name, got %s", body)
	}
}

func TestHandler_GET_NotFound(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()
	newMux("roles", "").ServeHTTP(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("want 404, got %d", rec.Code)
	}
}

func TestHandler_Verify_ValidSignature(t *testing.T) {
	const key = "s3cr3t"
	body := `{"user_grants":[{"roles":["admin"]}]}`
	hdr := map[string]string{signing.SigningHeader: signing.ComputeHeader(time.Now(), []byte(body), key)}
	res, out := post(t, newMux("roles", key), body, hdr)
	if res.StatusCode != 200 {
		t.Fatalf("status %d", res.StatusCode)
	}
	if !strings.Contains(out, `"admin"`) {
		t.Fatalf("expected claim, got %s", out)
	}
}

func TestHandler_Verify_MissingSignature_401(t *testing.T) {
	res, _ := post(t, newMux("roles", "s3cr3t"), `{"user_grants":[]}`, nil)
	if res.StatusCode != http.StatusUnauthorized {
		t.Fatalf("want 401, got %d", res.StatusCode)
	}
}

func TestHandler_Verify_BadSignature_401(t *testing.T) {
	const key = "s3cr3t"
	body := `{"user_grants":[{"roles":["admin"]}]}`
	// signature computed over a different body → must be rejected
	hdr := map[string]string{signing.SigningHeader: signing.ComputeHeader(time.Now(), []byte(`{}`), key)}
	res, _ := post(t, newMux("roles", key), body, hdr)
	if res.StatusCode != http.StatusUnauthorized {
		t.Fatalf("want 401, got %d", res.StatusCode)
	}
}

func TestHandler_Verify_WrongKey_401(t *testing.T) {
	body := `{"user_grants":[]}`
	hdr := map[string]string{signing.SigningHeader: signing.ComputeHeader(time.Now(), []byte(body), "attacker-key")}
	res, _ := post(t, newMux("roles", "real-key"), body, hdr)
	if res.StatusCode != http.StatusUnauthorized {
		t.Fatalf("want 401, got %d", res.StatusCode)
	}
}

func TestHandler_BadJSON_400(t *testing.T) {
	res, _ := post(t, newMux("roles", ""), `{not json`, nil)
	if res.StatusCode != http.StatusBadRequest {
		t.Fatalf("want 400, got %d", res.StatusCode)
	}
}

func TestHandler_BodyTooLarge_400(t *testing.T) {
	// Exceed maxBody (1 MiB): MaxBytesReader makes io.ReadAll error before decode.
	big := strings.Repeat("a", maxBody+10)
	res, _ := post(t, newMux("roles", ""), big, nil)
	if res.StatusCode != http.StatusBadRequest {
		t.Fatalf("want 400 for oversized body, got %d", res.StatusCode)
	}
}
