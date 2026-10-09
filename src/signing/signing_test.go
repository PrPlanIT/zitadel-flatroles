package signing

import (
	"errors"
	"strings"
	"testing"
	"time"
)

// Golden vectors computed independently of this package (Python hmac-sha256
// over "<unix>.<body>"), so this is a true cross-implementation check of the
// wire format, not a self-consistency check.
const (
	goldenKey   = "test-signing-key"
	goldenTS    = 1700000000
	goldenBody  = `{"hello":"world"}`
	goldenHex   = "89048963c2650fb7ab2d0fad0ae4e5c0f35cece10f90039a108dc55c251ec93e"
	goldenEmpty = "45e396df12e15d10102253fbe05d5666600628aa7c12b4294f2a18b959eba49b"
)

func TestComputeHeader_GoldenVector(t *testing.T) {
	got := ComputeHeader(time.Unix(goldenTS, 0), []byte(goldenBody), goldenKey)
	want := "t=1700000000,v1=" + goldenHex
	if got != want {
		t.Fatalf("header mismatch:\n got=%s\nwant=%s", got, want)
	}
}

func TestComputeHeader_GoldenVectorEmptyBody(t *testing.T) {
	got := ComputeHeader(time.Unix(goldenTS, 0), nil, goldenKey)
	want := "t=1700000000,v1=" + goldenEmpty
	if got != want {
		t.Fatalf("header mismatch:\n got=%s\nwant=%s", got, want)
	}
}

func TestValidate_RoundTrip(t *testing.T) {
	body := []byte(`{"user_grants":[{"roles":["admin"]}]}`)
	hdr := ComputeHeader(time.Now(), body, goldenKey)
	if err := Validate(body, hdr, goldenKey); err != nil {
		t.Fatalf("expected valid, got %v", err)
	}
}

func TestValidate_TamperedBody(t *testing.T) {
	body := []byte(`{"roles":["admin"]}`)
	hdr := ComputeHeader(time.Now(), body, goldenKey)
	if err := Validate([]byte(`{"roles":["root"]}`), hdr, goldenKey); !errors.Is(err, ErrNoValidSignature) {
		t.Fatalf("want ErrNoValidSignature, got %v", err)
	}
}

func TestValidate_WrongKey(t *testing.T) {
	body := []byte(`{}`)
	hdr := ComputeHeader(time.Now(), body, goldenKey)
	if err := Validate(body, hdr, "other-key"); !errors.Is(err, ErrNoValidSignature) {
		t.Fatalf("want ErrNoValidSignature, got %v", err)
	}
}

func TestValidate_TooOld(t *testing.T) {
	body := []byte(`{}`)
	hdr := ComputeHeader(time.Now().Add(-10*time.Minute), body, goldenKey)
	if err := Validate(body, hdr, goldenKey); !errors.Is(err, ErrTooOld) {
		t.Fatalf("want ErrTooOld, got %v", err)
	}
}

func TestValidate_WithinTolerance(t *testing.T) {
	body := []byte(`{}`)
	hdr := ComputeHeader(time.Now().Add(-4*time.Minute), body, goldenKey)
	if err := Validate(body, hdr, goldenKey); err != nil {
		t.Fatalf("expected valid within 5m tolerance, got %v", err)
	}
}

func TestValidate_MissingHeader(t *testing.T) {
	if err := Validate([]byte(`{}`), "", goldenKey); !errors.Is(err, ErrNotSigned) {
		t.Fatalf("want ErrNotSigned, got %v", err)
	}
}

func TestValidate_MalformedHeader(t *testing.T) {
	if err := Validate([]byte(`{}`), "t=abc,v1=zz", goldenKey); !errors.Is(err, ErrInvalidHeader) {
		t.Fatalf("want ErrInvalidHeader, got %v", err)
	}
}

func TestValidate_NoSignaturePart(t *testing.T) {
	// a well-formed timestamp but no v1 signature part
	if err := Validate([]byte(`{}`), "t=1700000000", goldenKey); !errors.Is(err, ErrNoValidSignature) {
		t.Fatalf("want ErrNoValidSignature, got %v", err)
	}
}

func TestValidate_MultipleSignaturesOneMatches(t *testing.T) {
	body := []byte(`{"a":1}`)
	now := time.Now()
	// Zitadel may rotate keys and emit several v1 parts; a match on any is valid.
	hdr := ComputeHeader(now, body, "stale-key", goldenKey)
	if strings.Count(hdr, "v1=") != 2 {
		t.Fatalf("expected two v1 parts, got %q", hdr)
	}
	if err := Validate(body, hdr, goldenKey); err != nil {
		t.Fatalf("expected valid when one of several signatures matches, got %v", err)
	}
}
