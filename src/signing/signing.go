// Package signing verifies the ZITADEL-Signature header Zitadel attaches to
// every Actions v2 target request.
//
// It is a stdlib-only, wire-compatible reimplementation of the scheme in
// github.com/zitadel/zitadel-go/v3/pkg/actions (signing.go) — reimplemented
// rather than imported so the binary stays pure-stdlib and the image stays
// distroless-static with no module graph to drag in.
//
// Scheme: the signature is HMAC-SHA256 over the bytes "<unixSeconds>.<body>",
// keyed by the raw signing-key string, hex-encoded. The header carries the
// timestamp and one-or-more signatures:
//
//	ZITADEL-Signature: t=<unixSeconds>,v1=<hex>[,v1=<hex>...]
//
// The timestamp is checked against a tolerance window to reject replays.
package signing

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"
)

// SigningHeader is the HTTP header Zitadel sets on every target call.
const SigningHeader = "ZITADEL-Signature"

// DefaultTolerance is the maximum age of a signed request Zitadel accepts; we
// mirror it so a clock-skewed or replayed payload is rejected.
const DefaultTolerance = 300 * time.Second

const (
	fieldTimestamp = "t"
	fieldVersion   = "v1"
	partSeparator  = ","
)

var (
	// ErrNotSigned is returned when no ZITADEL-Signature header is present.
	ErrNotSigned = errors.New("no ZITADEL-Signature header")
	// ErrInvalidHeader is returned when the header is malformed.
	ErrInvalidHeader = errors.New("invalid ZITADEL-Signature header")
	// ErrNoValidSignature is returned when no signature in the header matches.
	ErrNoValidSignature = errors.New("no valid signature")
	// ErrTooOld is returned when the signed timestamp is outside the tolerance.
	ErrTooOld = errors.New("timestamp wasn't within tolerance")
)

type signedHeader struct {
	timestamp  time.Time
	signatures [][]byte
}

// computeSignature builds HMAC-SHA256 over "<unix>.<payload>" keyed by signingKey.
func computeSignature(t time.Time, payload []byte, signingKey string) []byte {
	mac := hmac.New(sha256.New, []byte(signingKey))
	fmt.Fprintf(mac, "%d", t.Unix())
	mac.Write([]byte("."))
	mac.Write(payload)
	return mac.Sum(nil)
}

// ComputeHeader produces a ZITADEL-Signature header value for the given time,
// payload, and one-or-more signing keys. It is the inverse of Validate and is
// primarily used in tests to exercise the verification path.
func ComputeHeader(t time.Time, payload []byte, signingKeys ...string) string {
	parts := []string{fmt.Sprintf("%s=%d", fieldTimestamp, t.Unix())}
	for _, k := range signingKeys {
		parts = append(parts, fmt.Sprintf("%s=%s", fieldVersion, hex.EncodeToString(computeSignature(t, payload, k))))
	}
	return strings.Join(parts, partSeparator)
}

func parseSignatureHeader(header string) (*signedHeader, error) {
	sh := &signedHeader{}
	if header == "" {
		return sh, ErrNotSigned
	}
	for _, pair := range strings.Split(header, partSeparator) {
		kv := strings.Split(pair, "=")
		if len(kv) != 2 {
			return sh, ErrInvalidHeader
		}
		switch kv[0] {
		case fieldTimestamp:
			ts, err := strconv.ParseInt(kv[1], 10, 64)
			if err != nil {
				return sh, ErrInvalidHeader
			}
			sh.timestamp = time.Unix(ts, 0)
		case fieldVersion:
			sig, err := hex.DecodeString(kv[1])
			if err != nil {
				continue
			}
			sh.signatures = append(sh.signatures, sig)
		default:
			continue
		}
	}
	if len(sh.signatures) == 0 {
		return sh, ErrNoValidSignature
	}
	return sh, nil
}

// Validate verifies payload against the ZITADEL-Signature header value using
// the DefaultTolerance window. A nil return means the request is authentic and
// fresh.
func Validate(payload []byte, header, signingKey string) error {
	return ValidateWithTolerance(payload, header, signingKey, DefaultTolerance)
}

// ValidateWithTolerance is Validate with an explicit freshness window.
func ValidateWithTolerance(payload []byte, header, signingKey string, tolerance time.Duration) error {
	sh, err := parseSignatureHeader(header)
	if err != nil {
		return err
	}
	if time.Since(sh.timestamp) > tolerance {
		return ErrTooOld
	}
	expected := computeSignature(sh.timestamp, payload, signingKey)
	for _, sig := range sh.signatures {
		if hmac.Equal(expected, sig) {
			return nil
		}
	}
	return ErrNoValidSignature
}
