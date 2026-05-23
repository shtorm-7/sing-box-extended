package xhttp

import (
	"net/http"
	"net/url"
	"testing"

	"github.com/sagernet/sing-box/option"
	Xbadoption "github.com/sagernet/sing-box/common/xray/json/badoption"
)

func newReq(t *testing.T, raw string) *http.Request {
	t.Helper()
	req, err := http.NewRequest("POST", raw, nil)
	if err != nil {
		t.Fatal(err)
	}
	return req
}

func baseOpts(placement, key, header, method string) *option.V2RayXHTTPBaseOptions {
	return &option.V2RayXHTTPBaseOptions{
		XPaddingBytes:     Xbadoption.Range{From: 100, To: 1000},
		XPaddingPlacement: placement,
		XPaddingKey:       key,
		XPaddingHeader:    header,
		XPaddingMethod:    method,
	}
}

// roundTrip simulates client building a request then server extracting padding.
func roundTrip(t *testing.T, opts *option.V2RayXHTTPBaseOptions, obfsMode bool) (string, string, *http.Request) {
	t.Helper()
	req := newReq(t, "https://example.com/xhttp")

	length := 200
	cfg := XPaddingConfig{Length: length}
	if obfsMode {
		cfg.Placement = XPaddingPlacement{
			Placement: opts.XPaddingPlacement,
			Key:       opts.XPaddingKey,
			Header:    opts.XPaddingHeader,
			RawURL:    req.URL.String(),
		}
		cfg.Method = PaddingMethod(opts.XPaddingMethod)
	} else {
		cfg.Placement = XPaddingPlacement{
			Placement: option.PlacementQueryInHeader,
			Key:       "x_padding",
			Header:    "Referer",
			RawURL:    req.URL.String(),
		}
	}
	ApplyXPaddingToRequest(req, cfg)

	val, place := ExtractXPaddingFromRequest(opts, req, obfsMode)
	return val, place, req
}

func TestObfsModeQueryInHeaderDefault(t *testing.T) {
	o := baseOpts("queryInHeader", "x_padding", "X-Padding", "repeat-x")
	val, place, _ := roundTrip(t, o, true)
	t.Logf("placement=%s value-len=%d", place, len(val))
	if !IsPaddingValid(o, val, 100, 1000, "repeat-x") {
		t.Fatalf("validation failed: place=%s len=%d", place, len(val))
	}
}

func TestObfsModeQueryInHeaderReferer(t *testing.T) {
	o := baseOpts("queryInHeader", "x_padding", "Referer", "repeat-x")
	val, place, _ := roundTrip(t, o, true)
	t.Logf("placement=%s value-len=%d", place, len(val))
	if !IsPaddingValid(o, val, 100, 1000, "repeat-x") {
		t.Fatalf("validation failed: place=%s len=%d", place, len(val))
	}
}

func TestObfsModeHeader(t *testing.T) {
	o := baseOpts("header", "x_padding", "X-Padding", "repeat-x")
	val, place, _ := roundTrip(t, o, true)
	t.Logf("placement=%s value-len=%d", place, len(val))
	if !IsPaddingValid(o, val, 100, 1000, "repeat-x") {
		t.Fatalf("validation failed: place=%s len=%d", place, len(val))
	}
}

func TestObfsModeCookie(t *testing.T) {
	o := baseOpts("cookie", "x_padding", "X-Padding", "repeat-x")
	val, place, _ := roundTrip(t, o, true)
	t.Logf("placement=%s value-len=%d", place, len(val))
	if !IsPaddingValid(o, val, 100, 1000, "repeat-x") {
		t.Fatalf("validation failed: place=%s len=%d", place, len(val))
	}
}

func TestObfsModeQuery(t *testing.T) {
	o := baseOpts("query", "x_padding", "X-Padding", "repeat-x")
	val, place, _ := roundTrip(t, o, true)
	t.Logf("placement=%s value-len=%d", place, len(val))
	if !IsPaddingValid(o, val, 100, 1000, "repeat-x") {
		t.Fatalf("validation failed: place=%s len=%d", place, len(val))
	}
}

func TestObfsModeTokenish(t *testing.T) {
	o := baseOpts("header", "x_padding", "X-Padding", "tokenish")
	val, place, _ := roundTrip(t, o, true)
	t.Logf("placement=%s value-len=%d", place, len(val))
	if !IsPaddingValid(o, val, 100, 1000, "tokenish") {
		t.Fatalf("validation failed: place=%s len=%d", place, len(val))
	}
}

func TestNoObfsReferer(t *testing.T) {
	o := baseOpts("queryInHeader", "x_padding", "X-Padding", "repeat-x")
	val, place, _ := roundTrip(t, o, false)
	t.Logf("placement=%s value-len=%d", place, len(val))
	if !IsPaddingValid(o, val, 100, 1000, "repeat-x") {
		t.Fatalf("validation failed: place=%s len=%d", place, len(val))
	}
}

// Edge case: when obfs mode is OFF on the SERVER but ON on the CLIENT.
// (Could happen if user only configures one side)
func TestServerNoObfsClientObfsHeader(t *testing.T) {
	o := baseOpts("queryInHeader", "x_padding", "X-Padding", "repeat-x")

	// Client side (obfs mode ON, placement=header)
	req := newReq(t, "https://example.com/xhttp")
	cfg := XPaddingConfig{Length: 200}
	cfg.Placement = XPaddingPlacement{
		Placement: "header",
		Key:       "x_padding",
		Header:    "X-Padding",
		RawURL:    req.URL.String(),
	}
	cfg.Method = "repeat-x"
	ApplyXPaddingToRequest(req, cfg)

	// Server side (obfs mode OFF)
	val, place := ExtractXPaddingFromRequest(o, req, false)
	t.Logf("server (no obfs) extraction: placement=%s value-len=%d", place, len(val))
}

// Test what happens if URL parse of header succeeds but the value is not actually a URL.
func TestParseNonURLValue(t *testing.T) {
	rawValue := "XXXXXXXXXXXXXXXXXXXXXXXXX"
	parsed, err := url.Parse(rawValue)
	t.Logf("parse %q -> err=%v query[x_padding]=%q", rawValue, err, parsed.Query().Get("x_padding"))
}
