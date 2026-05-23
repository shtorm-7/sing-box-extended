package xhttp

import (
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	Xbadoption "github.com/sagernet/sing-box/common/xray/json/badoption"
	"github.com/sagernet/sing-box/option"
)

func opts(placement, key, header, method string) *option.V2RayXHTTPBaseOptions {
	return &option.V2RayXHTTPBaseOptions{
		XPaddingBytes:     Xbadoption.Range{From: 100, To: 1000},
		XPaddingPlacement: placement,
		XPaddingKey:       key,
		XPaddingHeader:    header,
		XPaddingMethod:    method,
	}
}

// e2e: client sends real HTTP request via net/http test server, server extracts padding.
func runE2E(t *testing.T, o *option.V2RayXHTTPBaseOptions, obfsMode bool) (string, string) {
	t.Helper()

	resultVal := ""
	resultPlace := ""
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resultVal, resultPlace = ExtractXPaddingFromRequest(o, r, obfsMode)
		w.WriteHeader(200)
	}))
	defer srv.Close()

	u, _ := url.Parse(srv.URL + "/xhttp/")
	req, _ := http.NewRequest("POST", u.String(), strings.NewReader("hello"))

	length := 250
	cfg := XPaddingConfig{Length: length}
	if obfsMode {
		cfg.Placement = XPaddingPlacement{
			Placement: o.XPaddingPlacement,
			Key:       o.XPaddingKey,
			Header:    o.XPaddingHeader,
			RawURL:    req.URL.String(),
		}
		cfg.Method = PaddingMethod(o.XPaddingMethod)
	} else {
		cfg.Placement = XPaddingPlacement{
			Placement: option.PlacementQueryInHeader,
			Key:       "x_padding",
			Header:    "Referer",
			RawURL:    req.URL.String(),
		}
	}
	ApplyXPaddingToRequest(req, cfg)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()

	return resultVal, resultPlace
}

func TestE2E_ObfsHeaderXPadding(t *testing.T) {
	o := opts("header", "x_padding", "X-Padding", "repeat-x")
	val, place := runE2E(t, o, true)
	t.Logf("placement=%s val-len=%d", place, len(val))
	if !IsPaddingValid(o, val, 100, 1000, "repeat-x") {
		t.Fatalf("not valid: place=%s len=%d", place, len(val))
	}
}

func TestE2E_ObfsHeaderCustom(t *testing.T) {
	o := opts("header", "mykey", "X-My-Pad", "repeat-x")
	val, place := runE2E(t, o, true)
	t.Logf("placement=%s val-len=%d", place, len(val))
	if !IsPaddingValid(o, val, 100, 1000, "repeat-x") {
		t.Fatalf("not valid: place=%s len=%d", place, len(val))
	}
}

func TestE2E_ObfsCookie(t *testing.T) {
	o := opts("cookie", "x_padding", "X-Padding", "repeat-x")
	val, place := runE2E(t, o, true)
	t.Logf("placement=%s val-len=%d", place, len(val))
	if !IsPaddingValid(o, val, 100, 1000, "repeat-x") {
		t.Fatalf("not valid: place=%s len=%d", place, len(val))
	}
}

func TestE2E_ObfsCookieCustomKey(t *testing.T) {
	o := opts("cookie", "mypad", "X-Padding", "repeat-x")
	val, place := runE2E(t, o, true)
	t.Logf("placement=%s val-len=%d", place, len(val))
	if !IsPaddingValid(o, val, 100, 1000, "repeat-x") {
		t.Fatalf("not valid: place=%s len=%d", place, len(val))
	}
}

func TestE2E_ObfsQuery(t *testing.T) {
	o := opts("query", "x_padding", "X-Padding", "repeat-x")
	val, place := runE2E(t, o, true)
	t.Logf("placement=%s val-len=%d", place, len(val))
	if !IsPaddingValid(o, val, 100, 1000, "repeat-x") {
		t.Fatalf("not valid: place=%s len=%d", place, len(val))
	}
}

func TestE2E_ObfsQueryCustomKey(t *testing.T) {
	o := opts("query", "mypad", "X-Padding", "repeat-x")
	val, place := runE2E(t, o, true)
	t.Logf("placement=%s val-len=%d", place, len(val))
	if !IsPaddingValid(o, val, 100, 1000, "repeat-x") {
		t.Fatalf("not valid: place=%s len=%d", place, len(val))
	}
}

func TestE2E_ObfsQueryInHeader(t *testing.T) {
	o := opts("queryInHeader", "x_padding", "X-Padding", "repeat-x")
	val, place := runE2E(t, o, true)
	t.Logf("placement=%s val-len=%d", place, len(val))
	if !IsPaddingValid(o, val, 100, 1000, "repeat-x") {
		t.Fatalf("not valid: place=%s len=%d", place, len(val))
	}
}

func TestE2E_ObfsQueryInHeaderReferer(t *testing.T) {
	o := opts("queryInHeader", "x_padding", "Referer", "repeat-x")
	val, place := runE2E(t, o, true)
	t.Logf("placement=%s val-len=%d", place, len(val))
	if !IsPaddingValid(o, val, 100, 1000, "repeat-x") {
		t.Fatalf("not valid: place=%s len=%d", place, len(val))
	}
}

func TestE2E_NoObfs(t *testing.T) {
	o := opts("queryInHeader", "x_padding", "X-Padding", "repeat-x")
	val, place := runE2E(t, o, false)
	t.Logf("placement=%s val-len=%d", place, len(val))
	if !IsPaddingValid(o, val, 100, 1000, "repeat-x") {
		t.Fatalf("not valid: place=%s len=%d", place, len(val))
	}
}

func TestE2E_ObfsTokenish(t *testing.T) {
	o := opts("header", "x_padding", "X-Padding", "tokenish")
	val, place := runE2E(t, o, true)
	t.Logf("placement=%s val-len=%d", place, len(val))
	if !IsPaddingValid(o, val, 100, 1000, "tokenish") {
		t.Fatalf("not valid: place=%s len=%d", place, len(val))
	}
}

func TestE2E_ObfsTokenishQueryInHeader(t *testing.T) {
	o := opts("queryInHeader", "x_padding", "X-Padding", "tokenish")
	val, place := runE2E(t, o, true)
	t.Logf("placement=%s val-len=%d", place, len(val))
	if !IsPaddingValid(o, val, 100, 1000, "tokenish") {
		t.Fatalf("not valid: place=%s len=%d", place, len(val))
	}
}

// Cross-config: server expects header placement, but client (e.g. legacy
// sing-box) is still sending Referer + x_padding. The fallback path should
// allow the server to accept the request.
func TestE2E_ObfsServerWithLegacyClient(t *testing.T) {
	srvOpts := opts("header", "x_padding", "X-Padding", "repeat-x")

	resultVal := ""
	resultPlace := ""
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resultVal, resultPlace = ExtractXPaddingFromRequest(srvOpts, r, true)
		w.WriteHeader(200)
	}))
	defer srv.Close()

	u, _ := url.Parse(srv.URL + "/xhttp/")
	req, _ := http.NewRequest("POST", u.String(), strings.NewReader("hello"))

	// Legacy client behaviour: Referer-based padding.
	cfg := XPaddingConfig{Length: 250}
	cfg.Placement = XPaddingPlacement{
		Placement: option.PlacementQueryInHeader,
		Key:       "x_padding",
		Header:    "Referer",
		RawURL:    req.URL.String(),
	}
	ApplyXPaddingToRequest(req, cfg)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()

	t.Logf("placement=%s val-len=%d", resultPlace, len(resultVal))
	if !IsPaddingValid(srvOpts, resultVal, 100, 1000, "repeat-x") {
		t.Fatalf("not valid: place=%s len=%d", resultPlace, len(resultVal))
	}
}

// A stale cookie sharing the configured key must not shadow the real padding
// that lives in the configured placement (here: a header).
func TestE2E_StaleCookieDoesNotMaskHeader(t *testing.T) {
	srvOpts := opts("header", "x_padding", "X-Padding", "repeat-x")

	resultVal := ""
	resultPlace := ""
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resultVal, resultPlace = ExtractXPaddingFromRequest(srvOpts, r, true)
		w.WriteHeader(200)
	}))
	defer srv.Close()

	u, _ := url.Parse(srv.URL + "/xhttp/")
	req, _ := http.NewRequest("POST", u.String(), strings.NewReader("hello"))

	// Real padding in the header (as the configuration expects).
	cfg := XPaddingConfig{Length: 250}
	cfg.Placement = XPaddingPlacement{
		Placement: "header",
		Key:       "x_padding",
		Header:    "X-Padding",
		RawURL:    req.URL.String(),
	}
	cfg.Method = "repeat-x"
	ApplyXPaddingToRequest(req, cfg)

	// Add a stale cookie with the same key but a too-short value.
	req.AddCookie(&http.Cookie{Name: "x_padding", Value: "short"})

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()

	t.Logf("placement=%s val-len=%d", resultPlace, len(resultVal))
	if !IsPaddingValid(srvOpts, resultVal, 100, 1000, "repeat-x") {
		t.Fatalf("stale cookie should not be picked up: place=%s len=%d", resultPlace, len(resultVal))
	}
	if !strings.Contains(resultPlace, "header") {
		t.Fatalf("expected the configured header placement to win, got: %s", resultPlace)
	}
}
