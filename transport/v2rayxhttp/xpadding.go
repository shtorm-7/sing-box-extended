package xhttp

import (
	"crypto/rand"
	"math"
	"net/http"
	"net/url"
	"strings"

	"github.com/sagernet/sing-box/option"
	"golang.org/x/net/http2/hpack"
)

type PaddingMethod string

const (
	PaddingMethodRepeatX  PaddingMethod = "repeat-x"
	PaddingMethodTokenish PaddingMethod = "tokenish"
)

const charsetBase62 = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"

// Huffman encoding gives ~20% size reduction for base62 sequences
const avgHuffmanBytesPerCharBase62 = 0.8

const validationTolerance = 2

type XPaddingPlacement struct {
	Placement string
	Key       string
	Header    string
	RawURL    string
}

type XPaddingConfig struct {
	Length    int
	Placement XPaddingPlacement
	Method    PaddingMethod
}

func randStringFromCharset(n int, charset string) (string, bool) {
	if n <= 0 || len(charset) == 0 {
		return "", false
	}
	m := len(charset)
	limit := byte(256 - (256 % m))
	result := make([]byte, n)
	i := 0
	buf := make([]byte, 256)
	for i < n {
		if _, err := rand.Read(buf); err != nil {
			return "", false
		}
		for _, rb := range buf {
			if rb >= limit {
				continue
			}
			result[i] = charset[int(rb)%m]
			i++
			if i == n {
				break
			}
		}
	}
	return string(result), true
}

func absInt(x int) int {
	if x < 0 {
		return -x
	}
	return x
}

func GenerateTokenishPaddingBase62(targetHuffmanBytes int) string {
	n := int(math.Ceil(float64(targetHuffmanBytes) / avgHuffmanBytesPerCharBase62))
	if n < 1 {
		n = 1
	}
	randBase62Str, ok := randStringFromCharset(n, charsetBase62)
	if !ok {
		return ""
	}
	const maxIter = 150
	adjustChar := byte('X')
	// Adjust until close enough
	for iter := 0; iter < maxIter; iter++ {
		currentLength := int(hpack.HuffmanEncodeLength(randBase62Str))
		diff := currentLength - targetHuffmanBytes

		if absInt(diff) <= validationTolerance {
			return randBase62Str
		}
		if diff < 0 {
			// Too small -> append padding char(s)
			randBase62Str += string(adjustChar)
			// Avoid a long run of identical chars
			if adjustChar == 'X' {
				adjustChar = 'Z'
			} else {
				adjustChar = 'X'
			}
		} else {
			// Too big -> remove from the end
			if len(randBase62Str) <= 1 {
				return randBase62Str
			}
			randBase62Str = randBase62Str[:len(randBase62Str)-1]
		}
	}
	return randBase62Str
}

func GeneratePadding(method PaddingMethod, length int) string {
	if length <= 0 {
		return ""
	}
	// https://www.rfc-editor.org/rfc/rfc7541.html#appendix-B
	// h2's HPACK Header Compression feature employs a huffman encoding using a static table.
	// 'X' and 'Z' are assigned an 8 bit code, so HPACK compression won't change actual padding length on the wire.
	// https://www.rfc-editor.org/rfc/rfc9204.html#section-4.1.2-2
	// h3's similar QPACK feature uses the same huffman table.
	switch method {
	case PaddingMethodRepeatX:
		return strings.Repeat("X", length)
	case PaddingMethodTokenish:
		paddingValue := GenerateTokenishPaddingBase62(length)
		if paddingValue == "" {
			return strings.Repeat("X", length)
		}
		return paddingValue
	default:
		return strings.Repeat("X", length)
	}
}

func ApplyPaddingToCookie(req *http.Request, name, value string) {
	if req == nil || name == "" || value == "" {
		return
	}
	req.AddCookie(&http.Cookie{
		Name:  name,
		Value: value,
		Path:  "/",
	})
}

func ApplyPaddingToResponseCookie(writer http.ResponseWriter, name, value string) {
	if name == "" || value == "" {
		return
	}
	http.SetCookie(writer, &http.Cookie{
		Name:  name,
		Value: value,
		Path:  "/",
	})
}

func ApplyPaddingToQuery(u *url.URL, key, value string) {
	if u == nil || key == "" || value == "" {
		return
	}
	q := u.Query()
	q.Set(key, value)
	u.RawQuery = q.Encode()
}

func ApplyXPaddingToHeader(h http.Header, config XPaddingConfig) {
	if h == nil {
		return
	}
	paddingValue := GeneratePadding(config.Method, config.Length)
	switch p := config.Placement; p.Placement {
	case option.PlacementHeader:
		if p.Header != "" {
			h.Set(p.Header, paddingValue)
		}
	case option.PlacementQueryInHeader:
		if p.Header == "" || p.Key == "" {
			return
		}
		u, err := url.Parse(p.RawURL)
		if err != nil || u == nil {
			// No source URL (e.g., server response side): fall back to a
			// synthetic relative URL so the wire shape stays "?key=value".
			u = &url.URL{Path: "/"}
		}
		u.RawQuery = p.Key + "=" + paddingValue
		h.Set(p.Header, u.String())
	}
}

func ApplyXPaddingToRequest(req *http.Request, config XPaddingConfig) {
	if req == nil {
		return
	}
	if req.Header == nil {
		req.Header = make(http.Header)
	}
	placement := config.Placement.Placement
	if placement == option.PlacementHeader || placement == option.PlacementQueryInHeader {
		ApplyXPaddingToHeader(req.Header, config)
		return
	}
	paddingValue := GeneratePadding(config.Method, config.Length)
	switch placement {
	case option.PlacementCookie:
		ApplyPaddingToCookie(req, config.Placement.Key, paddingValue)
	case option.PlacementQuery:
		ApplyPaddingToQuery(req.URL, config.Placement.Key, paddingValue)
	}
}

func ApplyXPaddingToResponse(writer http.ResponseWriter, config XPaddingConfig) {
	if writer == nil {
		return
	}
	placement := config.Placement.Placement
	switch placement {
	case option.PlacementHeader, option.PlacementQueryInHeader:
		ApplyXPaddingToHeader(writer.Header(), config)
	case option.PlacementCookie:
		paddingValue := GeneratePadding(config.Method, config.Length)
		ApplyPaddingToResponseCookie(writer, config.Placement.Key, paddingValue)
	case option.PlacementQuery:
		// Query placement makes no sense for a response (no request URL).
		// Fall back to a header so the response still carries padding for
		// traffic-shape symmetry.
		paddingValue := GeneratePadding(config.Method, config.Length)
		headerName := config.Placement.Header
		if headerName == "" {
			headerName = "X-Padding"
		}
		writer.Header().Set(headerName, paddingValue)
	}
}

// extractFromPlacement reads the padding value from a single placement only.
// Returns ("", "") if not found there.
func extractFromPlacement(req *http.Request, placement, key, header string) (string, string) {
	switch placement {
	case option.PlacementCookie:
		if key == "" {
			return "", ""
		}
		cookie, err := req.Cookie(key)
		if err != nil || cookie == nil || cookie.Value == "" {
			return "", ""
		}
		return cookie.Value, option.PlacementCookie + ", key=" + key
	case option.PlacementHeader:
		if header == "" {
			return "", ""
		}
		v := req.Header.Get(header)
		if v == "" {
			return "", ""
		}
		return v, option.PlacementHeader + "=" + header
	case option.PlacementQueryInHeader:
		if header == "" || key == "" {
			return "", ""
		}
		hv := req.Header.Get(header)
		if hv == "" {
			return "", ""
		}
		parsedURL, err := url.Parse(hv)
		if err != nil || parsedURL == nil {
			return "", ""
		}
		v := parsedURL.Query().Get(key)
		if v == "" {
			return "", ""
		}
		return v, option.PlacementQueryInHeader + "=" + header + ", key=" + key
	case option.PlacementQuery:
		if key == "" || req.URL == nil {
			return "", ""
		}
		v := req.URL.Query().Get(key)
		if v == "" {
			return "", ""
		}
		return v, option.PlacementQuery + ", key=" + key
	}
	return "", ""
}

func ExtractXPaddingFromRequest(options *option.V2RayXHTTPBaseOptions, req *http.Request, obfsMode bool) (string, string) {
	if req == nil {
		return "", ""
	}
	if !obfsMode {
		// Non-obfs (legacy) mode: padding is in Referer query, or URL query
		// if no Referer is present. Never fall through into the obfs paths.
		referrer := req.Header.Get("Referer")
		if referrer != "" {
			referrerURL, err := url.Parse(referrer)
			if err != nil {
				return "", option.PlacementQueryInHeader + "=Referer (unparseable)"
			}
			return referrerURL.Query().Get("x_padding"), option.PlacementQueryInHeader + "=Referer, key=x_padding"
		}
		if req.URL != nil {
			return req.URL.Query().Get("x_padding"), option.PlacementQuery + ", key=x_padding"
		}
		return "", ""
	}

	// obfs mode: read padding from the configured placement.
	key := options.XPaddingKey
	header := options.XPaddingHeader
	placement := options.XPaddingPlacement

	if v, p := extractFromPlacement(req, placement, key, header); v != "" {
		return v, p
	}

	// Fallback: probe the other placements in case a peer using a different
	// configuration (e.g. an older client) is talking to this server. This
	// preserves interoperability without weakening the configured path.
	fallbacks := []string{
		option.PlacementHeader,
		option.PlacementQueryInHeader,
		option.PlacementCookie,
		option.PlacementQuery,
	}
	for _, fp := range fallbacks {
		if fp == placement {
			continue
		}
		if v, p := extractFromPlacement(req, fp, key, header); v != "" {
			return v, p
		}
	}

	// Final fallback: legacy Referer + x_padding (used by the non-obfs client
	// path and historical sing-box releases).
	if referrer := req.Header.Get("Referer"); referrer != "" {
		if referrerURL, err := url.Parse(referrer); err == nil {
			if v := referrerURL.Query().Get("x_padding"); v != "" {
				return v, option.PlacementQueryInHeader + "=Referer, key=x_padding"
			}
		}
	}
	if req.URL != nil {
		if v := req.URL.Query().Get("x_padding"); v != "" {
			return v, option.PlacementQuery + ", key=x_padding"
		}
	}
	return "", ""
}

func IsPaddingValid(options *option.V2RayXHTTPBaseOptions, paddingValue string, from, to int32, method PaddingMethod) bool {
	if paddingValue == "" {
		return false
	}
	if to <= 0 {
		r := options.GetNormalizedXPaddingBytes()
		from, to = r.From, r.To
	}
	switch method {
	case PaddingMethodRepeatX:
		n := int32(len(paddingValue))
		return n >= from && n <= to
	case PaddingMethodTokenish:
		const tolerance = int32(validationTolerance)
		n := int32(hpack.HuffmanEncodeLength(paddingValue))
		f := from - tolerance
		t := to + tolerance
		if f < 0 {
			f = 0
		}
		return n >= f && n <= t
	default:
		n := int32(len(paddingValue))
		return n >= from && n <= to
	}
}
