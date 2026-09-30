/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2025 WireGuard LLC. All Rights Reserved.
 */

package device

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"strings"
	"testing"
)

// newUAPITestDevice returns a *Device suitable for exercising
// IpcSetOperation/IpcGetOperation directly, without a real tun.Device or
// conn.Bind (neither is touched by the device-line handlers under test).
func newUAPITestDevice() *Device {
	d := &Device{log: NewLogger(LogLevelSilent, "")}

	var r UintRange
	r.FromUint32(MessageInitiationType, MessageInitiationType)
	d.headers.init.Store(r)
	r.FromUint32(MessageResponseType, MessageResponseType)
	d.headers.response.Store(r)
	r.FromUint32(MessageCookieReplyType, MessageCookieReplyType)
	d.headers.cookie.Store(r)
	r.FromUint32(MessageTransportType, MessageTransportType)
	d.headers.transport.Store(r)

	return d
}

func setUAPI(t *testing.T, d *Device, body string) error {
	t.Helper()
	if !strings.HasSuffix(body, "\n\n") {
		if strings.HasSuffix(body, "\n") {
			body += "\n"
		} else {
			body += "\n\n"
		}
	}
	return d.IpcSetOperation(strings.NewReader(body))
}

func getUAPI(t *testing.T, d *Device) string {
	t.Helper()
	var buf bytes.Buffer
	if err := d.IpcGetOperation(&buf); err != nil {
		t.Fatalf("IpcGetOperation: %v", err)
	}
	return buf.String()
}

// TestUAPI_S1S4_SetGetRoundTrip sweeps every S1-S4 key individually across
// a range of values and checks it is both accepted and reported back
// correctly, and that unrelated padding keys stay at zero.
func TestUAPI_S1S4_SetGetRoundTrip(t *testing.T) {
	keys := []string{"s1", "s2", "s3", "s4"}
	values := []uint32{0, 1, 4, 12, 16, 64, 100, 65535}

	for _, key := range keys {
		for _, value := range values {
			key, value := key, value
			t.Run(fmt.Sprintf("%s=%d", key, value), func(t *testing.T) {
				d := newUAPITestDevice()
				if err := setUAPI(t, d, fmt.Sprintf("%s=%d", key, value)); err != nil {
					t.Fatalf("set %s=%d: %v", key, value, err)
				}

				out := getUAPI(t, d)
				wantLine := fmt.Sprintf("%s=%d", key, value)
				if value == 0 {
					if strings.Contains(out, key+"=") {
						t.Fatalf("expected no %s= line for zero value, got:\n%s", key, out)
					}
					return
				}
				if !strings.Contains(out, wantLine) {
					t.Fatalf("expected %q in output, got:\n%s", wantLine, out)
				}

				// The other three S-keys must remain absent (still zero).
				for _, other := range keys {
					if other == key {
						continue
					}
					if strings.Contains(out, other+"=") {
						t.Fatalf("unrelated key %s= unexpectedly present:\n%s", other, out)
					}
				}
			})
		}
	}
}

// TestUAPI_S1S4_AllTogether sets all four padding keys in a single
// transaction (mirroring a real UAPI batch) and checks all four are
// reported back.
func TestUAPI_S1S4_AllTogether(t *testing.T) {
	combos := []struct{ s1, s2, s3, s4 uint32 }{
		{1, 2, 3, 4},
		{12, 12, 12, 12},
		{0, 0, 0, 100},
		{100, 0, 0, 0},
		{65535, 65535, 65535, 65535},
	}

	for _, c := range combos {
		c := c
		t.Run(fmt.Sprintf("s1=%d,s2=%d,s3=%d,s4=%d", c.s1, c.s2, c.s3, c.s4), func(t *testing.T) {
			d := newUAPITestDevice()
			body := fmt.Sprintf("s1=%d\ns2=%d\ns3=%d\ns4=%d", c.s1, c.s2, c.s3, c.s4)
			if err := setUAPI(t, d, body); err != nil {
				t.Fatalf("set failed: %v", err)
			}

			out := getUAPI(t, d)
			for key, val := range map[string]uint32{"s1": c.s1, "s2": c.s2, "s3": c.s3, "s4": c.s4} {
				if val == 0 {
					if strings.Contains(out, key+"=") {
						t.Fatalf("expected no %s= line, got:\n%s", key, out)
					}
					continue
				}
				want := fmt.Sprintf("%s=%d", key, val)
				if !strings.Contains(out, want) {
					t.Fatalf("expected %q, got:\n%s", want, out)
				}
			}
		})
	}
}

// TestUAPI_S1S4_IncrementalUpdatesPreserveOthers verifies that setting one
// padding key in a later UAPI transaction does not clobber a value set by
// an earlier transaction (exercises ipcSetDevice.fromDevice pre-population).
func TestUAPI_S1S4_IncrementalUpdatesPreserveOthers(t *testing.T) {
	d := newUAPITestDevice()

	if err := setUAPI(t, d, "s1=10"); err != nil {
		t.Fatalf("set s1: %v", err)
	}
	if err := setUAPI(t, d, "s2=20"); err != nil {
		t.Fatalf("set s2: %v", err)
	}
	if err := setUAPI(t, d, "s4=40"); err != nil {
		t.Fatalf("set s4: %v", err)
	}

	out := getUAPI(t, d)
	for _, want := range []string{"s1=10", "s2=20", "s4=40"} {
		if !strings.Contains(out, want) {
			t.Fatalf("expected %q to survive incremental updates, got:\n%s", want, out)
		}
	}
	if strings.Contains(out, "s3=") {
		t.Fatalf("s3 should remain unset, got:\n%s", out)
	}
}

// TestUAPI_ContentPaddingAddition_SetGetRoundTrip covers the random content
// padding feature end to end through the UAPI.
func TestUAPI_ContentPaddingAddition_SetGetRoundTrip(t *testing.T) {
	cases := []string{"0", "5", "5-5", "5-100", "0-1400"}

	for _, in := range cases {
		in := in
		t.Run(in, func(t *testing.T) {
			d := newUAPITestDevice()
			if err := setUAPI(t, d, "content_padding_addition="+in); err != nil {
				t.Fatalf("set: %v", err)
			}

			out := getUAPI(t, d)

			var r UintRange
			if err := r.FromString(in); err != nil {
				t.Fatalf("FromString(%q): %v", in, err)
			}

			if r.IsZero() {
				if strings.Contains(out, "content_padding_addition=") {
					t.Fatalf("expected no content_padding_addition= line for zero range, got:\n%s", out)
				}
				return
			}

			want := "content_padding_addition=" + r.ToString()
			if !strings.Contains(out, want) {
				t.Fatalf("expected %q, got:\n%s", want, out)
			}
		})
	}
}

// TestUAPI_S1S4_InvalidValues checks that malformed S1-S4 values are
// rejected with an error and never silently applied.
func TestUAPI_S1S4_InvalidValues(t *testing.T) {
	invalid := []string{"abc", "-1", "", "5.5", "99999999999999", "1 2"}

	for _, key := range []string{"s1", "s2", "s3", "s4"} {
		for _, val := range invalid {
			key, val := key, val
			t.Run(fmt.Sprintf("%s=%q", key, val), func(t *testing.T) {
				d := newUAPITestDevice()
				err := setUAPI(t, d, fmt.Sprintf("%s=%s", key, val))
				if err == nil {
					t.Fatalf("expected error for %s=%q, got none", key, val)
				}
			})
		}
	}
}

// TestUAPI_HeaderProtection_RequiresMinimumPadding directly regression-tests
// the fix to the off-by-one in the padding-validation error message
// (device/uapi.go: mergeWithDevice used to report "S0"/"S1"/"S2"/"S3"
// instead of "S1"/"S2"/"S3"/"S4"). It also verifies the underlying
// validation logic: setting header_protection_key requires all four S1-S4
// paddings to be at least HeaderCipherNonceSize.
func TestUAPI_HeaderProtection_RequiresMinimumPadding(t *testing.T) {
	var key HeaderCipherKey
	if _, err := rand.Read(key[:]); err != nil {
		t.Fatalf("rand.Read: %v", err)
	}
	keyHex := hex.EncodeToString(key[:])

	// One padding at a time is left too small (below HeaderCipherNonceSize),
	// the rest are valid. Each case must fail, naming the correct S-number.
	cases := []struct {
		name           string
		s1, s2, s3, s4 uint32
		wantSubstr     string
	}{
		{"s1_too_small", 0, 12, 12, 12, "S1"},
		{"s2_too_small", 12, 11, 12, 12, "S2"},
		{"s3_too_small", 12, 12, 5, 12, "S3"},
		{"s4_too_small", 12, 12, 12, 0, "S4"},
		{"all_too_small", 0, 0, 0, 0, "S1"},
	}

	for _, c := range cases {
		c := c
		t.Run(c.name, func(t *testing.T) {
			d := newUAPITestDevice()
			body := fmt.Sprintf(
				"s1=%d\ns2=%d\ns3=%d\ns4=%d\nheader_protection_key=%s",
				c.s1, c.s2, c.s3, c.s4, keyHex,
			)
			err := setUAPI(t, d, body)
			if err == nil {
				t.Fatalf("expected error, got none")
			}
			if !strings.Contains(err.Error(), c.wantSubstr) {
				t.Fatalf("error %q does not mention %q", err.Error(), c.wantSubstr)
			}
			// The old, buggy message used the raw 0-based loop index, so
			// it could only ever say S0-S3 -- never S4, and always one
			// number short of the field it was actually complaining about.
			if strings.Contains(err.Error(), "S0") {
				t.Fatalf("error %q contains the pre-fix off-by-one field name S0", err.Error())
			}
		})
	}
}

// TestUAPI_HeaderProtection_AcceptsSufficientPadding is the positive
// counterpart: when every S1-S4 padding is >= HeaderCipherNonceSize, setting
// header_protection_key must succeed and round-trip through Get.
func TestUAPI_HeaderProtection_AcceptsSufficientPadding(t *testing.T) {
	var key HeaderCipherKey
	if _, err := rand.Read(key[:]); err != nil {
		t.Fatalf("rand.Read: %v", err)
	}
	keyHex := hex.EncodeToString(key[:])

	for _, padding := range []uint32{HeaderCipherNonceSize, HeaderCipherNonceSize + 1, 16, 32, 100} {
		padding := padding
		t.Run(fmt.Sprintf("padding=%d", padding), func(t *testing.T) {
			d := newUAPITestDevice()
			body := fmt.Sprintf(
				"s1=%d\ns2=%d\ns3=%d\ns4=%d\nheader_protection_key=%s",
				padding, padding, padding, padding, keyHex,
			)
			if err := setUAPI(t, d, body); err != nil {
				t.Fatalf("unexpected error at padding=%d: %v", padding, err)
			}

			out := getUAPI(t, d)
			if !strings.Contains(out, "header_protection_key="+keyHex) {
				t.Fatalf("expected header_protection_key to round-trip, got:\n%s", out)
			}
		})
	}
}

// TestUAPI_HeaderProtection_PaddingShrunkAfterKeySet checks that once a
// header_protection_key is active, a later transaction that only lowers one
// S-value below the minimum is still rejected (the validation re-reads the
// *previous* padding values for keys not touched in this transaction via
// ipcSetDevice.fromDevice, so it must not regress to the old zero-value
// defaults).
func TestUAPI_HeaderProtection_PaddingShrunkAfterKeySet(t *testing.T) {
	var key HeaderCipherKey
	if _, err := rand.Read(key[:]); err != nil {
		t.Fatalf("rand.Read: %v", err)
	}
	keyHex := hex.EncodeToString(key[:])

	d := newUAPITestDevice()
	initial := fmt.Sprintf("s1=12\ns2=12\ns3=12\ns4=12\nheader_protection_key=%s", keyHex)
	if err := setUAPI(t, d, initial); err != nil {
		t.Fatalf("initial set failed: %v", err)
	}

	// Now try to shrink s2 below the minimum in a follow-up transaction
	// that doesn't even mention header_protection_key.
	err := setUAPI(t, d, "s2=5")
	if err == nil {
		t.Fatalf("expected error when shrinking s2 below minimum while header protection is active")
	}
	if !strings.Contains(err.Error(), "S2") {
		t.Fatalf("error %q does not mention S2", err.Error())
	}
}

// TestUAPI_HeadersMustNotOverlap exercises the H1-H4 overlap validation.
func TestUAPI_HeadersMustNotOverlap(t *testing.T) {
	d := newUAPITestDevice()
	// Default h1=1 (init) and h2=2 (response) don't overlap; force an
	// overlap between h1 and h2.
	err := setUAPI(t, d, "h1=1-10\nh2=10-20")
	if err == nil {
		t.Fatalf("expected overlap error, got none")
	}
	if !strings.Contains(err.Error(), "overlap") {
		t.Fatalf("error %q does not mention overlap", err.Error())
	}
}

// TestUAPI_HeadersNonOverlapping is the negative counterpart: disjoint
// ranges across all four header slots must be accepted.
func TestUAPI_HeadersNonOverlapping(t *testing.T) {
	d := newUAPITestDevice()
	err := setUAPI(t, d, "h1=1-10\nh2=11-20\nh3=21-30\nh4=31-40")
	if err != nil {
		t.Fatalf("unexpected error for disjoint ranges: %v", err)
	}

	out := getUAPI(t, d)
	for _, want := range []string{"h1=1-10", "h2=11-20", "h3=21-30", "h4=31-40"} {
		if !strings.Contains(out, want) {
			t.Fatalf("expected %q, got:\n%s", want, out)
		}
	}
}
