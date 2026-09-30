package option

import (
	"net/netip"

	"github.com/sagernet/sing/common/json/badoption"
)

type WireGuardEndpointOptions struct {
	System                     bool                             `json:"system,omitempty"`
	Name                       string                           `json:"name,omitempty"`
	MTU                        uint32                           `json:"mtu,omitempty"`
	Address                    badoption.Listable[netip.Prefix] `json:"address"`
	PrivateKey                 string                           `json:"private_key"`
	ListenPort                 uint16                           `json:"listen_port,omitempty"`
	Peers                      []WireGuardPeer                  `json:"peers,omitempty"`
	UDPTimeout                 badoption.Duration               `json:"udp_timeout,omitempty"`
	UDPMapping                 UDPNATBehavior                   `json:"udp_mapping,omitempty"`
	UDPFiltering               UDPNATBehavior                   `json:"udp_filtering,omitempty"`
	UDPNATMax                  uint32                           `json:"udp_nat_max,omitempty"`
	Workers                    int                              `json:"workers,omitempty"`
	PreallocatedBuffersPerPool uint32                           `json:"preallocated_buffers_per_pool,omitempty"`
	DisablePauses              bool                             `json:"disable_pauses,omitempty"`
	Amnezia                    *WireGuardAmnezia                `json:"amnezia,omitempty"`
	DialerOptions
}

type WireGuardPeer struct {
	Address                     string                           `json:"address,omitempty"`
	Port                        uint16                           `json:"port,omitempty"`
	PublicKey                   string                           `json:"public_key,omitempty"`
	PreSharedKey                string                           `json:"pre_shared_key,omitempty"`
	AllowedIPs                  badoption.Listable[netip.Prefix] `json:"allowed_ips,omitempty"`
	PersistentKeepaliveInterval uint16                           `json:"persistent_keepalive_interval,omitempty"`
}

type WireGuardAmnezia struct {
	JC                     int                      `json:"jc,omitempty"`
	JMin                   int                      `json:"jmin,omitempty"`
	JMax                   int                      `json:"jmax,omitempty"`
	S1                     int                      `json:"s1,omitempty"`
	S2                     int                      `json:"s2,omitempty"`
	S3                     int                      `json:"s3,omitempty"`
	S4                     int                      `json:"s4,omitempty"`
	H1                     *badoption.Range[uint32] `json:"h1,omitempty"`
	H2                     *badoption.Range[uint32] `json:"h2,omitempty"`
	H3                     *badoption.Range[uint32] `json:"h3,omitempty"`
	H4                     *badoption.Range[uint32] `json:"h4,omitempty"`
	I1                     string                   `json:"i1,omitempty"`
	I2                     string                   `json:"i2,omitempty"`
	I3                     string                   `json:"i3,omitempty"`
	I4                     string                   `json:"i4,omitempty"`
	I5                     string                   `json:"i5,omitempty"`
	HeaderProtectionKey    string                   `json:"header_protection_key,omitempty"`
	ContentPaddingAddition *badoption.Range[uint32] `json:"content_padding_addition,omitempty"`
	RekeyAfterTime         *badoption.Range[uint32] `json:"rekey_after_time,omitempty"`
	RekeyTimeout           *badoption.Range[uint32] `json:"rekey_timeout,omitempty"`
	RejectAfterTime        *badoption.Range[uint32] `json:"reject_after_time,omitempty"`
	KeepaliveTimeout       *badoption.Range[uint32] `json:"keepalive_timeout,omitempty"`
	MaxHandshakeAttempts   *badoption.Range[uint32] `json:"max_handshake_attempts,omitempty"`
	RandomTrailers         bool                     `json:"random_trailers,omitempty"`
	DisableCookies         bool                     `json:"disable_cookies,omitempty"`
}
