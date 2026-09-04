package clash

import (
	"net/netip"
	"encoding/base64"
	"strings"

	"github.com/sagernet/sing/common/json/badoption"
	"github.com/sagernet/sing-box/option"
	E "github.com/sagernet/sing/common/exceptions"

	"gopkg.in/yaml.v3"
)

type ClashWireGuardReserved []uint8

func (r *ClashWireGuardReserved) UnmarshalYAML(value *yaml.Node) error {
	if value.Kind == yaml.ScalarNode {
		decoded, err := base64.StdEncoding.DecodeString(value.Value)
		if err != nil {
			return E.Cause(err, "decode reserved")
		}
		*r = decoded
		return nil
	}
	var reserved []uint8
	if err := value.Decode(&reserved); err != nil {
		return err
	}
	*r = reserved
	return nil
}

type ClashWireGuardPeerOption struct {
	Server       string                 `yaml:"server"`
	Port         int                    `yaml:"port"`
	PublicKey    string                 `yaml:"public-key,omitempty"`
	PreSharedKey string                 `yaml:"pre-shared-key,omitempty"`
	Reserved     ClashWireGuardReserved `yaml:"reserved,omitempty"`
	AllowedIPs   []string               `yaml:"allowed-ips,omitempty"`
}

type ClashWireGuardOption struct {
	DialerOptions            `yaml:",inline"`
	ClashWireGuardPeerOption `yaml:",inline"`
	Ip                       string                     `yaml:"ip,omitempty"`
	Ipv6                     string                     `yaml:"ipv6,omitempty"`
	PrivateKey               string                     `yaml:"private-key"`
	MTU                      int                        `yaml:"mtu,omitempty"`
	Workers                  int                        `yaml:"workers,omitempty"`
	PersistentKeepalive      int                        `yaml:"persistent-keepalive,omitempty"`
	Peers                    []ClashWireGuardPeerOption `yaml:"peers,omitempty"`
	AmneziaWGOption          map[string]any             `yaml:"amnezia-wg-option,omitempty"`
}

func (w *ClashWireGuardOption) Build() any {
	var address badoption.Listable[netip.Prefix]
	if w.Ip != "" {
		ip := w.Ip
		if !strings.Contains(ip, "/") {
			ip += "/32"
		}
		if prefix, err := netip.ParsePrefix(ip); err == nil {
			address = append(address, prefix)
		}
	}
	if w.Ipv6 != "" {
		ipv6 := w.Ipv6
		if !strings.Contains(ipv6, "/") {
			ipv6 += "/128"
		}
		if prefix, err := netip.ParsePrefix(ipv6); err == nil {
			address = append(address, prefix)
		}
	}
	var peers []option.WireGuardPeer
	if len(w.Peers) > 0 {
		for _, peer := range w.Peers {
			peers = append(peers, clashWireGuardPeer(peer, w.PersistentKeepalive))
		}
	} else {
		peers = append(peers, clashWireGuardPeer(w.ClashWireGuardPeerOption, w.PersistentKeepalive))
	}
	return &option.WireGuardEndpointOptions{
		Address:       address,
		PrivateKey:    w.PrivateKey,
		MTU:           uint32(w.MTU),
		Workers:       w.Workers,
		Peers:         peers,
		DialerOptions: w.DialerOptions.Build(),
	}
}

func clashWireGuardPeer(peer ClashWireGuardPeerOption, persistentKeepalive int) option.WireGuardPeer {
	var allowedIPs badoption.Listable[netip.Prefix]
	for _, ip := range peer.AllowedIPs {
		if prefix, err := netip.ParsePrefix(ip); err == nil {
			allowedIPs = append(allowedIPs, prefix)
		}
	}
	return option.WireGuardPeer{
		Address:                     peer.Server,
		Port:                        uint16(peer.Port),
		PublicKey:                   peer.PublicKey,
		PreSharedKey:                peer.PreSharedKey,
		AllowedIPs:                  allowedIPs,
		PersistentKeepaliveInterval: uint16(persistentKeepalive),
	}
}

