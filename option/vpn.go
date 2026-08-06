package option

import (
	"net/netip"

	"github.com/sagernet/sing/common/json/badoption"
)

type VPNClientEndpointOptions struct {
	Address        netip.Addr         `json:"address"`
	Key            string             `json:"key"`
	Outbound       Outbound           `json:"outbound"`
	PoolSize       uint8              `json:"pool_size,omitempty"`
	ReconnectDelay badoption.Duration `json:"reconnect_delay,omitempty"`
	RejectDelay    badoption.Duration `json:"reject_delay,omitempty"`
	DefaultGateway netip.Addr         `json:"default_gateway,omitempty"`
}

type VPNServerEndpointOptions struct {
	Address        netip.Addr         `json:"address"`
	Users          []VPNUser          `json:"users"`
	Inbounds       []Inbound          `json:"inbounds"`
	PoolSize       uint8              `json:"pool_size,omitempty"`
	ConnectTimeout badoption.Duration `json:"connect_timeout,omitempty"`
	DefaultGateway netip.Addr         `json:"default_gateway,omitempty"`
}

type VPNUser struct {
	Address netip.Addr `json:"address"`
	Key     string     `json:"key"`
}
