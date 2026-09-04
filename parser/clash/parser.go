package clash

import (
	"context"

	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common"
	E "github.com/sagernet/sing/common/exceptions"

	"gopkg.in/yaml.v3"
)

type ClashConfig struct {
	Proxies []ClashProxy `yaml:"proxies"`
}

type _ClashProxy struct {
	Name    string `yaml:"name"`
	Type    string `yaml:"type"`
	Options Proxy  `yaml:"-"`

	SingType string `yaml:"-"`
}
type ClashProxy _ClashProxy

type Proxy interface {
	Build() any
}

func (c *ClashProxy) UnmarshalYAML(value *yaml.Node) error {
	err := value.Decode((*_ClashProxy)(c))
	if err != nil {
		return err
	}
	var options Proxy
	switch c.Type {
	case "ss":
		c.SingType = C.TypeShadowsocks
		options = &ShadowSocksOption{}
	case "tuic":
		c.SingType = C.TypeTUIC
		options = &TuicOption{}
	case "vmess":
		c.SingType = C.TypeVMess
		options = &VmessOption{}
	case "vless":
		c.SingType = C.TypeVLESS
		options = &VlessOption{}
	case "socks5":
		c.SingType = C.TypeSOCKS
		options = &Socks5Option{}
	case "http":
		c.SingType = C.TypeHTTP
		options = &HttpOption{}
	case "trojan":
		c.SingType = C.TypeTrojan
		options = &TrojanOption{}
	case "hysteria":
		c.SingType = C.TypeHysteria
		options = &HysteriaOption{}
	case "hysteria2":
		c.SingType = C.TypeHysteria2
		options = &Hysteria2Option{}
	case "ssh":
		c.SingType = C.TypeSSH
		options = &SSHOption{}
	case "anytls":
		c.SingType = C.TypeAnyTLS
		options = &AnyTLSOption{}
	case "wireguard":
		c.SingType = C.TypeWireGuard
		options = &ClashWireGuardOption{}
	default:
		return nil
	}
	err = value.Decode(options)
	if err != nil {
		return err
	}
	c.Options = options
	return nil
}

func (c *ClashProxy) Build() option.Outbound {
	outbound := option.Outbound{
		Tag:  c.Name,
		Type: c.SingType,
	}
	if c.Options != nil {
		outbound.Options = c.Options.Build()
	}
	return outbound
}

func (c *ClashProxy) BuildEndpoint() option.Endpoint {
	endpoint := option.Endpoint{
		Tag:  c.Name,
		Type: c.SingType,
	}
	if c.Options != nil {
		endpoint.Options = c.Options.Build()
	}
	return endpoint
}

func ParseClashSubscription(_ context.Context, content string) ([]option.Outbound, []option.Endpoint, error) {
	config := &ClashConfig{}
	err := yaml.Unmarshal([]byte(content), &config)
	if err != nil {
		return nil, nil, E.Cause(err, "parse clash config")
	}
	outbounds := common.FilterIsInstance(config.Proxies, func(proxy ClashProxy) (option.Outbound, bool) {
		if proxy.SingType == "" || proxy.SingType == C.TypeWireGuard {
			return option.Outbound{}, false
		}
		return proxy.Build(), true
	})
	endpoints := common.FilterIsInstance(config.Proxies, func(proxy ClashProxy) (option.Endpoint, bool) {
		if proxy.SingType != C.TypeWireGuard {
			return option.Endpoint{}, false
		}
		if wgOpt, ok := proxy.Options.(*ClashWireGuardOption); ok && wgOpt.AmneziaWGOption != nil {
			return option.Endpoint{}, false
		}
		return proxy.BuildEndpoint(), true
	})
	return outbounds, endpoints, nil
}
