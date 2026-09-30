package link

import (
	"encoding/json"
	"net/url"
	"regexp"
	"strconv"

	"github.com/sagernet/sing-box/common"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/json/badoption"
)

func parseVMessLink(link string) (option.Outbound, error) {
	var proxy map[string]string
	reg := regexp.MustCompile(`(\"[^:,]+?\"[ \t]*:[ \t]*)(\d+|true|false)`)
	s := reg.ReplaceAllString(link, `$1"$2"`)
	err := json.Unmarshal([]byte(s[8:]), &proxy)
	if err != nil {
		proxy = make(map[string]string)
		linkURL, err := url.Parse(link)
		if err != nil {
			return option.Outbound{}, err
		}
		if linkURL.User == nil || linkURL.User.Username() == "" {
			return option.Outbound{}, E.New("missing uuid")
		}
		proxy["id"] = linkURL.User.Username()
		proxy["add"] = linkURL.Hostname()
		proxy["port"] = linkURL.Port()
		proxy["ps"] = linkURL.Fragment
		for key, values := range linkURL.Query() {
			value := values[0]
			switch key {
			case "type":
				if value == "http" {
					proxy["net"] = "tcp"
					proxy["type"] = "http"
				}
			case "encryption":
				proxy["scy"] = value
			case "alterId":
				proxy["aid"] = value
			case "key", "alpn", "seed", "path", "host":
				proxy[key] = value
			default:
				proxy[key] = value
			}
		}
	}
	outbound := option.Outbound{
		Type: C.TypeVMess,
	}
	options := option.VMessOutboundOptions{
		Security: "auto",
	}
	TLSOptions := option.OutboundTLSOptions{
		ECH:     &option.OutboundECHOptions{},
		UTLS:    &option.OutboundUTLSOptions{},
		Reality: &option.OutboundRealityOptions{},
	}
	for key, value := range proxy {
		switch key {
		case "ps":
			outbound.Tag = value
		case "add":
			options.Server = value
			TLSOptions.ServerName = value
		case "port":
			options.ServerPort = common.StringToType[uint16](value)
		case "id":
			options.UUID = value
		case "scy":
			options.Security = value
		case "aid":
			options.AlterId, _ = strconv.Atoi(value)
		case "packet_encoding":
			options.PacketEncoding = value
		case "xudp":
			if value == "1" || value == "true" {
				options.PacketEncoding = "xudp"
			}
		case "tls":
			if value == "1" || value == "true" || value == "tls" {
				TLSOptions.Enabled = true
			}
		case "insecure", "skip-cert-verify":
			if value == "1" || value == "true" {
				TLSOptions.Insecure = true
			}
		case "fp":
			TLSOptions.UTLS.Enabled = true
			TLSOptions.UTLS.Fingerprint = value
		case "net":
			Transport := option.V2RayTransportOptions{
				Type: "",
				WebsocketOptions: option.V2RayWebsocketOptions{
					Headers: badoption.HTTPHeader{},
				},
				HTTPOptions: option.V2RayHTTPOptions{
					Host:    badoption.Listable[string]{},
					Headers: map[string]badoption.Listable[string]{},
				},
				GRPCOptions: option.V2RayGRPCOptions{},
			}
			switch value {
			case "ws":
				Transport.Type = C.V2RayTransportTypeWebsocket
				Transport.WebsocketOptions = v2rayTransportWs(proxy["host"], proxy["path"])
			case "h2":
				Transport.Type = C.V2RayTransportTypeHTTP
				TLSOptions.Enabled = true
				if host, exists := proxy["host"]; exists && host != "" {
					Transport.HTTPOptions.Host = []string{host}
				}
				if path, exists := proxy["path"]; exists && path != "" {
					Transport.HTTPOptions.Path = path
				}
			case "tcp":
				if tType, exists := proxy["type"]; exists {
					if tType != "http" {
						continue
					}
					Transport.Type = C.V2RayTransportTypeHTTP
					if method, exists := proxy["method"]; exists {
						Transport.HTTPOptions.Method = method
					}
					if host, exists := proxy["host"]; exists && host != "" {
						Transport.HTTPOptions.Host = []string{host}
					}
					if path, exists := proxy["path"]; exists && path != "" {
						Transport.HTTPOptions.Path = path
					}
					if headers, exists := proxy["headers"]; exists {
						Transport.HTTPOptions.Headers = common.StringToType[badoption.HTTPHeader](headers)
					}
				}
			case "grpc":
				Transport.Type = C.V2RayTransportTypeGRPC
				if host, exists := proxy["host"]; exists && host != "" {
					Transport.GRPCOptions.ServiceName = host
				}
				if userAgent, exists := proxy["userAgent"]; exists && userAgent != "" {
					Transport.GRPCOptions.UserAgent = userAgent
				} else if userAgent, exists := proxy["user_agent"]; exists && userAgent != "" {
					Transport.GRPCOptions.UserAgent = userAgent
				}
			default:
				continue
			}
			options.Transport = &Transport
		case "tfo", "tcp-fast-open", "tcp_fast_open":
			if value == "1" || value == "true" {
				options.TCPFastOpen = true
			}
		}
	}
	if TLSOptions.Enabled {
		options.TLS = &TLSOptions
	}
	outbound.Options = &options
	return outbound, nil
}
