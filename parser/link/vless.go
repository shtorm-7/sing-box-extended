package link

import (
	"encoding/json"
	"net/url"
	"strings"

	"github.com/sagernet/sing-box/common"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/json/badoption"
)

func parseVLESSLink(link string) (option.Outbound, error) {
	linkURL, err := url.Parse(link)
	if err != nil {
		return option.Outbound{}, err
	}
	if linkURL.User == nil || linkURL.User.Username() == "" {
		return option.Outbound{}, E.New("missing uuid")
	}
	var options option.VLESSOutboundOptions
	TLSOptions := option.OutboundTLSOptions{
		ECH:     &option.OutboundECHOptions{},
		UTLS:    &option.OutboundUTLSOptions{},
		Reality: &option.OutboundRealityOptions{},
	}
	options.UUID = linkURL.User.Username()
	options.Server = linkURL.Hostname()
	TLSOptions.ServerName = linkURL.Hostname()
	options.ServerPort = common.StringToType[uint16](linkURL.Port())
	proxy := map[string]string{}
	for key, values := range linkURL.Query() {
		value := values[0]
		switch key {
		case "key", "alpn", "seed", "path", "host":
			proxy[key] = value
		default:
			proxy[key] = value
		}
	}
	for key, value := range proxy {
		switch key {
		case "type":
			Transport := option.V2RayTransportOptions{
				HTTPOptions: option.V2RayHTTPOptions{
					Host:    badoption.Listable[string]{},
					Headers: badoption.HTTPHeader{},
				},
				GRPCOptions: option.V2RayGRPCOptions{},
			}
			switch value {
			case "ws":
				Transport.Type = C.V2RayTransportTypeWebsocket
				Transport.WebsocketOptions = v2rayTransportWs(proxy["host"], proxy["path"])
			case "http":
				Transport.Type = C.V2RayTransportTypeHTTP
				if host, exists := proxy["host"]; exists && host != "" {
					Transport.HTTPOptions.Host = strings.Split(host, ",")
				}
				if path, exists := proxy["path"]; exists && path != "" {
					Transport.HTTPOptions.Path = path
				}
			case "grpc":
				Transport.Type = C.V2RayTransportTypeGRPC
				if serviceName, exists := proxy["serviceName"]; exists && serviceName != "" {
					Transport.GRPCOptions.ServiceName = serviceName
				}
				if userAgent, exists := proxy["userAgent"]; exists && userAgent != "" {
					Transport.GRPCOptions.UserAgent = userAgent
				} else if userAgent, exists := proxy["user_agent"]; exists && userAgent != "" {
					Transport.GRPCOptions.UserAgent = userAgent
				}
			case "xhttp":
				Transport.Type = C.V2RayTransportTypeXHTTP
				if alpn, exists := proxy["alpn"]; exists && alpn != "" {
					TLSOptions.ALPN = strings.Split(alpn, ",")
				} else {
					TLSOptions.ALPN = []string{"h2", "http/1.1"}
				}
				if host, exists := proxy["host"]; exists && host != "" {
					Transport.XHTTPOptions.Host = host
				}
				if path, exists := proxy["path"]; exists && path != "" {
					Transport.XHTTPOptions.Path = path
				}
				if mode, exists := proxy["mode"]; exists && mode != "" {
					Transport.XHTTPOptions.Mode = mode
				}
				if extra, exists := proxy["extra"]; exists && extra != "" {
					decodedExtra, err := common.DecodeBase64URLSafe(extra)
					if err == nil {
						var extraOptions map[string]interface{}
						if json.Unmarshal([]byte(decodedExtra), &extraOptions) == nil {
							if xmux, ok := extraOptions["xmux"].(map[string]interface{}); ok {
								Transport.XHTTPOptions.Xmux = &option.V2RayXHTTPXmuxOptions{}
								if val, ok := xmux["cMaxReuseTimes"].(string); ok {
									if r, err := common.ParseXHTTPRange(val); err == nil {
										Transport.XHTTPOptions.Xmux.CMaxReuseTimes = r
									}
								}
								if val, ok := xmux["maxConcurrency"].(string); ok {
									if r, err := common.ParseXHTTPRange(val); err == nil {
										Transport.XHTTPOptions.Xmux.MaxConcurrency = r
									}
								}
								if val, ok := xmux["maxConnections"].(string); ok {
									if r, err := common.ParseXHTTPRange(val); err == nil {
										Transport.XHTTPOptions.Xmux.MaxConnections = r
									}
								}
								if val, ok := xmux["hKeepAlivePeriod"].(string); ok {
									Transport.XHTTPOptions.Xmux.HKeepAlivePeriod = common.StringToType[int64](val)
								}
								if val, ok := xmux["hMaxRequestTimes"].(string); ok {
									if r, err := common.ParseXHTTPRange(val); err == nil {
										Transport.XHTTPOptions.Xmux.HMaxRequestTimes = r
									}
								}
								if val, ok := xmux["hMaxReusableSecs"].(string); ok {
									if r, err := common.ParseXHTTPRange(val); err == nil {
										Transport.XHTTPOptions.Xmux.HMaxReusableSecs = r
									}
								}
							}
							if val, ok := extraOptions["noGRPCHeader"].(bool); ok {
								Transport.XHTTPOptions.NoGRPCHeader = val
							}
							if val, ok := extraOptions["xPaddingBytes"].(string); ok {
								if r, err := common.ParseXHTTPRange(val); err == nil {
									Transport.XHTTPOptions.XPaddingBytes = r
								}
							}
							if val, ok := extraOptions["scMaxEachPostBytes"].(string); ok {
								if r, err := common.ParseXHTTPRange(val); err == nil {
									Transport.XHTTPOptions.ScMaxEachPostBytes = &r
								}
							}
							if val, ok := extraOptions["scMinPostsIntervalMs"].(string); ok {
								if r, err := common.ParseXHTTPRange(val); err == nil {
									Transport.XHTTPOptions.ScMinPostsIntervalMs = &r
								}
							}
							if val, ok := extraOptions["scStreamUpServerSecs"].(string); ok {
								if r, err := common.ParseXHTTPRange(val); err == nil {
									Transport.XHTTPOptions.ScStreamUpServerSecs = &r
								}
							}
						}
					}
				}
			default:
				continue
			}
			options.Transport = &Transport
		case "security":
			if value == "tls" {
				TLSOptions.Enabled = true
			} else if value == "reality" {
				TLSOptions.Enabled = true
				TLSOptions.Reality.Enabled = true
			}
		case "insecure", "skip-cert-verify":
			if value == "1" || value == "true" {
				TLSOptions.Insecure = true
			}
		case "serviceName", "sni", "peer":
			TLSOptions.ServerName = value
		case "alpn":
			TLSOptions.ALPN = strings.Split(value, ",")
		case "fp":
			TLSOptions.UTLS.Enabled = true
			TLSOptions.UTLS.Fingerprint = value
		case "flow":
			if value == "xtls-rprx-vision" {
				options.Flow = "xtls-rprx-vision"
			}
		case "pbk":
			TLSOptions.Reality.PublicKey = value
		case "sid":
			TLSOptions.Reality.ShortID = value
		case "tfo", "tcp-fast-open", "tcp_fast_open":
			if value == "1" || value == "true" {
				options.TCPFastOpen = true
			}
		}
	}
	outbound := option.Outbound{
		Type: C.TypeVLESS,
		Tag:  linkURL.Fragment,
	}
	if TLSOptions.Enabled {
		options.TLS = &TLSOptions
	}
	outbound.Options = &options
	return outbound, nil
}
