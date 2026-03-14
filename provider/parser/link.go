package parser

import (
	"net/url"
	"reflect"
	"regexp"
	"strconv"
	"strings"
	"time"

	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/byteformats"
	E "github.com/sagernet/sing/common/exceptions"
	F "github.com/sagernet/sing/common/format"
	"github.com/sagernet/sing/common/json"
	"github.com/sagernet/sing/common/json/badoption"
)

func ParseSubscriptionLink(link string) (option.Outbound, error) {
	reg := regexp.MustCompile(`^(.*?)(://)(.*?)([@?#].*)?$`)
	result := reg.FindStringSubmatch(link)
	if result == nil {
		return option.Outbound{}, E.New("invalid link")
	}

	scheme := result[1]
	switch scheme {
	case "tuic":
		return parseTuicLink(link)
	case "trojan":
		return parseTrojanLink(link)
	case "vless":
		return parseVLESSLink(link)
	case "hysteria":
		return parseHysteriaLink(link)
	case "hy2", "hysteria2":
		return parseHysteria2Link(link)
	}
	result[3], _ = DecodeBase64URLSafe(result[3])
	link = strings.Join(result[1:], "")
	switch scheme {
	case "ss":
		return parseShadowsocksLink(link)
	case "vmess":
		return parseVMessLink(link)
	default:
		return option.Outbound{}, E.New("unsupported scheme: ", scheme)
	}
}

func StringToType[T any](str string) T {
	var value T
	v := reflect.ValueOf(&value).Elem()
	switch any(value).(type) {
	case badoption.Duration:
		d, err := time.ParseDuration(str)
		if err != nil {
			v.SetInt(StringToType[int64](str))
		} else {
			v.Set(reflect.ValueOf(d))
		}
		return value
	case badoption.HTTPHeader:
		headers := badoption.HTTPHeader{}
		reg := regexp.MustCompile(`^[ \t]*?(\S+?):[ \t]*?(\S+?)[ \t]*?$`)
		for _, header := range strings.Split(str, "\n") {
			result := reg.FindStringSubmatch(header)
			if result != nil {
				key := result[1]
				headers[key] = strings.Split(result[2], ",")
			}
		}
		v.Set(reflect.ValueOf(headers))
		return value
	}
	switch v.Kind() {
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		i, _ := strconv.ParseInt(str, 10, 64)
		v.SetInt(i)
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		i, _ := strconv.ParseUint(str, 10, 64)
		v.SetUint(i)
	case reflect.Float32, reflect.Float64:
		f, _ := strconv.ParseFloat(str, 64)
		v.SetFloat(f)
	case reflect.Bool:
		b, _ := strconv.ParseBool(str)
		v.SetBool(b)
	default:
		panic("unsupported type")
	}
	return value
}

func shadowsocksPluginName(plugin string) string {
	if index := strings.Index(plugin, ";"); index != -1 {
		return plugin[:index]
	}
	return plugin
}

func shadowsocksPluginOptions(plugin string) string {
	if index := strings.Index(plugin, ";"); index != -1 {
		return plugin[index+1:]
	}
	return ""
}

func v2rayTransportWsPath(WebsocketOptions *option.V2RayWebsocketOptions, path string) {
	reg := regexp.MustCompile(`^(.*?)(?:\?ed=(\d*))?$`)
	result := reg.FindStringSubmatch(path)
	WebsocketOptions.Path = result[1]
	if result[2] != "" {
		WebsocketOptions.EarlyDataHeaderName = "Sec-WebSocket-Protocol"
		WebsocketOptions.MaxEarlyData = StringToType[uint32](result[2])
	}
}

func v2rayTransportWs(host string, path string) option.V2RayWebsocketOptions {
	var WebsocketOptions option.V2RayWebsocketOptions
	if host != "" {
		WebsocketOptions.Headers = StringToType[badoption.HTTPHeader](F.ToString("Host: ", host))
	}
	if path != "" {
		v2rayTransportWsPath(&WebsocketOptions, path)
	}
	return WebsocketOptions
}

func parseShadowsocksLink(link string) (option.Outbound, error) {
	linkURL, err := url.Parse(link)
	if err != nil {
		return option.Outbound{}, err
	}
	if linkURL.User == nil || linkURL.User.Username() == "" {
		return option.Outbound{}, E.New("missing user info")
	}
	var options option.ShadowsocksOutboundOptions
	options.ServerOptions.Server = linkURL.Hostname()
	options.ServerOptions.ServerPort = StringToType[uint16](linkURL.Port())
	password, _ := linkURL.User.Password()
	if password == "" {
		return option.Outbound{}, E.New("bad user info")
	}
	options.Method = linkURL.User.Username()
	options.Password = password
	plugin := linkURL.Query().Get("plugin")
	options.Plugin = shadowsocksPluginName(plugin)
	options.PluginOptions = shadowsocksPluginOptions(plugin)

	outbound := option.Outbound{
		Type: C.TypeShadowsocks,
		Tag:  linkURL.Fragment,
	}
	outbound.Options = &options
	return outbound, nil
}

func parseTuicLink(link string) (option.Outbound, error) {
	linkURL, err := url.Parse(link)
	if err != nil {
		return option.Outbound{}, err
	}
	if linkURL.User == nil || linkURL.User.Username() == "" {
		return option.Outbound{}, E.New("missing uuid")
	}
	var options option.TUICOutboundOptions
	TLSOptions := option.OutboundTLSOptions{
		Enabled: true,
		ECH:     &option.OutboundECHOptions{},
		UTLS:    &option.OutboundUTLSOptions{},
		Reality: &option.OutboundRealityOptions{},
	}
	options.UUID = linkURL.User.Username()
	options.Password, _ = linkURL.User.Password()
	options.ServerOptions.Server = linkURL.Hostname()
	TLSOptions.ServerName = linkURL.Hostname()
	options.ServerOptions.ServerPort = StringToType[uint16](linkURL.Port())
	for key, values := range linkURL.Query() {
		value := values[0]
		switch key {
		case "congestion_control":
			if value != "cubic" {
				options.CongestionControl = value
			}
		case "udp_relay_mode":
			options.UDPRelayMode = value
		case "udp_over_stream":
			if value == "true" || value == "1" {
				options.UDPOverStream = true
			}
		case "zero_rtt_handshake", "reduce_rtt":
			if value == "true" || value == "1" {
				options.ZeroRTTHandshake = true
			}
		case "heartbeat_interval":
			options.Heartbeat = StringToType[badoption.Duration](value)
		case "sni":
			TLSOptions.ServerName = value
		case "insecure", "skip-cert-verify", "allow_insecure":
			if value == "1" || value == "true" {
				TLSOptions.Insecure = true
			}
		case "disable_sni":
			if value == "1" || value == "true" {
				TLSOptions.DisableSNI = true
			}
		case "tfo", "tcp-fast-open", "tcp_fast_open":
			if value == "1" || value == "true" {
				options.TCPFastOpen = true
			}
		case "alpn":
			TLSOptions.ALPN = strings.Split(value, ",")
		}
	}
	if options.UDPOverStream {
		options.UDPRelayMode = ""
	}
	outbound := option.Outbound{
		Type: C.TypeTUIC,
		Tag:  linkURL.Fragment,
	}
	options.TLS = &TLSOptions
	outbound.Options = &options
	return outbound, nil
}

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
			options.ServerPort = StringToType[uint16](value)
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
						Transport.HTTPOptions.Headers = StringToType[badoption.HTTPHeader](headers)
					}
				}
			case "grpc":
				Transport.Type = C.V2RayTransportTypeGRPC
				if host, exists := proxy["host"]; exists && host != "" {
					Transport.GRPCOptions.ServiceName = host
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
	options.ServerPort = StringToType[uint16](linkURL.Port())
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

func parseTrojanLink(link string) (option.Outbound, error) {
	linkURL, err := url.Parse(link)
	if err != nil {
		return option.Outbound{}, err
	}
	if linkURL.User == nil || linkURL.User.Username() == "" {
		return option.Outbound{}, E.New("missing password")
	}
	var options option.TrojanOutboundOptions
	TLSOptions := option.OutboundTLSOptions{
		Enabled: true,
		ECH:     &option.OutboundECHOptions{},
		UTLS:    &option.OutboundUTLSOptions{},
		Reality: &option.OutboundRealityOptions{},
	}
	options.Server = linkURL.Hostname()
	TLSOptions.ServerName = linkURL.Hostname()
	options.ServerPort = StringToType[uint16](linkURL.Port())
	options.Password = linkURL.User.Username()
	proxy := map[string]string{}
	for key, values := range linkURL.Query() {
		value := values[0]
		proxy[key] = value
	}
	for key, value := range proxy {
		switch key {
		case "insecure", "allowInsecure", "skip-cert-verify":
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
		case "type":
			Transport := option.V2RayTransportOptions{
				Type: "",
				WebsocketOptions: option.V2RayWebsocketOptions{
					Headers: map[string]badoption.Listable[string]{},
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
			case "grpc":
				Transport.Type = C.V2RayTransportTypeGRPC
				if serviceName, exists := proxy["grpc-service-name"]; exists && serviceName != "" {
					Transport.GRPCOptions.ServiceName = serviceName
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
	outbound := option.Outbound{
		Type: C.TypeTrojan,
		Tag:  linkURL.Fragment,
	}
	options.TLS = &TLSOptions
	outbound.Options = &options
	return outbound, nil
}

func parseHysteriaLink(link string) (option.Outbound, error) {
	linkURL, err := url.Parse(link)
	if err != nil {
		return option.Outbound{}, err
	}
	var options option.HysteriaOutboundOptions
	TLSOptions := option.OutboundTLSOptions{
		Enabled: true,
		ECH:     &option.OutboundECHOptions{},
		UTLS:    &option.OutboundUTLSOptions{},
		Reality: &option.OutboundRealityOptions{},
	}
	options.Server = linkURL.Hostname()
	TLSOptions.ServerName = linkURL.Hostname()
	options.ServerPort = StringToType[uint16](linkURL.Port())
	for key, values := range linkURL.Query() {
		value := values[0]
		switch key {
		case "auth":
			options.AuthString = value
		case "peer", "sni":
			TLSOptions.ServerName = value
		case "alpn":
			TLSOptions.ALPN = strings.Split(value, ",")
		case "ca":
			TLSOptions.CertificatePath = value
		case "ca_str":
			TLSOptions.Certificate = strings.Split(value, "\n")
		case "up":
			options.Up = &byteformats.NetworkBytesCompat{}
			options.Up.UnmarshalJSON([]byte(value))
		case "up_mbps":
			options.UpMbps, _ = strconv.Atoi(value)
		case "down":
			options.Down = &byteformats.NetworkBytesCompat{}
			options.Down.UnmarshalJSON([]byte(value))
		case "down_mbps":
			options.DownMbps, _ = strconv.Atoi(value)
		case "obfs", "obfsParam":
			options.Obfs = value
		case "insecure", "skip-cert-verify":
			if value == "1" || value == "true" {
				TLSOptions.Insecure = true
			}
		case "tfo", "tcp-fast-open", "tcp_fast_open":
			if value == "1" || value == "true" {
				options.TCPFastOpen = true
			}
		}
	}
	outbound := option.Outbound{
		Type: C.TypeHysteria,
		Tag:  linkURL.Fragment,
	}
	options.TLS = &TLSOptions
	outbound.Options = &options
	return outbound, nil
}

func parseHysteria2Link(link string) (option.Outbound, error) {
	linkURL, err := url.Parse(link)
	if err != nil {
		return option.Outbound{}, err
	}
	var options option.Hysteria2OutboundOptions
	TLSOptions := option.OutboundTLSOptions{
		Enabled: true,
		ECH:     &option.OutboundECHOptions{},
		UTLS:    &option.OutboundUTLSOptions{},
		Reality: &option.OutboundRealityOptions{},
	}
	Obfs := &option.Hysteria2Obfs{}
	options.ServerPort = uint16(443)
	options.Server = linkURL.Hostname()
	TLSOptions.ServerName = linkURL.Hostname()
	if linkURL.User != nil {
		options.Password = linkURL.User.Username()
	}
	if linkURL.Port() != "" {
		options.ServerPort = StringToType[uint16](linkURL.Port())
	}
	for key, values := range linkURL.Query() {
		value := values[0]
		switch key {
		case "up":
			options.UpMbps, _ = strconv.Atoi(value)
		case "down":
			options.DownMbps, _ = strconv.Atoi(value)
		case "obfs":
			if value == "salamander" {
				Obfs.Type = "salamander"
				options.Obfs = Obfs
			}
		case "obfs-password":
			Obfs.Password = value
		case "insecure", "skip-cert-verify":
			if value == "1" || value == "true" {
				TLSOptions.Insecure = true
			}
		}
	}
	outbound := option.Outbound{
		Type: C.TypeHysteria2,
		Tag:  linkURL.Fragment,
	}
	options.TLS = &TLSOptions
	outbound.Options = &options
	return outbound, nil
}
