package include

import (
	"context"

	"github.com/sagernet/sing-box"
	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/endpoint"
	"github.com/sagernet/sing-box/adapter/inbound"
	"github.com/sagernet/sing-box/adapter/outbound"
	"github.com/sagernet/sing-box/adapter/provider"
	"github.com/sagernet/sing-box/adapter/service"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/dns"
	"github.com/sagernet/sing-box/dns/transport"
	"github.com/sagernet/sing-box/dns/transport/fakeip"
	"github.com/sagernet/sing-box/dns/transport/fallback"
	"github.com/sagernet/sing-box/dns/transport/hosts"
	"github.com/sagernet/sing-box/dns/transport/local"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-box/protocol/anytls"
	"github.com/sagernet/sing-box/protocol/block"
	"github.com/sagernet/sing-box/protocol/bond"
	"github.com/sagernet/sing-box/protocol/direct"
	"github.com/sagernet/sing-box/protocol/failover"
	"github.com/sagernet/sing-box/protocol/group"
	"github.com/sagernet/sing-box/protocol/http"
	"github.com/sagernet/sing-box/protocol/limiter/bandwidth"
	"github.com/sagernet/sing-box/protocol/limiter/connection"
	"github.com/sagernet/sing-box/protocol/limiter/rate"
	"github.com/sagernet/sing-box/protocol/limiter/traffic"
	"github.com/sagernet/sing-box/protocol/mieru"
	"github.com/sagernet/sing-box/protocol/mixed"
	"github.com/sagernet/sing-box/protocol/naive"
	"github.com/sagernet/sing-box/protocol/parser"
	"github.com/sagernet/sing-box/protocol/redirect"
	"github.com/sagernet/sing-box/protocol/shadowsocks"
	"github.com/sagernet/sing-box/protocol/shadowtls"
	"github.com/sagernet/sing-box/protocol/socks"
	"github.com/sagernet/sing-box/protocol/ssh"
	"github.com/sagernet/sing-box/protocol/tor"
	"github.com/sagernet/sing-box/protocol/trojan"
	"github.com/sagernet/sing-box/protocol/tun"
	"github.com/sagernet/sing-box/protocol/vless"
	"github.com/sagernet/sing-box/protocol/vmess"
	"github.com/sagernet/sing-box/protocol/vpn"
	localProvider "github.com/sagernet/sing-box/provider/local"
	remoteProvider "github.com/sagernet/sing-box/provider/remote"
	"github.com/sagernet/sing-box/service/admin_panel"
	"github.com/sagernet/sing-box/service/manager"
	"github.com/sagernet/sing-box/service/manager_api"
	"github.com/sagernet/sing-box/service/node"
	"github.com/sagernet/sing-box/service/node_manager_api"
	"github.com/sagernet/sing-box/service/resolved"
	"github.com/sagernet/sing-box/service/ssmapi"
	E "github.com/sagernet/sing/common/exceptions"
)

func Context(ctx context.Context) context.Context {
	return box.Context(ctx, InboundRegistry(), OutboundRegistry(), EndpointRegistry(), ProviderRegistry(), DNSTransportRegistry(), ServiceRegistry())
}

func InboundRegistry() *inbound.Registry {
	registry := inbound.NewRegistry()

	tun.RegisterInbound(registry)
	redirect.RegisterRedirect(registry)
	redirect.RegisterTProxy(registry)
	direct.RegisterInbound(registry)

	socks.RegisterInbound(registry)
	http.RegisterInbound(registry)
	mixed.RegisterInbound(registry)

	shadowsocks.RegisterInbound(registry)
	vmess.RegisterInbound(registry)
	trojan.RegisterInbound(registry)
	naive.RegisterInbound(registry)
	shadowtls.RegisterInbound(registry)
	vless.RegisterInbound(registry)
	anytls.RegisterInbound(registry)
	mieru.RegisterInbound(registry)
	ssh.RegisterInbound(registry)

	bond.RegisterInbound(registry)
	failover.RegisterInbound(registry)
	registerTrustTunnelInbound(registry)

	registerQUICInbounds(registry)
	registerStubForRemovedInbounds(registry)
	registerMTProxyInbound(registry)
	registerSudokuInbound(registry)
	registerSnellInbound(registry)
	registerCallInbound(registry)

	return registry
}

func OutboundRegistry() *outbound.Registry {
	registry := outbound.NewRegistry()

	direct.RegisterOutbound(registry)

	block.RegisterOutbound(registry)

	group.RegisterFallback(registry)
	group.RegisterSelector(registry)
	group.RegisterURLTest(registry)

	socks.RegisterOutbound(registry)
	http.RegisterOutbound(registry)
	shadowsocks.RegisterOutbound(registry)
	vmess.RegisterOutbound(registry)
	trojan.RegisterOutbound(registry)
	registerNaiveOutbound(registry)
	tor.RegisterOutbound(registry)
	ssh.RegisterOutbound(registry)
	shadowtls.RegisterOutbound(registry)
	vless.RegisterOutbound(registry)
	mieru.RegisterOutbound(registry)
	anytls.RegisterOutbound(registry)
	registerMASQUEOutbound(registry)
	registerOpenVPNOutbound(registry)

	bond.RegisterOutbound(registry)
	failover.RegisterOutbound(registry)
	registerTrustTunnelOutbound(registry)

	bandwidth.RegisterOutbound(registry)
	connection.RegisterOutbound(registry)
	traffic.RegisterOutbound(registry)
	rate.RegisterOutbound(registry)

	parser.RegisterOutbound(registry)

	registerQUICOutbounds(registry)
	registerStubForRemovedOutbounds(registry)
	registerSudokuOutbound(registry)
	registerSnellOutbound(registry)
	registerCallOutbound(registry)

	return registry
}

func EndpointRegistry() *endpoint.Registry {
	registry := endpoint.NewRegistry()

	vpn.RegisterServerEndpoint(registry)
	vpn.RegisterClientEndpoint(registry)

	registerWireGuardEndpoint(registry)
	registerTailscaleEndpoint(registry)

	return registry
}

func ProviderRegistry() *provider.Registry {
	registry := provider.NewRegistry()

	localProvider.RegisterProviderInline(registry)
	localProvider.RegisterProviderLocal(registry)
	remoteProvider.RegisterProvider(registry)

	return registry
}

func DNSTransportRegistry() *dns.TransportRegistry {
	registry := dns.NewTransportRegistry()

	transport.RegisterTCP(registry)
	transport.RegisterUDP(registry)
	transport.RegisterTLS(registry)
	transport.RegisterHTTPS(registry)
	transport.RegisterSDNS(registry)
	hosts.RegisterTransport(registry)
	local.RegisterTransport(registry)
	fakeip.RegisterTransport(registry)
	fallback.RegisterTransport(registry)
	resolved.RegisterTransport(registry)

	registerQUICTransports(registry)
	registerDHCPTransport(registry)
	registerTailscaleTransport(registry)

	return registry
}

func ServiceRegistry() *service.Registry {
	registry := service.NewRegistry()

	admin_panel.RegisterService(registry)
	manager.RegisterService(registry)
	manager_api.RegisterService(registry)
	node.RegisterService(registry)
	node_manager_api.RegisterService(registry)
	resolved.RegisterService(registry)
	ssmapi.RegisterService(registry)

	registerDERPService(registry)
	registerCCMService(registry)
	registerOCMService(registry)
	registerOOMKillerService(registry)
	registerProfilerService(registry)

	return registry
}

func registerStubForRemovedInbounds(registry *inbound.Registry) {
	inbound.Register[option.ShadowsocksInboundOptions](registry, C.TypeShadowsocksR, func(ctx context.Context, router adapter.Router, logger log.ContextLogger, tag string, options option.ShadowsocksInboundOptions) (adapter.Inbound, error) {
		return nil, E.New("ShadowsocksR is deprecated and removed in sing-box 1.6.0")
	})
}

func registerStubForRemovedOutbounds(registry *outbound.Registry) {
	outbound.Register[option.ShadowsocksROutboundOptions](registry, C.TypeShadowsocksR, func(ctx context.Context, router adapter.Router, logger log.ContextLogger, tag string, options option.ShadowsocksROutboundOptions) (adapter.Outbound, error) {
		return nil, E.New("ShadowsocksR is deprecated and removed in sing-box 1.6.0")
	})
	outbound.Register[option.StubOptions](registry, C.TypeWireGuard, func(ctx context.Context, router adapter.Router, logger log.ContextLogger, tag string, options option.StubOptions) (adapter.Outbound, error) {
		return nil, E.New("WireGuard outbound is deprecated in sing-box 1.11.0 and removed in sing-box 1.13.0, use WireGuard endpoint instead")
	})
}
