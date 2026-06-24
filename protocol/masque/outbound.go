package masque

import (
	"context"
	"net"
	"net/netip"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/outbound"
	"github.com/sagernet/sing-box/common/cloudflare"
	"github.com/sagernet/sing-box/common/dialer"
	"github.com/sagernet/sing-box/common/tls"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-box/transport/masque"
	"github.com/sagernet/sing/common"
	"github.com/sagernet/sing/common/bufio"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/service"
)

func RegisterOutbound(registry *outbound.Registry) {
	outbound.Register[option.MASQUEOutboundOptions](registry, C.TypeMASQUE, NewOutbound)
}

type Outbound struct {
	outbound.Adapter
	ctx          context.Context
	dnsRouter    adapter.DNSRouter
	logger       logger.ContextLogger
	options      option.MASQUEOutboundOptions
	tunnel       *masque.Tunnel
	startHandler func()

	await chan struct{}
}

func NewOutbound(ctx context.Context, router adapter.Router, logger log.ContextLogger, tag string, options option.MASQUEOutboundOptions) (adapter.Outbound, error) {
	outbound := &Outbound{
		Adapter:   outbound.NewAdapterWithDialerOptions(C.TypeMASQUE, tag, []string{N.NetworkTCP, N.NetworkUDP, N.NetworkICMP}, options.DialerOptions),
		ctx:       ctx,
		dnsRouter: service.FromContext[adapter.DNSRouter](ctx),
		logger:    logger,
		options:   options,
		await:     make(chan struct{}),
	}
	outbound.startHandler = func() {
		defer close(outbound.await)
		appConfig, err := outbound.provisionConfig(options.Profile.Recreate)
		if err != nil {
			logger.ErrorContext(ctx, err)
			return
		}
		privKey, err := appConfig.GetEcPrivateKey()
		if err != nil {
			logger.ErrorContext(ctx, E.New("failed to get private key: ", err))
			return
		}
		peerPubKey, err := appConfig.GetEcEndpointPublicKey()
		if err != nil {
			logger.ErrorContext(ctx, E.New("failed to get public key: ", err))
			return
		}
		cert, err := masque.GenerateCert(privKey, &privKey.PublicKey)
		if err != nil {
			logger.ErrorContext(ctx, E.New("failed to generate cert: ", err))
			return
		}
		serverName := cloudflare.ConnectSNI
		if options.TLS != nil && options.TLS.ServerName != "" {
			serverName = options.TLS.ServerName
		}
		tlsConfig, err := tls.NewMASQUEClient(ctx, logger, serverName, cert, privKey, peerPubKey, common.PtrValueOrDefault(options.TLS))
		if err != nil {
			logger.ErrorContext(ctx, E.New("failed to prepare TLS config: ", err))
			return
		}
		endpoint, err := appConfig.SelectEndpointFromConfig(options.UseHTTP2, options.UseIPv6, 443)
		if err != nil {
			logger.ErrorContext(ctx, E.New("failed to select endpoint: ", err))
			return
		}
		var udpTimeout time.Duration
		if options.UDPTimeout != 0 {
			udpTimeout = time.Duration(options.UDPTimeout)
		} else {
			udpTimeout = C.UDPTimeout
		}
		var udpKeepalivePeriod time.Duration
		if options.UDPKeepalivePeriod != 0 {
			udpKeepalivePeriod = time.Duration(options.UDPKeepalivePeriod)
		} else {
			udpKeepalivePeriod = time.Second * 30
		}
		outboundDialer, err := dialer.NewWithOptions(dialer.Options{
			Context:          ctx,
			Options:          options.DialerOptions,
			RemoteIsDomain:   false,
			ResolverOnDetour: true,
		})
		if err != nil {
			logger.ErrorContext(ctx, err)
			return
		}
		tunnel, err := masque.NewTunnel(
			ctx,
			logger,
			masque.TunnelOptions{
				System: options.System,
				Name:   options.Name,
				CreateDialer: func(interfaceName string) N.Dialer {
					return common.Must1(dialer.NewDefault(ctx, option.DialerOptions{
						BindInterface: interfaceName,
					}))
				},
				Dialer: outboundDialer,
				Address: []netip.Prefix{
					netip.MustParsePrefix(appConfig.IPv4 + "/32"),
					netip.MustParsePrefix(appConfig.IPv6 + "/128"),
				},
				AllowedAddress:       options.AllowedIPs,
				Endpoint:             endpoint,
				TLSConfig:            tlsConfig,
				UseHTTP2:             options.UseHTTP2,
				UDPTimeout:           udpTimeout,
				UDPKeepalivePeriod:   udpKeepalivePeriod,
				UDPInitialPacketSize: options.UDPInitialPacketSize,
				ReconnectDelay:       options.ReconnectDelay.Build(),
			},
		)
		if err != nil {
			logger.ErrorContext(ctx, err)
			return
		}
		outbound.tunnel = tunnel
		if err = outbound.tunnel.Start(false); err != nil {
			logger.ErrorContext(ctx, err)
			return
		}
		if err = outbound.tunnel.Start(true); err != nil {
			logger.ErrorContext(ctx, err)
			return
		}
	}
	return outbound, nil
}

func (w *Outbound) Start(stage adapter.StartStage) error {
	if stage != adapter.StartStatePostStart {
		return nil
	}
	go w.startHandler()
	return nil
}

func (w *Outbound) Close() error {
	if err := w.isTunnelInitialized(w.ctx); err != nil {
		return err
	}
	return w.tunnel.Close()
}

func (w *Outbound) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	if err := w.isTunnelInitialized(ctx); err != nil {
		return nil, err
	}
	switch network {
	case N.NetworkTCP:
		w.logger.InfoContext(ctx, "outbound connection to ", destination)
	case N.NetworkUDP:
		w.logger.InfoContext(ctx, "outbound packet connection to ", destination)
	}
	if destination.IsDomain() {
		destinationAddresses, err := w.dnsRouter.Lookup(ctx, destination.Fqdn, adapter.DNSQueryOptions{})
		if err != nil {
			return nil, err
		}
		return N.DialSerial(ctx, w.tunnel, network, destination, destinationAddresses)
	} else if !destination.Addr.IsValid() {
		return nil, E.New("invalid destination: ", destination)
	}
	return w.tunnel.DialContext(ctx, network, destination)
}

func (w *Outbound) ListenPacketWithDestination(ctx context.Context, destination M.Socksaddr) (net.PacketConn, netip.Addr, error) {
	if err := w.isTunnelInitialized(ctx); err != nil {
		return nil, netip.Addr{}, err
	}
	w.logger.InfoContext(ctx, "outbound packet connection to ", destination)
	if destination.IsDomain() {
		destinationAddresses, err := w.dnsRouter.Lookup(ctx, destination.Fqdn, adapter.DNSQueryOptions{})
		if err != nil {
			return nil, netip.Addr{}, err
		}
		return N.ListenSerial(ctx, w.tunnel, destination, destinationAddresses)
	}
	packetConn, err := w.tunnel.ListenPacket(ctx, destination)
	if err != nil {
		return nil, netip.Addr{}, err
	}
	if destination.IsIP() {
		return packetConn, destination.Addr, nil
	}
	return packetConn, netip.Addr{}, nil
}

func (w *Outbound) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	packetConn, destinationAddress, err := w.ListenPacketWithDestination(ctx, destination)
	if err != nil {
		return nil, err
	}
	if destinationAddress.IsValid() && destination != M.SocksaddrFrom(destinationAddress, destination.Port) {
		return bufio.NewNATPacketConn(bufio.NewPacketConn(packetConn), M.SocksaddrFrom(destinationAddress, destination.Port), destination), nil
	}
	return packetConn, nil
}

func (w *Outbound) isTunnelInitialized(ctx context.Context) error {
	select {
	case <-w.await:
	case <-ctx.Done():
		return ctx.Err()
	}
	if w.tunnel == nil {
		return E.New("tunnel not initialized")
	}
	return nil
}
