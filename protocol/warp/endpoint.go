package warp

import (
	"context"
	"math/rand"
	"net"
	"net/netip"
	"strings"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/endpoint"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-box/protocol/wireguard"
	"github.com/sagernet/sing/common"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/json/badoption"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

func RegisterEndpoint(registry *endpoint.Registry) {
	endpoint.Register[option.WARPEndpointOptions](registry, C.TypeWARP, NewEndpoint)
}

type Endpoint struct {
	endpoint.Adapter
	ctx          context.Context
	options      option.WARPEndpointOptions
	endpoint     adapter.Endpoint
	startHandler func()

	await chan struct{}
}

func NewEndpoint(ctx context.Context, router adapter.Router, logger log.ContextLogger, tag string, options option.WARPEndpointOptions) (adapter.Endpoint, error) {
	var dependencies []string
	if options.Detour != "" {
		dependencies = append(dependencies, options.Detour)
	}
	if options.Profile.Detour != "" {
		dependencies = append(dependencies, options.Profile.Detour)
	}
	endpoint := &Endpoint{
		Adapter: endpoint.NewAdapter(C.TypeWARP, tag, []string{N.NetworkTCP, N.NetworkUDP}, dependencies),
		ctx:     ctx,
		options: options,
		await:   make(chan struct{}),
	}
	endpoint.startHandler = func() {
		defer close(endpoint.await)
		config, err := endpoint.provisionConfig(options.Profile.Recreate, nil)
		if err != nil {
			logger.ErrorContext(ctx, err)
			return
		}
		peer := config.Peers[0]
		hostParts := strings.Split(peer.Endpoint.Host, ":")
		endpoint.endpoint, err = wireguard.NewEndpoint(
			ctx,
			router,
			logger,
			tag,
			option.WireGuardEndpointOptions{
				System:                     options.System,
				Name:                       options.Name,
				ListenPort:                 options.ListenPort,
				UDPTimeout:                 options.UDPTimeout,
				Workers:                    options.Workers,
				PreallocatedBuffersPerPool: options.PreallocatedBuffersPerPool,
				DisablePauses:              options.DisablePauses,
				Amnezia:                    options.Amnezia,
				DialerOptions:              options.DialerOptions,

				Address: badoption.Listable[netip.Prefix]{
					netip.MustParsePrefix(config.Interface.Addresses.V4 + "/32"),
					netip.MustParsePrefix(config.Interface.Addresses.V6 + "/128"),
				},
				PrivateKey: config.PrivateKey,
				Peers: []option.WireGuardPeer{
					{
						Address:   hostParts[0],
						Port:      uint16(peer.Endpoint.Ports[rand.Intn(len(peer.Endpoint.Ports))]),
						PublicKey: peer.PublicKey,
						AllowedIPs: badoption.Listable[netip.Prefix]{
							netip.MustParsePrefix("0.0.0.0/0"),
							netip.MustParsePrefix("::/0"),
						},
						PersistentKeepaliveInterval: options.PersistentKeepaliveInterval,
					},
				},
				MTU: 1280,
			},
		)
		if err != nil {
			logger.ErrorContext(ctx, err)
			return
		}
		if err = endpoint.endpoint.Start(adapter.StartStateStart); err != nil {
			logger.ErrorContext(ctx, err)
			return
		}
		if err = endpoint.endpoint.Start(adapter.StartStatePostStart); err != nil {
			logger.ErrorContext(ctx, err)
			return
		}
	}
	return endpoint, nil
}

func (w *Endpoint) Start(stage adapter.StartStage) error {
	if stage != adapter.StartStatePostStart {
		return nil
	}
	go w.startHandler()
	return nil
}

func (w *Endpoint) Close() error {
	if err := w.isEndpointInitialized(w.ctx); err != nil {
		return err
	}
	return common.Close(w.endpoint)
}

func (w *Endpoint) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	if err := w.isEndpointInitialized(ctx); err != nil {
		return nil, err
	}
	return w.endpoint.DialContext(ctx, network, destination)
}

func (w *Endpoint) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	if err := w.isEndpointInitialized(ctx); err != nil {
		return nil, err
	}
	return w.endpoint.ListenPacket(ctx, destination)
}

func (w *Endpoint) isEndpointInitialized(ctx context.Context) error {
	select {
	case <-w.await:
	case <-ctx.Done():
		return ctx.Err()
	}
	if w.endpoint == nil {
		return E.New("endpoint not initialized")
	}
	return nil
}
