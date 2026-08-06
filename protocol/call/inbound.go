package call

import (
	"context"
	"net"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/inbound"
	"github.com/sagernet/sing-box/common/dialer"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-box/transport/call"
	"github.com/sagernet/sing/common/bufio"
	"github.com/sagernet/sing/common/bufio/deadline"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/service"
)

func RegisterInbound(registry *inbound.Registry) {
	inbound.Register[option.CallInboundOptions](registry, C.TypeCall, NewInbound)
}

type Inbound struct {
	inbound.Adapter
	ctx     context.Context
	router  adapter.ConnectionRouterEx
	logger  logger.ContextLogger
	options option.CallInboundOptions
	dialer  N.Dialer
	bridge  *call.Bridge
}

func NewInbound(ctx context.Context, router adapter.Router, logger log.ContextLogger, tag string, options option.CallInboundOptions) (adapter.Inbound, error) {
	if options.Platform == "" {
		return nil, E.New("missing platform")
	}
	outboundDialer, err := dialer.New(ctx, options.DialerOptions, true)
	if err != nil {
		return nil, err
	}
	return &Inbound{
		Adapter: inbound.NewAdapter(C.TypeCall, tag),
		ctx:     ctx,
		router:  router,
		logger:  logger,
		options: options,
		dialer:  outboundDialer,
	}, nil
}

func (h *Inbound) Start(stage adapter.StartStage) error {
	if stage != adapter.StartStatePostStart {
		return nil
	}
	go h.run()
	return nil
}

func (h *Inbound) Close() error {
	if h.bridge == nil {
		return nil
	}
	return h.bridge.Close()
}

func (h *Inbound) run() {
	dnsRouter := service.FromContext[adapter.DNSRouter](h.ctx)
	bridge, err := call.Connect(h.ctx, call.Config{
		Platform:     h.options.Platform,
		Mode:         h.options.Mode,
		JoinLink:     h.options.JoinLink,
		CookieString: h.options.Cookies.Header(),
		Email:        h.options.Email,
		Password:     h.options.Password,
		ReadBuffer:   h.options.ReadBuffer,
		Role:         call.RoleCreator,
		Dialer:       h.dialer,
		DNSRouter:    dnsRouter,
		Logger:       h.logger,
	})
	if err != nil {
		h.logger.ErrorContext(h.ctx, err)
		return
	}
	h.bridge = bridge
	bridge.SetAcceptHandler(func(conn net.Conn, destination string) {
		h.handleConnection(conn, M.ParseSocksaddr(destination))
	})
	bridge.SetUDPAcceptHandler(func(conn net.Conn, destination string) {
		h.handlePacketConnection(bufio.NewUnbindPacketConnWithAddr(conn, M.ParseSocksaddr(destination)), M.ParseSocksaddr(destination))
	})
}

func (h *Inbound) handleConnection(conn net.Conn, destination M.Socksaddr) {
	ctx := log.ContextWithNewID(h.ctx)
	var metadata adapter.InboundContext
	metadata.Inbound = h.Tag()
	metadata.InboundType = h.Type()
	metadata.Source = M.Socksaddr{}
	metadata.Destination = destination
	h.logger.InfoContext(ctx, "inbound connection to ", destination)
	h.router.RouteConnectionEx(ctx, deadline.NewConn(conn), metadata, N.OnceClose(func(it error) {
		conn.Close()
	}))
}

func (h *Inbound) handlePacketConnection(conn N.PacketConn, destination M.Socksaddr) {
	ctx := log.ContextWithNewID(h.ctx)
	var metadata adapter.InboundContext
	metadata.Inbound = h.Tag()
	metadata.InboundType = h.Type()
	metadata.Source = M.Socksaddr{}
	metadata.Destination = destination
	h.logger.InfoContext(ctx, "inbound packet connection to ", destination)
	h.router.RoutePacketConnectionEx(ctx, conn, metadata, N.OnceClose(func(it error) {
		conn.Close()
	}))
}
