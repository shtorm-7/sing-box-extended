package traffic

import (
	"context"
	"net"
	"sync"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/onclose"
	E "github.com/sagernet/sing/common/exceptions"
)

type (
	ConnWrapper       = func(ctx context.Context, conn net.Conn, limiter TrafficLimiter, reverse bool) net.Conn
	PacketConnWrapper = func(ctx context.Context, conn net.PacketConn, limiter TrafficLimiter, reverse bool) net.PacketConn
)

type TrafficStrategy interface {
	wrapConn(ctx context.Context, conn net.Conn, metadata *adapter.InboundContext, reverse bool) (net.Conn, error)
	wrapPacketConn(ctx context.Context, conn net.PacketConn, metadata *adapter.InboundContext, reverse bool) (net.PacketConn, error)
}

type TrafficLimiterStrategy interface {
	getLimiter(ctx context.Context, metadata *adapter.InboundContext) (TrafficLimiter, error)
}

type DefaultWrapStrategy struct {
	limiterStrategy   TrafficLimiterStrategy
	connWrapper       ConnWrapper
	packetConnWrapper PacketConnWrapper
}

func NewDefaultWrapStrategy(limiterStrategy TrafficLimiterStrategy, connWrapper ConnWrapper, packetConnWrapper PacketConnWrapper) *DefaultWrapStrategy {
	return &DefaultWrapStrategy{limiterStrategy, connWrapper, packetConnWrapper}
}

func (s *DefaultWrapStrategy) wrapConn(ctx context.Context, conn net.Conn, metadata *adapter.InboundContext, reverse bool) (net.Conn, error) {
	limiter, err := s.limiterStrategy.getLimiter(ctx, metadata)
	if err != nil {
		return conn, err
	}
	_, err = limiter.Reserve(0)
	if err != nil {
		return conn, err
	}
	return s.connWrapper(ctx, conn, limiter, reverse), nil
}

func (s *DefaultWrapStrategy) wrapPacketConn(ctx context.Context, conn net.PacketConn, metadata *adapter.InboundContext, reverse bool) (net.PacketConn, error) {
	limiter, err := s.limiterStrategy.getLimiter(ctx, metadata)
	if err != nil {
		return conn, err
	}
	_, err = limiter.Reserve(0)
	if err != nil {
		return conn, err
	}
	return s.packetConnWrapper(ctx, conn, limiter, reverse), nil
}

type GlobalTrafficStrategy struct {
	limiter TrafficLimiter
}

func NewGlobalTrafficStrategy(limiter TrafficLimiter) *GlobalTrafficStrategy {
	return &GlobalTrafficStrategy{
		limiter: limiter,
	}
}

func (s *GlobalTrafficStrategy) getLimiter(ctx context.Context, metadata *adapter.InboundContext) (TrafficLimiter, error) {
	return s.limiter, nil
}

type connEntry struct {
	conn net.Conn
}

type ManagerTrafficStrategy struct {
	strategies map[string]TrafficStrategy
	conns      map[string][]*connEntry

	mtx sync.Mutex
}

func NewManagerTrafficStrategy() *ManagerTrafficStrategy {
	return &ManagerTrafficStrategy{
		conns: make(map[string][]*connEntry),
	}
}

func (s *ManagerTrafficStrategy) wrapConn(ctx context.Context, conn net.Conn, metadata *adapter.InboundContext, reverse bool) (net.Conn, error) {
	strategy, user, err := s.getStrategy(ctx, metadata)
	if err != nil {
		return nil, err
	}
	wrapped, err := strategy.wrapConn(ctx, conn, metadata, reverse)
	if err != nil {
		return nil, err
	}
	entry := &connEntry{conn: conn}
	s.mtx.Lock()
	s.conns[user] = append(s.conns[user], entry)
	s.mtx.Unlock()
	return onclose.NewConn(wrapped, func() {
		s.mtx.Lock()
		entries := s.conns[user]
		for i, e := range entries {
			if e == entry {
				s.conns[user] = append(entries[:i], entries[i+1:]...)
				break
			}
		}
		s.mtx.Unlock()
	}), nil
}

func (s *ManagerTrafficStrategy) wrapPacketConn(ctx context.Context, conn net.PacketConn, metadata *adapter.InboundContext, reverse bool) (net.PacketConn, error) {
	strategy, _, err := s.getStrategy(ctx, metadata)
	if err != nil {
		return nil, err
	}
	return strategy.wrapPacketConn(ctx, conn, metadata, reverse)
}

func (s *ManagerTrafficStrategy) getStrategy(ctx context.Context, metadata *adapter.InboundContext) (TrafficStrategy, string, error) {
	s.mtx.Lock()
	defer s.mtx.Unlock()
	var user string
	if metadata != nil {
		user = metadata.User
	}
	strategy, ok := s.strategies[user]
	if ok {
		return strategy, user, nil
	}
	return nil, user, E.New("user strategy not found: ", user)
}

func (s *ManagerTrafficStrategy) UpdateStrategies(strategies map[string]TrafficStrategy) {
	s.mtx.Lock()
	var closedEntries []*connEntry
	for user, entries := range s.conns {
		if _, exists := strategies[user]; !exists {
			closedEntries = append(closedEntries, entries...)
			delete(s.conns, user)
		}
	}
	s.strategies = strategies
	s.mtx.Unlock()
	for _, entry := range closedEntries {
		entry.conn.Close()
	}
}

type BypassTrafficStrategy struct{}

func NewBypassTrafficStrategy() *BypassTrafficStrategy {
	return &BypassTrafficStrategy{}
}

func (s *BypassTrafficStrategy) wrapConn(ctx context.Context, conn net.Conn, metadata *adapter.InboundContext, reverse bool) (net.Conn, error) {
	return conn, nil
}

func (s *BypassTrafficStrategy) wrapPacketConn(ctx context.Context, conn net.PacketConn, metadata *adapter.InboundContext, reverse bool) (net.PacketConn, error) {
	return conn, nil
}

func CreateStrategy(limiter TrafficLimiter, strategy string, mode string) (TrafficStrategy, error) {
	switch strategy {
	case "bypass":
		return NewBypassTrafficStrategy(), nil
	case "global", "":
		var (
			connWrapper       ConnWrapper
			packetConnWrapper PacketConnWrapper
		)
		switch mode {
		case "download":
			connWrapper = connWithDownloadTrafficWrapper
			packetConnWrapper = packetConnWithDownloadTrafficWrapper
		case "upload":
			connWrapper = connWithUploadTrafficWrapper
			packetConnWrapper = packetConnWithUploadTrafficWrapper
		case "bidirectional":
			connWrapper = connWithBidirectionalTrafficWrapper
			packetConnWrapper = packetConnWithBidirectionalTrafficWrapper
		default:
			return nil, E.New("mode not found: ", mode)
		}
		return NewDefaultWrapStrategy(
			NewGlobalTrafficStrategy(limiter),
			connWrapper,
			packetConnWrapper,
		), nil
	default:
		return nil, E.New("strategy not found: ", strategy)
	}
}
