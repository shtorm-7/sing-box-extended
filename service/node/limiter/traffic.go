package limiter

import (
	"context"
	"sync"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/protocol/limiter/traffic"
	CM "github.com/sagernet/sing-box/service/manager/constant"
	"github.com/sagernet/sing-box/service/node/constant"
	E "github.com/sagernet/sing/common/exceptions"
)

type ManagedTrafficStrategy interface {
	UpdateStrategies(strategies map[string]traffic.TrafficStrategy)
}

type TrafficLimiterManager struct {
	ctx         context.Context
	nodeManager CM.NodeManager
	logger      log.ContextLogger

	managers map[string]*TrafficLimiterStrategyManager

	mtx sync.Mutex
}

func NewTrafficLimiterManager(ctx context.Context, nodeManager CM.NodeManager, logger log.ContextLogger) *TrafficLimiterManager {
	manager := &TrafficLimiterManager{
		ctx:         ctx,
		nodeManager: nodeManager,
		logger:      logger,
		managers:    make(map[string]*TrafficLimiterStrategyManager),
	}
	go func() {
		timer := time.NewTimer(time.Second * 5)
		for {
			select {
			case <-ctx.Done():
				return
			default:
			}
			select {
			case <-timer.C:
				manager.mtx.Lock()
				strategyManagers := make([]*TrafficLimiterStrategyManager, 0, len(manager.managers))
				for _, strategyManager := range manager.managers {
					strategyManagers = append(strategyManagers, strategyManager)
				}
				manager.mtx.Unlock()
				for _, strategyManager := range strategyManagers {
					strategyManager.mtx.Lock()
					for _, limiter := range strategyManager.limiters {
						err := limiter.UpdateRemainingTraffic()
						if err != nil {
							logger.ErrorContext(ctx, err)
						}
					}
					strategyManager.mtx.Unlock()
				}
				timer.Reset(time.Second * 5)
			case <-ctx.Done():
				return
			}
		}
	}()
	return manager
}

func (m *TrafficLimiterManager) AddTrafficLimiterStrategyManager(outbound adapter.Outbound) error {
	m.mtx.Lock()
	defer m.mtx.Unlock()
	limiter, ok := outbound.(*traffic.Outbound)
	if !ok {
		return E.New("invalid traffic limiter: ", outbound.Tag())
	}
	strategy, ok := limiter.GetStrategy().(ManagedTrafficStrategy)
	if !ok {
		return E.New("strategy ", outbound.Tag(), " is not manager")
	}
	m.managers[outbound.Tag()] = &TrafficLimiterStrategyManager{
		manager:       m,
		strategy:      strategy,
		strategiesMap: make(map[string]traffic.TrafficStrategy),
		limiters:      make(map[string]*TrafficLimiter),
	}
	return nil
}

func (m *TrafficLimiterManager) GetTrafficLimiterStrategyManager(tag string) (constant.TrafficLimiterStrategyManager, bool) {
	m.mtx.Lock()
	defer m.mtx.Unlock()
	manager, ok := m.managers[tag]
	return manager, ok
}

func (m *TrafficLimiterManager) GetTrafficLimiterStrategyManagerTags() []string {
	m.mtx.Lock()
	defer m.mtx.Unlock()
	tags := make([]string, 0, len(m.managers))
	for tag := range m.managers {
		tags = append(tags, tag)
	}
	return tags
}

type TrafficLimiterStrategyManager struct {
	manager       *TrafficLimiterManager
	strategy      ManagedTrafficStrategy
	strategiesMap map[string]traffic.TrafficStrategy
	limiters      map[string]*TrafficLimiter

	mtx sync.Mutex
}

func (i *TrafficLimiterStrategyManager) postUpdate() {
	i.strategy.UpdateStrategies(i.strategiesMap)
}

func (i *TrafficLimiterStrategyManager) UpdateTrafficLimiter(limiter CM.TrafficLimiter) {
	i.mtx.Lock()
	defer i.mtx.Unlock()
	trafficLimiter := NewTrafficLimiter(i.manager.nodeManager, limiter)
	strategy, err := traffic.CreateStrategy(trafficLimiter, limiter.Strategy, limiter.Mode)
	if err != nil {
		i.manager.logger.ErrorContext(i.manager.ctx, err)
		return
	}
	i.limiters[limiter.Username] = trafficLimiter
	i.strategiesMap[limiter.Username] = strategy
	i.postUpdate()
}

func (i *TrafficLimiterStrategyManager) UpdateTrafficLimiters(limiters []CM.TrafficLimiter) {
	i.mtx.Lock()
	defer i.mtx.Unlock()
	clear(i.strategiesMap)
	newStrategiesMap := make(map[string]traffic.TrafficStrategy)
	for _, limiter := range limiters {
		trafficLimiter := NewTrafficLimiter(i.manager.nodeManager, limiter)
		strategy, err := traffic.CreateStrategy(trafficLimiter, limiter.Strategy, limiter.Mode)
		if err != nil {
			i.manager.logger.ErrorContext(i.manager.ctx, err)
			continue
		}
		i.limiters[limiter.Username] = trafficLimiter
		newStrategiesMap[limiter.Username] = strategy
	}
	i.strategiesMap = newStrategiesMap
	i.postUpdate()
}

func (i *TrafficLimiterStrategyManager) DeleteTrafficLimiter(username string) {
	i.mtx.Lock()
	defer i.mtx.Unlock()
	delete(i.strategiesMap, username)
	i.postUpdate()
}

type TrafficLimiter struct {
	manager  CM.NodeManager
	limiter  CM.TrafficLimiter
	new      uint64
	reserved uint64

	mtx sync.Mutex
}

func NewTrafficLimiter(manager CM.NodeManager, limiter CM.TrafficLimiter) *TrafficLimiter {
	return &TrafficLimiter{manager: manager, limiter: limiter}
}

func (l *TrafficLimiter) Reserve(n uint64) (uint64, error) {
	l.mtx.Lock()
	defer l.mtx.Unlock()
	used := l.limiter.RawUsed + l.reserved
	if used >= l.limiter.RawQuota {
		return 0, E.New("traffic limit exceeded")
	}
	remaining := l.limiter.RawQuota - used
	if n > remaining {
		l.reserved += remaining
		return remaining, E.New("traffic limit exceeded")
	}
	l.reserved += n
	return n, nil
}

func (l *TrafficLimiter) Commit(reserved uint64, n uint64) {
	if reserved == 0 && n == 0 {
		return
	}
	l.mtx.Lock()
	defer l.mtx.Unlock()
	if reserved > l.reserved {
		reserved = l.reserved
	}
	l.reserved -= reserved
	l.limiter.RawUsed += n
	l.new += n
}

func (l *TrafficLimiter) UpdateRemainingTraffic() error {
	l.mtx.Lock()
	if l.new == 0 {
		l.mtx.Unlock()
		return nil
	}
	new := l.new
	l.new = 0
	l.mtx.Unlock()
	newUsed, err := l.manager.AddTrafficUsage(l.limiter.ID, new)
	l.mtx.Lock()
	defer l.mtx.Unlock()
	if err == nil {
		l.limiter.RawUsed = newUsed
	} else {
		l.new += new
	}
	return err
}
