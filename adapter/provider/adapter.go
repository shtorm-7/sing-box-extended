package provider

import (
	"context"
	"reflect"
	"sync"
	"sync/atomic"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/urltest"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/batch"
	E "github.com/sagernet/sing/common/exceptions"
	F "github.com/sagernet/sing/common/format"
	"github.com/sagernet/sing/common/x/list"
	"github.com/sagernet/sing/service"
)

type Adapter struct {
	ctx            context.Context
	outbound       adapter.OutboundManager
	router         adapter.Router
	logFactory     log.Factory
	logger         log.ContextLogger
	providerType   string
	providerTag    string
	outbounds      []adapter.Outbound
	outboundsByTag map[string]adapter.Outbound
	ticker         *time.Ticker
	checking       atomic.Bool
	history        adapter.URLTestHistoryStorage
	callbackAccess sync.Mutex
	callbacks      list.List[adapter.ProviderUpdateCallback]

	link     string
	enabled  bool
	timeout  time.Duration
	interval time.Duration
}

func NewAdapter(ctx context.Context, router adapter.Router, outbound adapter.OutboundManager, logFactory log.Factory, logger log.ContextLogger, providerTag string, providerType string, options option.ProviderHealthCheckOptions) Adapter {
	timeout := time.Duration(options.Timeout)
	if timeout == 0 {
		timeout = 3 * time.Second
	}
	interval := time.Duration(options.Interval)
	if interval == 0 {
		interval = 10 * time.Minute
	}
	if interval < time.Minute {
		interval = time.Minute
	}
	return Adapter{
		ctx:          ctx,
		outbound:     outbound,
		router:       router,
		logFactory:   logFactory,
		logger:       logger,
		providerType: providerType,
		providerTag:  providerTag,

		enabled:  options.Enabled,
		link:     options.URL,
		timeout:  timeout,
		interval: interval,
	}
}

func (a *Adapter) Start() error {
	a.history = service.FromContext[adapter.URLTestHistoryStorage](a.ctx)
	if a.history == nil {
		if clashServer := service.FromContext[adapter.ClashServer](a.ctx); clashServer != nil {
			a.history = clashServer.HistoryStorage()
		} else {
			a.history = urltest.NewHistoryStorage()
		}
	}
	go a.loopCheck()
	return nil
}

func (a *Adapter) Type() string {
	return a.providerType
}

func (a *Adapter) Tag() string {
	return a.providerTag
}

func (a *Adapter) Outbounds() []adapter.Outbound {
	return a.outbounds
}

func (a *Adapter) Outbound(tag string) (adapter.Outbound, bool) {
	if a.outboundsByTag == nil {
		return nil, false
	}
	detour, ok := a.outboundsByTag[tag]
	return detour, ok
}

func (a *Adapter) UpdateOutbounds(oldOpts []option.Outbound, newOpts []option.Outbound) {
	a.removeUseless(newOpts)
	var (
		oldOptByTag    = make(map[string]option.Outbound)
		outbounds      = make([]adapter.Outbound, 0, len(newOpts))
		outboundsByTag = make(map[string]adapter.Outbound)
	)
	for _, opt := range oldOpts {
		oldOptByTag[opt.Tag] = opt
	}
	for i, opt := range newOpts {
		var tag string
		if opt.Tag != "" {
			tag = F.ToString(a.providerTag, "/", opt.Tag)
		} else {
			tag = F.ToString(a.providerTag, "/", i)
		}
		outbound, exist := a.outbound.Outbound(tag)
		if !exist || !reflect.DeepEqual(opt, oldOptByTag[opt.Tag]) {
			err := a.outbound.Create(
				adapter.WithContext(a.ctx, &adapter.InboundContext{
					Outbound: tag,
				}),
				a.router,
				a.logFactory.NewLogger(F.ToString("outbound/", opt.Type, "[", tag, "]")),
				tag,
				opt.Type,
				opt.Options,
			)
			if err != nil {
				a.logger.Warn(err, " in ", tag, ", skip create this outbound")
				continue
			}
			outbound, _ = a.outbound.Outbound(tag)
		}
		outbounds = append(outbounds, outbound)
		outboundsByTag[tag] = outbound
	}
	if a.enabled && a.history != nil {
		go a.HealthCheck(a.ctx)
	}
	a.outbounds = outbounds
	a.outboundsByTag = outboundsByTag
}

func (a *Adapter) HealthCheck(ctx context.Context) (map[string]uint16, error) {
	if a.ticker != nil {
		a.ticker.Reset(a.interval)
	}
	return a.healthcheck(ctx)
}

func (a *Adapter) RegisterCallback(callback adapter.ProviderUpdateCallback) *list.Element[adapter.ProviderUpdateCallback] {
	a.callbackAccess.Lock()
	defer a.callbackAccess.Unlock()
	return a.callbacks.PushBack(callback)
}

func (a *Adapter) UnregisterCallback(element *list.Element[adapter.ProviderUpdateCallback]) {
	a.callbackAccess.Lock()
	defer a.callbackAccess.Unlock()
	a.callbacks.Remove(element)
}

func (a *Adapter) UpdateGroups() {
	for element := a.callbacks.Front(); element != nil; element = element.Next() {
		element.Value(a.providerTag)
	}
}

func (a *Adapter) Close() error {
	if a.ticker != nil {
		a.ticker.Stop()
	}
	outbounds := a.outbounds
	a.outbounds = nil
	var err error
	for _, ob := range outbounds {
		if err2 := a.outbound.Remove(ob.Tag()); err2 != nil {
			err = E.Append(err, err2, func(err error) error {
				return E.Cause(err, "close outbound [", ob.Tag(), "]")
			})
		}
	}
	return err
}

func (a *Adapter) loopCheck() {
	if !a.enabled {
		return
	}
	a.ticker = time.NewTicker(a.interval)
	a.healthcheck(a.ctx)
	for {
		select {
		case <-a.ctx.Done():
			return
		case <-a.ticker.C:
			a.healthcheck(a.ctx)
		}
	}
}

func (a *Adapter) healthcheck(ctx context.Context) (map[string]uint16, error) {
	result := make(map[string]uint16)
	if a.checking.Swap(true) {
		return result, nil
	}
	defer a.checking.Store(false)
	b, _ := batch.New(ctx, batch.WithConcurrencyNum[any](10))
	var resultAccess sync.Mutex
	checked := make(map[string]bool)
	for _, detour := range a.outbounds {
		tag := detour.Tag()
		if checked[tag] {
			continue
		}
		checked[tag] = true
		b.Go(tag, func() (any, error) {
			ctx, cancel := context.WithTimeout(a.ctx, a.timeout)
			defer cancel()
			t, err := urltest.URLTest(ctx, a.link, detour)
			if err != nil {
				a.logger.Debug("outbound ", tag, " unavailable: ", err)
				a.history.DeleteURLTestHistory(tag)
			} else {
				a.logger.Debug("outbound ", tag, " available: ", t, "ms")
				a.history.StoreURLTestHistory(tag, &adapter.URLTestHistory{
					Time:  time.Now(),
					Delay: t,
				})
				resultAccess.Lock()
				result[tag] = t
				resultAccess.Unlock()
			}
			return nil, nil
		})
	}
	b.Wait()
	return result, nil
}

func (a *Adapter) removeUseless(newOpts []option.Outbound) {
	if len(a.outbounds) == 0 {
		return
	}
	exists := make(map[string]bool)
	for i, opt := range newOpts {
		var tag string
		if opt.Tag != "" {
			tag = F.ToString(a.providerTag, "/", opt.Tag)
		} else {
			tag = F.ToString(a.providerTag, "/", i)
		}
		exists[tag] = true
	}
	for _, opt := range a.outbounds {
		if !exists[opt.Tag()] {
			if err := a.outbound.Remove(opt.Tag()); err != nil {
				a.logger.Error(err, "close outbound [", opt.Tag(), "]")
			}
		}
	}
}
