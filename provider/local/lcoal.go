package provider

import (
	"context"
	"os"
	"path/filepath"
	"time"

	"github.com/sagernet/fswatch"
	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/provider"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-box/provider/parser"
	"github.com/sagernet/sing/common"
	E "github.com/sagernet/sing/common/exceptions"
	F "github.com/sagernet/sing/common/format"
	"github.com/sagernet/sing/service"
	"github.com/sagernet/sing/service/filemanager"
)

func RegisterProviderLocal(registry *provider.Registry) {
	provider.Register[option.ProviderLocalOptions](registry, C.ProviderTypeLocal, NewProviderLocal)
}

func RegisterProviderInline(registry *provider.Registry) {
	provider.Register[option.ProviderInlineOptions](registry, C.ProviderTypeInline, NewProviderInline)
}

var _ adapter.Provider = (*ProviderLocal)(nil)

type ProviderLocal struct {
	provider.Adapter
	ctx         context.Context
	logger      log.ContextLogger
	provider    adapter.ProviderManager
	path        string
	lastOutOpts []option.Outbound
	lastUpdated time.Time
	watcher     *fswatch.Watcher
}

func NewProviderInline(ctx context.Context, router adapter.Router, logFactory log.Factory, tag string, options option.ProviderInlineOptions) (adapter.Provider, error) {
	var (
		outbound = service.FromContext[adapter.OutboundManager](ctx)
		logger   = logFactory.NewLogger(F.ToString("provider/inline", "[", tag, "]"))
	)
	provider := &ProviderLocal{
		Adapter: provider.NewAdapter(ctx, router, outbound, logFactory, logger, tag, C.ProviderTypeInline, options.HealthCheck),
		ctx:     ctx,
		logger:  logger,
	}
	provider.UpdateOutbounds(nil, options.Outbounds)
	return provider, nil
}

func NewProviderLocal(ctx context.Context, router adapter.Router, logFactory log.Factory, tag string, options option.ProviderLocalOptions) (adapter.Provider, error) {
	if options.Path == "" {
		return nil, E.New("provider path is required")
	}
	var (
		outbound = service.FromContext[adapter.OutboundManager](ctx)
		logger   = logFactory.NewLogger(F.ToString("provider/local", "[", tag, "]"))
	)
	provider := &ProviderLocal{
		Adapter:  provider.NewAdapter(ctx, router, outbound, logFactory, logger, tag, C.ProviderTypeLocal, options.HealthCheck),
		ctx:      ctx,
		logger:   logger,
		provider: service.FromContext[adapter.ProviderManager](ctx),
	}
	filePath := filemanager.BasePath(ctx, options.Path)
	provider.path, _ = filepath.Abs(filePath)
	watcher, err := fswatch.NewWatcher(fswatch.Options{
		Path: []string{filePath},
		Callback: func(path string) {
			uErr := provider.reloadFile(path)
			if uErr != nil {
				logger.Error(E.Cause(uErr, "reload provider ", tag))
			}
			provider.UpdateGroups()
		},
	})
	if err != nil {
		return nil, err
	}
	provider.watcher = watcher
	return provider, nil
}

func (s *ProviderLocal) Start() error {
	err := s.reloadFile(s.path)
	if err != nil {
		return err
	}
	s.UpdateGroups()
	if s.watcher != nil {
		err := s.watcher.Start()
		if err != nil {
			s.logger.Error(E.Cause(err, "watch provider file"))
		}
	}
	return s.Adapter.Start()
}

func (s *ProviderLocal) UpdatedAt() time.Time {
	return s.lastUpdated
}

func (s *ProviderLocal) reloadFile(path string) error {
	if fileInfo, err := os.Stat(path); err == nil {
		s.lastUpdated = fileInfo.ModTime()
	}
	content, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	outboundOpts, err := parser.ParseSubscription(s.ctx, string(content))
	if err != nil {
		return err
	}
	s.UpdateOutbounds(s.lastOutOpts, outboundOpts)
	s.lastOutOpts = outboundOpts
	return nil
}

func (s *ProviderLocal) Close() error {
	return common.Close(&s.Adapter, common.PtrOrNil(s.watcher))
}
