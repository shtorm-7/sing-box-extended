//go:build !with_call

package include

import (
	"context"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/inbound"
	"github.com/sagernet/sing-box/adapter/outbound"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	E "github.com/sagernet/sing/common/exceptions"
)

func registerCallInbound(registry *inbound.Registry) {
	inbound.Register[option.CallInboundOptions](registry, C.TypeCall, func(ctx context.Context, router adapter.Router, logger log.ContextLogger, tag string, options option.CallInboundOptions) (adapter.Inbound, error) {
		return nil, E.New(`Call is not included in this build, rebuild with -tags with_call`)
	})
}

func registerCallOutbound(registry *outbound.Registry) {
	outbound.Register[option.CallOutboundOptions](registry, C.TypeCall, func(ctx context.Context, router adapter.Router, logger log.ContextLogger, tag string, options option.CallOutboundOptions) (adapter.Outbound, error) {
		return nil, E.New(`Call is not included in this build, rebuild with -tags with_call`)
	})
}
