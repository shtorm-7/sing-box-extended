package parser

import (
	"context"

	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-box/parser/clash"
	"github.com/sagernet/sing-box/parser/raw"
	"github.com/sagernet/sing-box/parser/singbox"
	"github.com/sagernet/sing-box/parser/sip008"
	E "github.com/sagernet/sing/common/exceptions"
)

var subscriptionParsers = []func(ctx context.Context, content string) ([]option.Outbound, []option.Endpoint, error){
	singbox.ParseBoxSubscription,
	clash.ParseClashSubscription,
	sip008.ParseSIP008Subscription,
	raw.ParseRawSubscription,
}

func ParseSubscription(ctx context.Context, content string) ([]option.Outbound, []option.Endpoint, error) {
	var pErr error
	for _, parser := range subscriptionParsers {
		outbounds, endpoints, err := parser(ctx, content)
		if len(outbounds) > 0 || len(endpoints) > 0 {
			return outbounds, endpoints, nil
		}
		pErr = E.Errors(pErr, err)
	}
	return nil, nil, E.Cause(pErr, "no servers found")
}
