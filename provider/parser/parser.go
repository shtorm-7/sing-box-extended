package parser

import (
	"context"

	"github.com/sagernet/sing-box/option"
	E "github.com/sagernet/sing/common/exceptions"
)

var subscriptionParsers = []func(ctx context.Context, content string) ([]option.Outbound, error){
	ParseBoxSubscription,
	ParseClashSubscription,
	ParseSIP008Subscription,
	ParseRawSubscription,
}

func ParseSubscription(ctx context.Context, content string) ([]option.Outbound, error) {
	var pErr error
	for _, parser := range subscriptionParsers {
		servers, err := parser(ctx, content)
		if len(servers) > 0 {
			return servers, nil
		}
		pErr = E.Errors(pErr, err)
	}
	return nil, E.Cause(pErr, "no servers found")
}
