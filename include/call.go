//go:build with_call

package include

import (
	"github.com/sagernet/sing-box/adapter/inbound"
	"github.com/sagernet/sing-box/adapter/outbound"
	"github.com/sagernet/sing-box/protocol/call"
)

func registerCallInbound(registry *inbound.Registry) {
	call.RegisterInbound(registry)
}

func registerCallOutbound(registry *outbound.Registry) {
	call.RegisterOutbound(registry)
}
