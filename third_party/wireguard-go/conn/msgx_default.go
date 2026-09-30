//go:build !darwin || ios

package conn

import (
	"net"

	"golang.org/x/net/ipv6"
)

const supportsMsgX = false

const msgXBatchSize = 1

type msgXState struct{}

func (m *msgXState) reset() {
}

// SetSinglePeerMode is a no-op on platforms without sendmsg_x/recvmsg_x.
func (s *StdNetBind) SetSinglePeerMode() {
}

func (s *StdNetBind) sendMsgX(conn *net.UDPConn, msgs []ipv6.Message) error {
	panic("sendMsgX is not supported on this platform")
}

func (s *StdNetBind) makeReceiveMsgX(conn *net.UDPConn, isV6 bool) (ReceiveFunc, error) {
	panic("makeReceiveMsgX is not supported on this platform")
}
