//go:build !linux

package device

import (
	"github.com/sagernet/wireguard-go/conn"
	"github.com/sagernet/wireguard-go/rwcancel"
)

func (device *Device) startRouteListener(_ conn.Bind) (*rwcancel.RWCancel, error) {
	return nil, nil
}
