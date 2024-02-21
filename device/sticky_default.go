//go:build !linux

package device

import (
	"github.com/GFW-knocker/wireguard/conn"
	"github.com/GFW-knocker/wireguard/rwcancel"
)

func (device *Device) startRouteListener(bind conn.Bind) (*rwcancel.RWCancel, error) {
	return nil, nil
}
