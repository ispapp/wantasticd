//go:build !linux

package device

import (
	"wantastic-agent/internal/device/wireguard-go/conn"
	"wantastic-agent/internal/device/wireguard-go/rwcancel"
)

func (device *Device) startRouteListener(_ conn.Bind) (*rwcancel.RWCancel, error) {
	return nil, nil
}
