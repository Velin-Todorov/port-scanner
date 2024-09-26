package banner

import (
	"net"
	"time"
)

type BannerGrabber interface {
	Grab(conn net.Conn) (string, error)
}

type TCPBannerGrabber struct {
	Timeout time.Duration
}

