package server

import (
	"net"
)

type udpConn struct {
	*net.UDPConn

	agent *Agent
}
