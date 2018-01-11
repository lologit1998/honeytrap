package server

import (
	"context"
	"io"
	"net"
)

const (
	MessageTypeHello uint8 = 0x0
	MessageTypePing        = 0x2
)

type conn struct {
	net.Conn

	out  chan []byte
	host string

	agent *Agent
}

func (c *conn) Close() {
	c.agent.in <- EOF{
		Laddr: c.LocalAddr(),
		Raddr: c.RemoteAddr(),
	}

	c.Conn.Close()
}

func (c *conn) serve() {
	// TODO: add inactivity timeout
	defer c.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	c.agent.in <- Hello{
		Token: c.agent.token,
		Laddr: c.LocalAddr(),
		Raddr: c.RemoteAddr(),
	}

	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			case buf := <-c.out:
				_, err := c.Write(buf)
				if err == io.EOF {
					return
				} else if err != nil {
					log.Errorf("Error writing to connection: %s", err.Error())
					return
				}
			}
		}
	}()

	buf := make([]byte, 32*1024)

	for {
		nr, er := c.Read(buf)
		if er == io.EOF {
			return
		} else if er != nil {
			log.Errorf("Error reading from connection: ", er.Error())
			return
		} else if nr == 0 {
			continue
		}

		c.agent.in <- ReadWrite{
			Laddr:   c.LocalAddr(),
			Raddr:   c.RemoteAddr(),
			Payload: buf[:nr],
		}
	}
}
