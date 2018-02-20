package server

import (
	"context"
	"io"
	"net"
	"runtime"
)

const (
	MessageTypeHello uint8 = 0x0
	MessageTypePing        = 0x2
)

type conn struct {
	net.Conn

	id uint32

	out  chan []byte
	host string

	agent *Agent

	close  chan struct{}
	closed bool
}

func (c *conn) Close() {
	// don't have to mutex, closing all in same goroutine
	if c.closed {
		return
	}

	close(c.out)
	c.Conn.Close()

	c.closed = true
}

func (c *conn) serve() {
	defer func() {
		if err := recover(); err != nil {
			trace := make([]byte, 1024)
			count := runtime.Stack(trace, true)
			log.Errorf("Error: %s\nStack of %d bytes: %s\n", err, count, string(trace))
			return
		}
	}()

	c.agent.in <- Hello{
		Token: c.agent.token,
		Laddr: c.LocalAddr(),
		Raddr: c.RemoteAddr(),
	}

	ctx, cancel := context.WithCancel(context.Background())

	defer func() {
		cancel()

		go func() {
			for _ = range c.out {
			}
		}()

		c.agent.in <- EOF{
			Laddr: c.LocalAddr(),
			Raddr: c.RemoteAddr(),
		}
	}()

	go func() {
		defer c.Close()

		for {
			select {
			case <-ctx.Done():
				return
			case <-c.close:
				return
			case buf := <-c.out:
				_, err := c.Write(buf)
				if err == io.EOF {
					return
				} else if err != nil {
					return
				}
			}
		}
	}()

	buf := make([]byte, 64*1024)

	for {
		nr, er := c.Read(buf)
		if er == io.EOF {
			return
		} else if er != nil {
			return
		}

		c.agent.in <- ReadWrite{
			Laddr:   c.LocalAddr(),
			Raddr:   c.RemoteAddr(),
			Payload: buf[:nr],
		}
	}

}
