package socket

import "time"

type Receiver interface {
	Receive(data []byte)
	Close()
}

type Options struct {
	MaxConnections int
	MaxMessageSize int64
	SendQueueSize  int
	WriteTimeout   time.Duration
	PingInterval   time.Duration
	PongTimeout    time.Duration
	Accept         func(c *Client) Receiver
}

func DefaultOptions() Options {
	return Options{
		MaxConnections: 10000,
		MaxMessageSize: 32 << 10,
		SendQueueSize:  64,
		WriteTimeout:   10 * time.Second,
		PingInterval:   30 * time.Second,
		PongTimeout:    60 * time.Second,
	}
}
