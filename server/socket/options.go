package socket

import "time"

type Options struct {
	MaxConnections int
	MaxMessageSize int64
	SendQueueSize  int
	WriteTimeout   time.Duration
	OnMessage      func(c *Client, data []byte)
}

func DefaultOptions() Options {
	return Options{
		MaxConnections: 10000,
		MaxMessageSize: 32 << 10,
		SendQueueSize:  64,
		WriteTimeout:   10 * time.Second,
	}
}
