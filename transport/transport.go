package transport

import (
	"net"
	"time"
)

// IdleDeadlineConn wraps a net.Conn and bumps its read/write deadline on every
// successful Read so the connection is culled if it goes fully silent for idleTimeout.
// This prevents io.Copy goroutines from hanging forever when the upstream JEG process
// hangs or deadlocks (TCP Keep-Alives only detect OS-level liveness, not app-level).
type IdleDeadlineConn struct {
	net.Conn
	Timeout time.Duration
}

func (c *IdleDeadlineConn) Read(b []byte) (int, error) {
	// Bump the deadline before each read; a successful transfer keeps the pipe alive.
	_ = c.Conn.SetDeadline(time.Now().Add(c.Timeout))
	return c.Conn.Read(b)
}

func (c *IdleDeadlineConn) Write(b []byte) (int, error) {
	_ = c.Conn.SetDeadline(time.Now().Add(c.Timeout))
	return c.Conn.Write(b)
}
