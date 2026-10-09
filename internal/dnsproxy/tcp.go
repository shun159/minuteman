package dnsproxy

import (
	"context"
	"io"
	"net"
	"net/netip"
	"time"

	"github.com/shun159/molecule/net/gentcpacceptor"
	"github.com/shun159/molecule/proc"
)

// tcpDialTimeout bounds how long a relay waits to connect to one upstream
// before trying the next.
const tcpDialTimeout = 5 * time.Second

// relay is the handler of each DNS-over-TCP connection: it proxies the
// client's bytes to and from the first of upstreams that accepts a
// connection, verbatim in both directions -- a full byte-level relay rather
// than parsing individual length-prefixed DNS messages (RFC 7766 §6.2.1
// allows pipelining multiple queries on one connection, which a byte-level
// relay handles for free without this package ever needing to frame
// messages itself). It returns once both directions have finished copying
// (i.e. one side closed), or the process dies.
func relay(upstreams []netip.AddrPort) gentcpacceptor.Handler {
	return func(self *proc.Self, client net.Conn) error {
		defer client.Close()

		var upstream net.Conn
		d := net.Dialer{Timeout: tcpDialTimeout}
		for _, addr := range upstreams {
			conn, err := d.DialContext(self.Context(), "tcp", addr.String())
			if err == nil {
				upstream = conn
				break
			}
		}
		if upstream == nil {
			return nil
		}
		defer upstream.Close()
		// The copies block on the connections: closing them is what ends
		// the relay when the process dies.
		stop := context.AfterFunc(self.Context(), func() {
			client.Close()
			upstream.Close()
		})
		defer stop()

		done := make(chan struct{}, 2)
		go func() {
			io.Copy(upstream, client)
			closeWrite(upstream)
			done <- struct{}{}
		}()
		go func() {
			io.Copy(client, upstream)
			closeWrite(client)
			done <- struct{}{}
		}()
		<-done
		<-done
		return nil
	}
}

func closeWrite(c net.Conn) {
	if tc, ok := c.(*net.TCPConn); ok {
		tc.CloseWrite()
	}
}
