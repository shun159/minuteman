package dhcpv4

import (
	"context"
	"fmt"
	"log"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"
)

// conn is the per-interface socket I/O serveOne needs; packetConn is the
// production implementation, and tests substitute a fake so serveOne's
// error handling can be exercised without a raw socket.
type conn interface {
	recv() (*Message, error)
	send(reply *Message, dstIP netip.Addr, dstMAC net.HardwareAddr) error
	Close() error
}

type worker struct {
	cfg  InterfaceConfig
	pool *Pool
	conn conn
}

// Server is a configured, ready-to-run DHCPv4 server: New has already
// validated every interface's pool and opened its packet socket.
type Server struct {
	workers []worker
}

// New validates every interface's pool and opens its packet socket
// synchronously, returning any failure — an invalid/non-IPv4 subnet, a
// missing interface, a socket/bind/filter error — to the caller instead of
// letting it surface only in a log line from a background goroutine (so a
// misconfigured -dhcpv4 fails minuteman's startup rather than leaving it
// running with no DHCP service). On any failure every already-opened socket
// is closed.
func New(cfgs []InterfaceConfig) (*Server, error) {
	if len(cfgs) == 0 {
		return nil, fmt.Errorf("dhcpv4: no interfaces configured")
	}
	s := &Server{}
	for _, cfg := range cfgs {
		pool, err := NewPool(cfg.Subnet, cfg.ServerIP, cfg.LeaseTime)
		if err != nil {
			s.closeAll()
			return nil, err
		}
		c, err := listenPacket(cfg.Iface, cfg.ServerIP)
		if err != nil {
			s.closeAll()
			return nil, err
		}
		s.workers = append(s.workers, worker{cfg: cfg, pool: pool, conn: c})
	}
	return s, nil
}

func (s *Server) closeAll() {
	for _, w := range s.workers {
		w.conn.Close()
	}
}

// Serve runs each interface's receive/handle/reply loop until ctx is
// cancelled (returning nil after closing every socket) or one loop hits a
// runtime read error, which it returns — a single interface's DHCP failing
// is surfaced, not swallowed. The read errors that closing the sockets on
// shutdown itself provokes are suppressed via the shuttingDown flag.
func (s *Server) Serve(ctx context.Context) error {
	var (
		wg           sync.WaitGroup
		shuttingDown atomic.Bool
		errCh        = make(chan error, len(s.workers))
	)
	for _, w := range s.workers {
		wg.Add(1)
		go func(w worker) {
			defer wg.Done()
			if err := serveOne(w.cfg, w.pool, w.conn); err != nil && !shuttingDown.Load() {
				errCh <- fmt.Errorf("dhcpv4: %s: %w", w.cfg.Iface, err)
			}
		}(w)
	}

	var runErr error
	select {
	case <-ctx.Done():
	case runErr = <-errCh:
	}
	shuttingDown.Store(true)
	s.closeAll()
	wg.Wait()
	return runErr
}

// serveOne is one interface's receive/handle/reply loop. It returns the read
// error that ends it (Server.Serve decides whether that's a benign shutdown
// or a failure to report).
func serveOne(cfg InterfaceConfig, pool *Pool, c conn) error {
	for {
		req, err := c.recv()
		if err != nil {
			return err
		}
		reply := handle(cfg, pool, req, time.Now())
		if reply == nil {
			continue
		}
		dstIP, dstMAC := destination(reply)
		if err := c.send(reply, dstIP, dstMAC); err != nil {
			log.Printf("dhcpv4: sending %s to %s on %s: %v",
				replyType(reply), dstIP, cfg.Iface, err)
		}
	}
}

// replyType is the message type of reply, for logging.
func replyType(reply *Message) MessageType {
	mt, _ := reply.Options.MessageType()
	return mt
}
