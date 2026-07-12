package dhcpv4

import (
	"context"
	"fmt"
	"log"
	"sync"
	"time"
)

// Serve runs the DHCPv4 server on every interface in cfgs until ctx is
// cancelled, at which point every socket is closed and Serve returns nil. A
// non-nil return means cfgs was empty, an interface's pool config was
// invalid, or opening a packet socket failed outright -- all startup
// failures worth surfacing before the datapath is considered up.
//
// Each interface gets its own goroutine, packet socket, and lease Pool;
// there is no shared state between interfaces, so no locking is needed
// (each Pool is touched only by its own goroutine).
func Serve(ctx context.Context, cfgs []InterfaceConfig) error {
	if len(cfgs) == 0 {
		return fmt.Errorf("dhcpv4: no interfaces configured")
	}

	type worker struct {
		cfg  InterfaceConfig
		pool *Pool
		conn *packetConn
	}

	var workers []worker
	closeAll := func() {
		for _, w := range workers {
			w.conn.Close()
		}
	}
	for _, cfg := range cfgs {
		pool, err := NewPool(cfg.Subnet, cfg.ServerIP, cfg.LeaseTime)
		if err != nil {
			closeAll()
			return err
		}
		conn, err := listenPacket(cfg.Iface, cfg.ServerIP)
		if err != nil {
			closeAll()
			return err
		}
		workers = append(workers, worker{cfg: cfg, pool: pool, conn: conn})
	}

	var wg sync.WaitGroup
	for _, w := range workers {
		wg.Add(1)
		go func(w worker) {
			defer wg.Done()
			serveOne(w.cfg, w.pool, w.conn)
		}(w)
	}

	<-ctx.Done()
	closeAll() // unblocks every serveOne's recv
	wg.Wait()
	return nil
}

// serveOne is one interface's receive/handle/reply loop, running until its
// socket is closed.
func serveOne(cfg InterfaceConfig, pool *Pool, conn *packetConn) {
	for {
		req, err := conn.recv()
		if err != nil {
			return // socket closed
		}
		reply := handle(cfg, pool, req, time.Now())
		if reply == nil {
			continue
		}
		dstIP, dstMAC := destination(reply)
		if err := conn.send(reply, dstIP, dstMAC); err != nil {
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
