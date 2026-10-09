package main

import (
	"context"
	"fmt"
	"log"
	"sync"
	"time"

	"github.com/shun159/miniteman/internal/dhcpv6client"
	"github.com/shun159/miniteman/pkg/dhcpv6"
	"github.com/shun159/molecule/behaviours/supervisor"
	"github.com/shun159/molecule/proc"
)

// treeStopTimeout bounds how long shutdown waits for a supervision tree to
// stop, before what it drives (the datapath, its tunnel) is closed under it
// anyway.
const treeStopTimeout = 10 * time.Second

// superviseTree starts the supervision tree spec on node, and ties it to run's
// lifetime: registered on wg, it stops the tree when ctx is done -- before
// run's deferred closes of what the tree drives -- and if the tree gives up on
// its own, a child restarting past its supervisor's intensity, it fails the
// whole of minuteman through fail, so that whatever restarts minuteman starts
// it cleanly. what names the tree in errors and logs; after, if not nil, runs
// once the tree is down.
func superviseTree(ctx context.Context, fail context.CancelCauseFunc, node *proc.Node, what string, spec supervisor.Spec, wg *sync.WaitGroup, after func()) error {
	if after == nil {
		after = func() {}
	}
	sup, err := supervisor.Start(ctx, node, spec)
	if err != nil {
		after()
		return fmt.Errorf("starting %s: %w", what, err)
	}

	wg.Add(1)
	go func() {
		defer wg.Done()
		defer after()
		down, cancel := node.Watch(context.Background(), sup)
		defer cancel()
		select {
		case <-ctx.Done():
			stopCtx, cancel := context.WithTimeout(context.Background(), treeStopTimeout)
			defer cancel()
			if err := supervisor.Stop(stopCtx, node, sup); err != nil {
				log.Printf("stopping %s: %v", what, err)
			}
		case <-down.Done():
			fail(fmt.Errorf("%s gave up: %w", what, context.Cause(down)))
		}
	}()
	return nil
}

// startDHCPv6Client starts the DHCPv6 client of wanIface
// (internal/dhcpv6client) on node, and returns it with the function stopping
// it. The client is not tied to run's ctx, as the other trees are: its users
// -- the DHCPv6-PD maintenance releasing its lease, AFTR re-discovery --
// stop on that ctx, and may still exchange while they do, so the caller
// stops the client once they have. If it gives up on its own, it fails
// minuteman through fail, as superviseTree's trees do.
func startDHCPv6Client(fail context.CancelCauseFunc, node *proc.Node, wanIface string) (dhcpv6.Exchanger, func(), error) {
	ctx, cancel := context.WithCancel(context.Background())
	var wg sync.WaitGroup
	spec := supervisor.Spec{Children: []supervisor.ChildSpec{dhcpv6client.ChildSpec(dhcpv6client.Config{Iface: wanIface})}}
	if err := superviseTree(ctx, fail, node, "DHCPv6 client", spec, &wg, nil); err != nil {
		cancel()
		return nil, nil, err
	}
	stop := func() {
		cancel()
		wg.Wait()
	}
	return dhcpv6client.NewClient(node, wanIface), stop, nil
}
