package main

import (
	"context"
	"fmt"
	"log"
	"sync"
	"time"

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
