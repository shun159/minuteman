package main

import (
	"context"
	"log"
	"sync"
	"time"

	"github.com/shun159/miniteman/internal/dhcpv6client"
	"github.com/shun159/molecule/application"
	"github.com/shun159/molecule/behaviours/supervisor"
	"github.com/shun159/molecule/proc"
)

// appShutdown bounds how long each application is given to stop, before its
// top is killed and what it drives -- the datapath, its tunnel -- closed
// under it anyway.
const appShutdown = 10 * time.Second

// app is the application of the supervision tree spec, named name.
func app(name string, spec supervisor.Spec) application.App {
	return application.App{Name: name, Start: supervisor.Child(spec), Shutdown: appShutdown}
}

// startApps starts minuteman's applications on node, none yet: run starts
// its supervision trees into them as each is needed (Running.Start), and they
// stop in reverse order. stop stops them, once, whichever of run's defers
// gets there first. If one gives up -- a supervisor past its restart
// intensity -- it fails the whole of minuteman through fail, so that whatever
// restarts minuteman starts it cleanly.
func startApps(ctx context.Context, fail context.CancelCauseFunc, node *proc.Node) (apps *application.Running, stop func(), err error) {
	apps, err = application.Start(ctx, node)
	if err != nil {
		return nil, nil, err
	}
	go func() {
		select {
		case <-apps.Done():
			if err := apps.Err(); err != nil {
				fail(err)
			}
		case <-ctx.Done():
		}
	}()
	stop = sync.OnceFunc(func() {
		if err := apps.Stop(context.Background()); err != nil {
			log.Printf("stopping: %v", err)
		}
	})
	return apps, stop, nil
}

// dhcpv6ClientApp is the application of the DHCPv6 client of wanIface
// (internal/dhcpv6client).
func dhcpv6ClientApp(wanIface string) application.App {
	return app("DHCPv6 client", supervisor.Spec{Children: []supervisor.ChildSpec{
		dhcpv6client.ChildSpec(dhcpv6client.Config{Iface: wanIface}),
	}})
}
