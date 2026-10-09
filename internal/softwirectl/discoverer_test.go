package softwirectl

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/shun159/molecule"
	"github.com/shun159/molecule/proc"
)

func startDiscoverer(t *testing.T, discover DiscoverFunc) *proc.Node {
	t.Helper()
	node := proc.NewNode("")
	d := discoverer{discover: discover, retryDelay: func(error) time.Duration { return time.Hour }}
	if _, err := node.Start(t.Context(), d.run); err != nil {
		t.Fatal(err)
	}
	return node
}

func TestDiscovererReplies(t *testing.T) {
	node := startDiscoverer(t, func(_ context.Context, token string) (Discovery, error) {
		if token != "tok" {
			return Discovery{}, errors.New("token not echoed")
		}
		return Discovery{AFTR: aftr2}, nil
	})
	v, err := molecule.Call(t.Context(), node, DiscoveryName, discoverReq{Token: "tok"})
	if err != nil {
		t.Fatal(err)
	}
	if rep := v.(discoverRep); rep.Err != nil || rep.Disc.AFTR != aftr2 {
		t.Errorf("reply %+v", rep)
	}
}

// A cancel ends the attempt in flight, whose caller is answered with the
// cancellation and a backoff.
func TestDiscovererCancel(t *testing.T) {
	started := make(chan struct{})
	node := startDiscoverer(t, func(ctx context.Context, _ string) (Discovery, error) {
		close(started)
		<-ctx.Done()
		return Discovery{}, ctx.Err()
	})
	p := molecule.Request[any](node, DiscoveryName, discoverReq{})
	<-started
	molecule.SendCast(node, DiscoveryName, cancelDiscovery{})
	v, err := p.Wait(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if rep := v.(discoverRep); !errors.Is(rep.Err, context.Canceled) || rep.RetryIn != time.Hour {
		t.Errorf("reply %+v", rep)
	}
}
