package ndproxy

import (
	"net/netip"
	"testing"
	"time"
)

var (
	target1 = netip.MustParseAddr("2001:db8::1")
	asker1  = netip.MustParseAddr("2001:db8::a")
	asker2  = netip.MustParseAddr("2001:db8::b")
)

func TestOnWANSolicitUnknownTargetTriggersProbe(t *testing.T) {
	s := newProxyState()
	t0 := time.Now()

	reply, probe := s.onWANSolicit(t0, target1, asker1)
	if reply != nil {
		t.Fatalf("reply = %+v, want nil", reply)
	}
	if !probe {
		t.Fatal("probe = false, want true for an unknown target")
	}
	if _, ok := s.pending[target1]; !ok {
		t.Fatal("target1 not recorded in pending")
	}
}

func TestOnWANSolicitDuplicateDoesNotReprobe(t *testing.T) {
	s := newProxyState()
	t0 := time.Now()

	if _, probe := s.onWANSolicit(t0, target1, asker1); !probe {
		t.Fatal("first onWANSolicit: probe = false, want true")
	}
	reply, probe := s.onWANSolicit(t0.Add(100*time.Millisecond), target1, asker2)
	if probe {
		t.Fatal("second onWANSolicit for the same pending target: probe = true, want false")
	}
	if reply != nil {
		t.Fatalf("second onWANSolicit: reply = %+v, want nil (still pending, not active)", reply)
	}

	// The second (most recent) solicitor is the one that gets answered.
	adReply, ok := s.onLANAdvert(t0.Add(200*time.Millisecond), "lan0", target1)
	if !ok {
		t.Fatal("onLANAdvert: ok = false, want true")
	}
	if adReply.Solicitor != asker2 {
		t.Fatalf("reply.Solicitor = %v, want the most recent asker %v", adReply.Solicitor, asker2)
	}
}

func TestOnLANAdvertResolvesPendingProbeAndBecomesActive(t *testing.T) {
	s := newProxyState()
	t0 := time.Now()

	s.onWANSolicit(t0, target1, asker1)
	reply, ok := s.onLANAdvert(t0.Add(50*time.Millisecond), "lan0", target1)
	if !ok {
		t.Fatal("onLANAdvert: ok = false, want true")
	}
	if reply.Target != target1 || reply.Solicitor != asker1 || reply.Iface != "lan0" {
		t.Fatalf("reply = %+v, want {%v %v lan0}", reply, target1, asker1)
	}
	if _, stillPending := s.pending[target1]; stillPending {
		t.Fatal("target1 still in pending after being resolved")
	}
	if a, active := s.active[target1]; !active || a.iface != "lan0" {
		t.Fatalf("active[target1] = %+v, active = %v, want iface lan0", a, active)
	}
}

func TestOnLANAdvertUnmatchedIsIgnored(t *testing.T) {
	s := newProxyState()
	reply, ok := s.onLANAdvert(time.Now(), "lan0", target1)
	if ok || reply != nil {
		t.Fatalf("onLANAdvert with no pending probe: ok = %v, reply = %+v, want false/nil", ok, reply)
	}
}

func TestOnWANSolicitActiveFastPath(t *testing.T) {
	s := newProxyState()
	t0 := time.Now()

	s.onWANSolicit(t0, target1, asker1)
	s.onLANAdvert(t0.Add(50*time.Millisecond), "lan0", target1)

	reply, probe := s.onWANSolicit(t0.Add(time.Second), target1, asker2)
	if probe {
		t.Fatal("onWANSolicit for a fresh active target: probe = true, want false")
	}
	if reply == nil || reply.Iface != "lan0" || reply.Solicitor != asker2 {
		t.Fatalf("reply = %+v, want immediate reply via lan0 to %v", reply, asker2)
	}
}

func TestActiveEntryExpiryForcesReprobe(t *testing.T) {
	s := newProxyState()
	t0 := time.Now()

	s.onWANSolicit(t0, target1, asker1)
	s.onLANAdvert(t0.Add(50*time.Millisecond), "lan0", target1)

	reply, probe := s.onWANSolicit(t0.Add(activeTTL+time.Second), target1, asker2)
	if reply != nil {
		t.Fatalf("reply = %+v, want nil once the active entry has expired", reply)
	}
	if !probe {
		t.Fatal("probe = false, want true once the active entry has expired")
	}
}

func TestSweepRetransmitsPendingProbe(t *testing.T) {
	s := newProxyState()
	t0 := time.Now()
	s.onWANSolicit(t0, target1, asker1)

	// Before the retransmit timer fires, nothing to do.
	retransmit, gaveUp, expired := s.sweep(t0.Add(500 * time.Millisecond))
	if len(retransmit) != 0 || len(gaveUp) != 0 || len(expired) != 0 {
		t.Fatalf("sweep before RetransTimer: retransmit = %v, gaveUp = %v, expired = %v, want all empty", retransmit, gaveUp, expired)
	}

	retransmit, gaveUp, _ = s.sweep(t0.Add(probeRetransTimer))
	if len(gaveUp) != 0 {
		t.Fatalf("gaveUp = %v, want empty (only 1 attempt so far)", gaveUp)
	}
	if len(retransmit) != 1 || retransmit[0] != target1 {
		t.Fatalf("retransmit = %v, want [%v]", retransmit, target1)
	}
	if s.pending[target1].attempts != 2 {
		t.Fatalf("attempts = %d, want 2", s.pending[target1].attempts)
	}
}

func TestSweepGivesUpAfterMaxAttempts(t *testing.T) {
	s := newProxyState()
	t0 := time.Now()
	s.onWANSolicit(t0, target1, asker1) // attempt 1

	now := t0
	for i := range maxMulticastSolicit - 1 {
		now = now.Add(probeRetransTimer)
		retransmit, gaveUp, _ := s.sweep(now)
		if len(gaveUp) != 0 {
			t.Fatalf("sweep #%d: gaveUp = %v, want empty", i, gaveUp)
		}
		if len(retransmit) != 1 {
			t.Fatalf("sweep #%d: retransmit = %v, want [%v]", i, retransmit, target1)
		}
	}

	// One more RetransTimer after the last attempt: budget exhausted.
	now = now.Add(probeRetransTimer)
	retransmit, gaveUp, _ := s.sweep(now)
	if len(retransmit) != 0 {
		t.Fatalf("final sweep: retransmit = %v, want empty", retransmit)
	}
	if len(gaveUp) != 1 || gaveUp[0] != target1 {
		t.Fatalf("final sweep: gaveUp = %v, want [%v]", gaveUp, target1)
	}
	if _, ok := s.pending[target1]; ok {
		t.Fatal("target1 still in pending after giving up")
	}
}

func TestSweepExpiresActiveEntries(t *testing.T) {
	s := newProxyState()
	t0 := time.Now()
	s.onWANSolicit(t0, target1, asker1)
	s.onLANAdvert(t0.Add(50*time.Millisecond), "lan0", target1)

	_, _, expired := s.sweep(t0.Add(activeTTL + time.Second))
	if _, ok := s.active[target1]; ok {
		t.Fatal("target1 still active after sweep past activeTTL")
	}
	if len(expired) != 1 || expired[0].Target != target1 || expired[0].Iface != "lan0" {
		t.Fatalf("expired = %+v, want [{%v lan0}]", expired, target1)
	}
}
