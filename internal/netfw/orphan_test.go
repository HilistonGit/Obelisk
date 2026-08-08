package netfw

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"
)

// scriptRunner answers a fixed script of commands and records what was asked.
type scriptRunner struct {
	mu       sync.Mutex
	rules    string
	linkGone bool
	// linkGoesAfter is how many "ip link show" calls happen before the
	// interface finally disappears, standing in for a tun device the kernel has
	// not finished tearing down.
	linkGoesAfter int
	linkCalls     int
	calls         []string
}

func (r *scriptRunner) Run(_ context.Context, name string, args []string, _ string) (string, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	line := name + " " + strings.Join(args, " ")
	r.calls = append(r.calls, line)

	switch {
	case strings.Contains(line, "link show"):
		r.linkCalls++
		if r.linkGone || r.linkCalls > r.linkGoesAfter {
			return `Device "obelisk0" does not exist.`, fmt.Errorf("exit status 1")
		}
		return "56: obelisk0: <POINTOPOINT,UP> mtu 9000", nil

	case strings.Contains(line, "rule show"):
		if strings.Contains(line, "-6") {
			return "", nil
		}
		return r.rules, nil

	case strings.Contains(line, "rule del"):
		// One rule goes per call; the caller retries until this fails.
		if r.rules == "" {
			return "", fmt.Errorf("no such rule")
		}
		lines := strings.Split(strings.TrimSpace(r.rules), "\n")
		for i, l := range lines {
			if strings.HasPrefix(strings.TrimSpace(l), args[len(args)-1]+":") {
				r.rules = strings.Join(append(lines[:i:i], lines[i+1:]...), "\n")
				return "", nil
			}
		}
		return "", fmt.Errorf("no such rule")
	}
	return "", nil
}

func (r *scriptRunner) ran(substr string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, c := range r.calls {
		if strings.Contains(c, substr) {
			return true
		}
	}
	return false
}

// A live tunnel must never be disturbed, whatever else is going on.
func TestSweepLeavesALiveTunnelAlone(t *testing.T) {
	r := &scriptRunner{
		linkGoesAfter: 1 << 30, // never goes
		rules: `0:	from all lookup local
9000:	from all to 172.19.0.0/30 lookup 2022
9003:	not from all iif lo lookup 2022
32766:	from all lookup main`,
	}
	m := NewWithRunner(DefaultConfig(), r)

	removed, err := m.Sweep(context.Background(), SweepOptions{TUN: "obelisk0", Table: 2022})
	if err != nil {
		t.Fatalf("Sweep: %v", err)
	}
	if removed != 0 {
		t.Errorf("removed %d rules from a tunnel that is up", removed)
	}
	if r.ran("rule del") {
		t.Error("a live tunnel had its routing deleted")
	}
}

// This is the failure that took a router off the internet: the interface is
// gone, the rules that pointed the whole LAN at its table are not.
func TestSweepClearsRoutingLeftByADeadTunnel(t *testing.T) {
	r := &scriptRunner{
		linkGone: true,
		rules: `0:	from all lookup local
9000:	from all to 172.19.0.0/30 lookup 2022
9001:	from all lookup 2022 suppress_prefixlength 0
9003:	not from all iif lo lookup 2022
32766:	from all lookup main`,
	}
	m := NewWithRunner(DefaultConfig(), r)

	removed, err := m.Sweep(context.Background(), SweepOptions{TUN: "obelisk0", Table: 2022})
	if err != nil {
		t.Fatalf("Sweep: %v", err)
	}
	if removed != 3 {
		t.Errorf("removed %d rules, want the 3 in sing-box's range", removed)
	}
	if !r.ran("route flush table 2022") {
		t.Error("the routing table itself was left populated")
	}
	// Everything outside the range belongs to someone else.
	if strings.Contains(r.rules, "9000:") || strings.Contains(r.rules, "9003:") {
		t.Errorf("stale rules survived: %s", r.rules)
	}
	if !strings.Contains(r.rules, "32766:") || !strings.Contains(r.rules, "0:") {
		t.Errorf("rules outside sing-box's range were touched: %s", r.rules)
	}
}

// A rule marked [detached] refers to an interface index the kernel no longer
// has. That is proof the tunnel is gone even while "ip link" still lists it,
// and acting on it is what closes the race at startup.
func TestSweepActsOnADetachedRuleWithoutWaiting(t *testing.T) {
	r := &scriptRunner{
		linkGoesAfter: 1 << 30, // "ip link" keeps insisting the device is there
		rules: `9002:	from all iif obelisk0 [detached] goto 9010
9003:	not from all iif lo lookup 2022
9010:	from all nop`,
	}
	m := NewWithRunner(DefaultConfig(), r)

	start := time.Now()
	removed, err := m.Sweep(context.Background(), SweepOptions{
		TUN: "obelisk0", Table: 2022, Wait: 30 * time.Second,
	})
	if err != nil {
		t.Fatalf("Sweep: %v", err)
	}
	if removed != 3 {
		t.Errorf("removed %d rules, want 3", removed)
	}
	if elapsed := time.Since(start); elapsed > 2*time.Second {
		t.Errorf("waited %v for a tunnel already proved dead", elapsed)
	}
}

// The interface does not vanish the instant the process holding it is killed.
// A sweep that gives up on the first look is the one that left the LAN pointed
// at an empty table after a restart.
func TestSweepWaitsForAnInterfaceOnItsWayOut(t *testing.T) {
	r := &scriptRunner{
		linkGoesAfter: 2,
		rules: `9000:	from all to 172.19.0.0/30 lookup 2022
9003:	not from all iif lo lookup 2022`,
	}
	m := NewWithRunner(DefaultConfig(), r)

	removed, err := m.Sweep(context.Background(), SweepOptions{
		TUN: "obelisk0", Table: 2022, Wait: 5 * time.Second,
	})
	if err != nil {
		t.Fatalf("Sweep: %v", err)
	}
	if removed != 2 {
		t.Errorf("removed %d rules, want 2 once the interface went", removed)
	}
}

// With nothing in range there is nothing to wait for, and a daemon must not
// spend its startup budget confirming that.
func TestSweepReturnsAtOnceWhenThereIsNothingToClean(t *testing.T) {
	r := &scriptRunner{
		linkGoesAfter: 1 << 30,
		rules: `0:	from all lookup local
32766:	from all lookup main`,
	}
	m := NewWithRunner(DefaultConfig(), r)

	start := time.Now()
	removed, err := m.Sweep(context.Background(), SweepOptions{
		TUN: "obelisk0", Table: 2022, Wait: 30 * time.Second,
	})
	if err != nil {
		t.Fatalf("Sweep: %v", err)
	}
	if removed != 0 {
		t.Errorf("removed %d rules from a clean system", removed)
	}
	if elapsed := time.Since(start); elapsed > 2*time.Second {
		t.Errorf("waited %v with nothing to clean up", elapsed)
	}
}
