package app

import (
	"context"
	"fmt"
	"time"

	"github.com/obelisk-project/obelisk/internal/core/singbox"
	"github.com/obelisk-project/obelisk/internal/probe"
)

// startMonitor points the monitor at the running core's control API.
//
// It must be called without the state lock held. Monitor.Stop waits for the
// sampling goroutine to come to a halt, and that goroutine is in App code on its
// way round — so the swap is done under the lock and the stop outside it.
func (a *App) startMonitor(ctx context.Context, opts singbox.Options) {
	if opts.ClashAPIListen == "" {
		return
	}

	monitor := probe.NewMonitor(probe.NewClient(opts.ClashAPIListen, opts.ClashAPISecret))
	monitor.OnSample = a.recordSample
	monitor.OnLatency = a.recordLatency

	a.mu.Lock()
	previous := a.monitor
	a.monitor = monitor
	a.mu.Unlock()

	if previous != nil {
		previous.Stop()
	}
	monitor.Start(ctx)
}

// stopMonitor ends sampling. It must be called without the state lock held, for
// the same reason startMonitor must.
func (a *App) stopMonitor() {
	a.mu.Lock()
	monitor := a.monitor
	a.monitor = nil
	a.mu.Unlock()

	if monitor != nil {
		monitor.Stop()
	}
}

// Traffic returns the current throughput and recent history.
func (a *App) Traffic() probe.Traffic {
	a.mu.RLock()
	monitor := a.monitor
	a.mu.RUnlock()

	if monitor == nil {
		return probe.Traffic{Available: false, Error: "not connected"}
	}
	return monitor.Traffic()
}

// TestNodes measures latency for the given node tags, or for every carried node
// when none are named.
func (a *App) TestNodes(ctx context.Context, tags []string) (map[string]probe.Latency, error) {
	a.mu.RLock()
	monitor := a.monitor
	if len(tags) == 0 && a.plan != nil {
		tags = a.plan.CarriedTags()
	}
	a.mu.RUnlock()

	if monitor == nil {
		return nil, fmt.Errorf("the cores are not running, so there is nothing to measure through")
	}
	if len(tags) == 0 {
		return map[string]probe.Latency{}, nil
	}

	results := monitor.TestAll(ctx, tags, probe.DefaultTestURL, 5*time.Second)
	a.events.publish(Event{Type: "nodes"})
	return results, nil
}

// SelectNode points the proxy group at one node.
//
// Choosing a server is a configuration decision, so it works whether or not the
// cores are running: the choice is stored first, and only pushed to a live core
// when there is one. Requiring the tunnel to be up before a server can be picked
// gets the order backwards — a user reasonably wants to choose where they are
// going before setting off.
//
// An empty tag means automatic, letting the latency test pick.
func (a *App) SelectNode(ctx context.Context, tag string) error {
	a.mu.Lock()
	if tag != "" && !a.carriesTag(tag) {
		a.mu.Unlock()
		return fmt.Errorf("no such server")
	}
	a.cfg.Settings.SelectedNode = tag
	group := a.cfg.Settings.ProxyGroup
	opts := a.singboxOptions()
	running := a.monitor != nil && a.connected
	err := a.save()
	a.mu.Unlock()

	if err != nil {
		return err
	}
	a.events.publish(Event{Type: "nodes"})

	if !running {
		// Nothing to push to. The choice is saved and the next connect applies
		// it, which is what the stored default in the generated config is for.
		return nil
	}
	if group == "" {
		group = "proxy"
	}

	target := tag
	if target == "" {
		target = "auto"
	}

	client := probe.NewClient(opts.ClashAPIListen, opts.ClashAPISecret)
	if err := client.Select(ctx, group, target); err != nil {
		return fmt.Errorf("saved, but the running core did not accept it: %w", err)
	}
	// Existing connections are dropped, or the switch would only apply to ones
	// opened afterwards and a user who changed server because the old one was
	// failing would watch it keep failing.
	if err := client.CloseConnections(ctx); err != nil {
		return fmt.Errorf("server selected, but existing connections could not be dropped: %w", err)
	}
	return nil
}

// carriesTag reports whether the plan actually has this outbound. The caller
// holds the lock.
func (a *App) carriesTag(tag string) bool {
	if a.plan == nil {
		return false
	}
	for _, t := range a.plan.CarriedTags() {
		if t == tag {
			return true
		}
	}
	return false
}

// ActiveNode reports which node the proxy group currently points at.
func (a *App) ActiveNode(ctx context.Context) string {
	a.mu.RLock()
	monitor := a.monitor
	group := a.cfg.Settings.ProxyGroup
	opts := a.singboxOptions()
	a.mu.RUnlock()

	if monitor == nil {
		return ""
	}
	if group == "" {
		group = "proxy"
	}

	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	client := probe.NewClient(opts.ClashAPIListen, opts.ClashAPISecret)
	proxies, err := client.Proxies(ctx)
	if err != nil {
		return ""
	}

	// A selector pointed at "auto" is pointed at a urltest group, whose own
	// "now" is the node actually carrying traffic. Reporting "auto" would tell
	// the user nothing they did not already know.
	current := proxies[group].Now
	for i := 0; i < 4 && current != ""; i++ {
		next, ok := proxies[current]
		if !ok || next.Now == "" {
			break
		}
		current = next.Now
	}
	return current
}

// latencies returns the measurements taken so far. The caller holds the lock.
func (a *App) latencies() map[string]probe.Latency {
	if a.monitor == nil {
		return nil
	}
	return a.monitor.Latencies()
}
