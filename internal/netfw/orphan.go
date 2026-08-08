package netfw

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"time"
)

// TUN routing defaults used by sing-box's auto_route.
//
// When auto_route is on, sing-box installs policy routing of its own: a set of
// ip rules in the 9000s pointing at its own table. These are the values it uses,
// and Obelisk needs to know them for one reason only — to clean them up when
// sing-box does not.
const (
	SingBoxRouteTable = 2022
	singBoxRuleFirst  = 9000
	singBoxRuleLast   = 9010
)

// SweepOptions tunes a sweep.
type SweepOptions struct {
	// TUN is the tunnel interface name, Table the routing table it fed.
	TUN   string
	Table int

	// Wait is how long to give an interface that is on its way out.
	//
	// A tun device does not disappear the moment the process holding it is
	// killed; it goes when the last reference to it is dropped, which can be a
	// short while later. A sweep that runs the instant the daemon starts can
	// therefore find the interface still listed, conclude the tunnel is alive,
	// and leave the LAN pointed at a routing table that is about to be emptied.
	// That race is not theoretical — it is how a restart left a router with no
	// internet after the first version of this sweep was already in place.
	Wait time.Duration
}

// SweepTunRemnants removes policy routing left behind by a tunnel that is gone.
//
// This exists because of the worst failure this product can have. sing-box
// removes its own rules when it shuts down gracefully, but a core that is killed
// — out of memory, a stop that ran past its deadline, a power cut — never gets
// the chance. What is left is a set of ip rules directing the entire LAN into a
// routing table with nothing in it, and no tunnel interface to carry it. Every
// client silently loses the internet, the router itself keeps working because it
// matches a different rule, and nothing anywhere reports an error.
//
// The sweep is deliberately conservative: it only acts once the interface is
// actually gone, so it can never disturb a tunnel that is up.
func (m *Manager) SweepTunRemnants(ctx context.Context, tunName string, table int) (int, error) {
	return m.Sweep(ctx, SweepOptions{TUN: tunName, Table: table})
}

// Sweep is SweepTunRemnants with room to wait for a departing interface.
func (m *Manager) Sweep(ctx context.Context, opts SweepOptions) (int, error) {
	if opts.Table == 0 {
		opts.Table = SingBoxRouteTable
	}
	if m.lookPath != nil {
		if _, err := m.lookPath("ip"); err != nil {
			return 0, nil // nothing to sweep with, and nothing that could have been created
		}
	}

	deadline := time.Now().Add(opts.Wait)
	for {
		gone, prefs := m.tunnelGone(ctx, opts)
		if gone {
			if len(prefs) == 0 {
				return 0, nil
			}
			return m.removeRemnants(ctx, opts, prefs), nil
		}
		// Nothing to clean up is the ordinary case, and it is not worth waiting
		// out a timer to confirm it.
		if len(prefs) == 0 || !time.Now().Before(deadline) {
			return 0, nil
		}
		select {
		case <-ctx.Done():
			return 0, ctx.Err()
		case <-time.After(250 * time.Millisecond):
		}
	}
}

// tunnelGone reports whether the tunnel is really gone, along with the rule
// preferences that are sitting in its range.
//
// Two independent signals say it is gone, and either is enough. The interface
// being absent is the obvious one. The other is a rule that names the interface
// and is marked "[detached]": the kernel prints that when the rule refers to a
// device index that no longer exists, which is proof the tunnel died without
// taking its routing with it — regardless of what "ip link" happens to say in
// the same instant.
func (m *Manager) tunnelGone(ctx context.Context, opts SweepOptions) (bool, []int) {
	rules, err := m.runner.Run(ctx, "ip", []string{"rule", "show"}, "")
	if err != nil {
		return false, nil
	}
	prefs := orphanPrefs(rules, opts.Table)

	if detachedRule(rules, opts.Table) {
		return true, prefs
	}

	out, err := m.runner.Run(ctx, "ip", []string{"link", "show", opts.TUN}, "")
	present := err == nil && !strings.Contains(out, "does not exist")
	return !present, prefs
}

// removeRemnants deletes the rules and empties the table.
func (m *Manager) removeRemnants(ctx context.Context, opts SweepOptions, prefs []int) int {
	removed := 0
	for _, family := range []string{"-4", "-6"} {
		familyPrefs := prefs
		if family == "-6" {
			rules, err := m.runner.Run(ctx, "ip", []string{family, "rule", "show"}, "")
			if err != nil {
				continue
			}
			familyPrefs = orphanPrefs(rules, opts.Table)
		}
		for _, pref := range familyPrefs {
			// Deleting by preference alone removes one rule at a time, and
			// several rules can share a preference, so each is retried until the
			// kernel reports there is nothing left at that number.
			for attempt := 0; attempt < 8; attempt++ {
				if _, err := m.runner.Run(ctx, "ip",
					[]string{family, "rule", "del", "pref", strconv.Itoa(pref)}, ""); err != nil {
					break
				}
				removed++
			}
		}

		// A table that was never created cannot be flushed, which is not a
		// failure worth reporting.
		_, _ = m.runner.Run(ctx, "ip",
			[]string{family, "route", "flush", "table", strconv.Itoa(opts.Table)}, "")
	}
	return removed
}

// detachedRule reports whether any rule in the tunnel's range refers to an
// interface the kernel no longer has.
func detachedRule(rules string, table int) bool {
	for _, line := range strings.Split(rules, "\n") {
		if !strings.Contains(line, "[detached]") {
			continue
		}
		prefText, _, ok := strings.Cut(strings.TrimSpace(line), ":")
		if !ok {
			continue
		}
		pref, err := strconv.Atoi(strings.TrimSpace(prefText))
		if err == nil && pref >= singBoxRuleFirst && pref <= singBoxRuleLast {
			return true
		}
	}
	return false
}

// orphanPrefs finds the rule preferences a departed tunnel left behind.
//
// Only rules in the range sing-box uses, and only those that either name the
// tunnel's routing table or sit in that range at all, are considered. Anything
// a user or another package put there is outside the range and is not touched.
func orphanPrefs(rules string, table int) []int {
	tableRef := "lookup " + strconv.Itoa(table)
	seen := map[int]bool{}
	var out []int

	for _, line := range strings.Split(rules, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		prefText, rest, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		pref, err := strconv.Atoi(strings.TrimSpace(prefText))
		if err != nil || pref < singBoxRuleFirst || pref > singBoxRuleLast {
			continue
		}
		// Inside the range, a rule either points at the tunnel's table or is one
		// of the companions sing-box installs alongside — a detached interface
		// reference, a suppress_prefixlength, a goto. All of them are its doing.
		_ = rest
		if seen[pref] {
			continue
		}
		seen[pref] = true
		out = append(out, pref)
	}
	_ = tableRef
	return out
}

// Describe renders what a sweep would target, for logging.
func (m *Manager) DescribeRemnants(ctx context.Context, tunName string, table int) string {
	if table == 0 {
		table = SingBoxRouteTable
	}
	rules, err := m.runner.Run(ctx, "ip", []string{"rule", "show"}, "")
	if err != nil {
		return ""
	}
	prefs := orphanPrefs(rules, table)
	if len(prefs) == 0 {
		return ""
	}
	return fmt.Sprintf("%d stale routing rule(s) from a previous run of %s", len(prefs), tunName)
}
