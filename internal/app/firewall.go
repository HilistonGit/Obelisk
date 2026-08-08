package app

import (
	"context"
	"net"
	"time"

	"github.com/obelisk-project/obelisk/internal/core"
	"github.com/obelisk-project/obelisk/internal/netfw"
)

// netfwMode maps a capture mode onto the firewall rules it needs.
//
// TUN and proxy need none. sing-box's auto_route installs its own routing for
// TUN, and a proxy-only setup captures nothing by definition — in both cases
// adding rules of our own would only create something to fight with.
func netfwMode(mode string) netfw.Mode {
	switch mode {
	case "tproxy":
		return netfw.ModeTProxy
	case "redirect":
		return netfw.ModeRedirect
	default:
		return netfw.ModeNone
	}
}

// firewallConfig builds the rule set for the current settings. The caller holds
// the lock.
//
// It deliberately stops short of the servers' own addresses: finding those means
// DNS, and DNS under the state lock is how a connect froze every reader for as
// long as the network took to answer. The caller adds them with resolveServers.
func (a *App) firewallConfig() netfw.Config {
	fw := a.cfg.Settings.Firewall

	cfg := netfw.DefaultConfig()
	cfg.Mode = netfwMode(a.cfg.Settings.Mode)
	cfg.LANInterfaces = fw.LANInterfaces
	cfg.BlockQUIC = fw.BlockQUIC
	cfg.KillSwitch = fw.KillSwitch
	cfg.Port = a.singboxOptions().TransparentPort
	cfg.DNSPort = a.cfg.Settings.DNS.Listen

	if fw.BypassMark != 0 {
		cfg.BypassMark = fw.BypassMark
	}
	if fw.TProxyMark != 0 {
		cfg.TProxyMark = fw.TProxyMark
	}
	if fw.RouteTable != 0 {
		cfg.RouteTable = fw.RouteTable
	}

	v4, v6 := splitByFamily(fw.Bypass)
	cfg.BypassIPv4 = append(cfg.BypassIPv4, v4...)
	cfg.BypassIPv6 = append(cfg.BypassIPv6, v6...)

	return cfg
}

// resolveServers resolves the plan's servers to addresses for the bypass sets.
//
// The servers themselves must never be captured. The mark the cores set on their
// own sockets already handles this, and this is the belt to that braces: on
// paths where the mark does not survive, an address match still keeps a node's
// own connection out of the tunnel it is building.
//
// Resolution failures are ignored rather than fatal. A name that cannot be
// resolved right now simply does not get an address entry, and the mark-based
// bypass still covers it; refusing to connect over it would be a much worse
// trade.
func resolveServers(ctx context.Context, plan *core.Plan) (v4, v6 []string) {
	if plan == nil {
		return nil, nil
	}

	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	seen := map[string]bool{}
	resolver := net.DefaultResolver

	for _, as := range plan.Assignments {
		if !as.Carried() || as.Node == nil {
			continue
		}
		host := as.Node.Server
		if host == "" || seen[host] {
			continue
		}
		seen[host] = true

		if ip := net.ParseIP(host); ip != nil {
			appendAddress(&v4, &v6, ip)
			continue
		}
		addrs, err := resolver.LookupIPAddr(ctx, host)
		if err != nil {
			continue
		}
		for _, addr := range addrs {
			appendAddress(&v4, &v6, addr.IP)
		}
	}
	return v4, v6
}

func appendAddress(v4, v6 *[]string, ip net.IP) {
	if ip4 := ip.To4(); ip4 != nil {
		*v4 = append(*v4, ip4.String()+"/32")
		return
	}
	*v6 = append(*v6, ip.String()+"/128")
}

// splitByFamily sorts user-supplied bypass entries into the two families.
func splitByFamily(entries []string) (v4, v6 []string) {
	for _, e := range entries {
		if _, network, err := net.ParseCIDR(e); err == nil {
			if network.IP.To4() != nil {
				v4 = append(v4, e)
			} else {
				v6 = append(v6, e)
			}
			continue
		}
		if ip := net.ParseIP(e); ip != nil {
			appendAddress(&v4, &v6, ip)
		}
	}
	return v4, v6
}

// SweepStaleRouting removes policy routing left by a core that did not exit
// cleanly, and reports what it removed.
//
// Called on startup, before anything else. A tunnel that was killed rather than
// stopped leaves ip rules pointing the whole LAN at a routing table with nothing
// in it: every client loses the internet, the router itself keeps working
// because it matches a different rule, and nothing reports an error anywhere.
// Starting up is the one moment when any such remnant is guaranteed to be dead,
// so it is the right place to clear it.
func (a *App) SweepStaleRouting(ctx context.Context) (int, error) {
	a.mu.RLock()
	tun := a.singboxOptions().TUNName
	a.mu.RUnlock()

	manager := netfw.New(netfw.DefaultConfig())
	return manager.Sweep(ctx, netfw.SweepOptions{
		TUN:   tun,
		Table: netfw.SingBoxRouteTable,
		// The interface may still be listed for a moment after the process
		// holding it was killed, and concluding from that that the tunnel is
		// alive is what leaves a router with no internet. The wait costs nothing
		// when there is nothing to clean up, because a sweep with no rules in
		// range returns immediately.
		Wait: 8 * time.Second,
	})
}

// FirewallStatus reports what is installed, and the script that would be.
//
// Returning the rendered rules is deliberate: on a router these are the rules
// standing between a household and the internet, and being able to read them
// without root — or before applying them — is worth more than a status word.
func (a *App) FirewallStatus(ctx context.Context) map[string]any {
	a.mu.RLock()
	cfg := a.firewallConfig()
	installed := a.firewall
	managed := a.cfg.Settings.Firewall.Manage
	a.mu.RUnlock()

	manager := netfw.New(cfg)

	out := map[string]any{
		"mode":    cfg.Mode,
		"managed": managed,
		"script":  manager.Render(),
	}
	if installed != nil {
		out["status"] = installed.Status(ctx)
	} else {
		out["status"] = manager.Status(ctx)
	}
	return out
}
