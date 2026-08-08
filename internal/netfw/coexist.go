package netfw

import (
	"context"
	"fmt"
	"strconv"
	"strings"
)

// ZapretExemptBit is the mark bit zapret uses to recognize traffic it has
// already handled, and therefore must not handle again.
//
// Its rules are gated on it from the outside:
//
//	chain postnat_hook { meta mark & 0x40000000 == 0 jump postnat }
//
// so anything carrying the bit is passed over. Obelisk borrows that to keep the
// cores' own connections away from the DPI desynchroniser — see WantsZapretExempt
// for why it has to.
const ZapretExemptBit = 0x40000000

// DetectZapret reports whether zapret is active on this system.
//
// It looks for zapret's own nftables table rather than for its process, because
// the table is what actually intercepts traffic: a stopped daemon with rules
// still loaded queues packets to a queue nobody is reading, and a running daemon
// with no rules does nothing at all.
func DetectZapret(ctx context.Context) bool {
	m := New(DefaultConfig())
	out, err := m.runner.Run(ctx, "nft", []string{"list", "tables"}, "")
	if err != nil {
		return false
	}
	return detectZapretIn(out)
}

// detectZapretIn is the pure half of the detection, so a table listing can be
// asserted against without a kernel.
//
// The names are matched exactly rather than by substring: a table called
// "zapretx" belongs to somebody else, and silently exempting Obelisk's traffic
// from a firewall it has not actually identified would be a change nobody asked
// for.
func detectZapretIn(tables string) bool {
	for _, line := range strings.Split(tables, "\n") {
		switch strings.TrimSpace(line) {
		case "table inet zapret", "table ip zapret", "table ip6 zapret":
			return true
		}
	}
	return false
}

// WithZapretExempt returns the mark a core should stamp on its own sockets so
// that zapret leaves them alone.
//
// This is not a theoretical precaution. Measured on a live router, with the
// tunnel up and zapret running, a 10 MB download stopped after 21 kB and
// trickled at 844 B/s. With either one alone the same transfer completed at
// 8-9 MB/s, and with the tunnel up and zapret stopped it was the fastest of the
// three. The two are individually fine and destroy each other in combination.
//
// The mechanism: in TUN mode every connection the LAN makes is terminated by the
// front core, which then opens its own connection out of the WAN. zapret sees
// that connection, matches its hostlist against the same SNI, and applies
// dpi-desync — injecting fake segments into a stream produced by a userspace TCP
// stack rather than the kernel's. Transfers to hosts on zapret's list break;
// transfers to hosts that are not on it are untouched, which is why the failure
// looks like "some sites load partially" rather than like a broken network.
//
// The cost of the exemption is real and worth stating plainly: traffic the
// tunnel routes *direct* no longer gets zapret's DPI bypass. On a router running
// both, the answer for a blocked destination is to route it through the VPN
// rather than to desynchronise it — which is what the VPN was installed for.
func WithZapretExempt(mark int) int { return mark | ZapretExemptBit }

// HasZapretExempt reports whether a mark already carries the exemption bit.
func HasZapretExempt(mark int) bool { return mark&ZapretExemptBit != 0 }

// ZapretRoutePref is where the exemption routing rule sits.
//
// It has to be above sing-box's own rules, which start at 9000: those send
// everything that is not already handled into the tunnel's table, and the whole
// point here is to be consulted first.
const ZapretRoutePref = 8900

// InstallZapretRoute sends packets carrying zapret's own mark out through the
// ordinary routing table instead of the tunnel.
//
// The desynchroniser works by injecting extra packets — a fake segment the DPI
// will act on and the real server will discard. Those packets are generated
// locally, on a raw socket, and a tunnel with auto_route captures exactly that:
// its rule "from 0.0.0.0 iif lo lookup <tunnel table>" is written to catch
// locally-originated traffic before a source address has been chosen. So the
// fakes go into the tunnel instead of to the provider, the DPI never sees them,
// and the bypass silently stops working — while the real connection, now
// half-desynchronised, stalls.
//
// zapret stamps everything it generates with --dpi-desync-fwmark, and this rule
// is that mark's way out. It is a routing rule, not a firewall rule: nothing of
// zapret's is modified, and removing it puts the system back exactly as it was.
func (m *Manager) InstallZapretRoute(ctx context.Context, mark int) error {
	if mark == 0 {
		mark = ZapretExemptBit
	}
	_ = m.RemoveZapretRoute(ctx, mark)

	_, err := m.runner.Run(ctx, "ip", []string{
		"rule", "add", "pref", strconv.Itoa(ZapretRoutePref),
		"fwmark", fmt.Sprintf("%#x/%#x", mark, mark),
		"lookup", "main",
	}, "")
	return err
}

// RemoveZapretRoute takes the rule back out. Missing is success: this runs on
// every teardown, including ones where it was never installed.
func (m *Manager) RemoveZapretRoute(ctx context.Context, mark int) error {
	if mark == 0 {
		mark = ZapretExemptBit
	}
	for attempt := 0; attempt < 4; attempt++ {
		if _, err := m.runner.Run(ctx, "ip", []string{
			"rule", "del", "pref", strconv.Itoa(ZapretRoutePref),
			"fwmark", fmt.Sprintf("%#x/%#x", mark, mark),
			"lookup", "main",
		}, ""); err != nil {
			return nil
		}
	}
	return nil
}
