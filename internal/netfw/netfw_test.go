package netfw

import (
	"context"
	"strings"
	"testing"
)

// recorder captures the commands that would have been run.
type recorder struct {
	calls  []string
	stdin  []string
	fail   map[string]bool
	output string
}

func (r *recorder) Run(_ context.Context, name string, args []string, stdin string) (string, error) {
	call := name + " " + strings.Join(args, " ")
	r.calls = append(r.calls, call)
	if stdin != "" {
		r.stdin = append(r.stdin, stdin)
	}
	if r.fail[call] {
		return "", context.DeadlineExceeded
	}
	return r.output, nil
}

func (r *recorder) ran(substr string) bool {
	for _, c := range r.calls {
		if strings.Contains(c, substr) {
			return true
		}
	}
	return false
}

func tproxyConfig() Config {
	c := DefaultConfig()
	c.Mode = ModeTProxy
	c.LANInterfaces = []string{"br-lan"}
	c.BypassIPv4 = []string{"203.0.113.10/32"}
	return c
}

func TestRenderNeverFlushesTheRuleset(t *testing.T) {
	// A router runs more than Obelisk. Flushing would take out fw4 and anything
	// else hooked on the same points, which is the fastest way to break a box
	// that is somebody's only route to the internet.
	for _, mode := range []Mode{ModeTProxy, ModeRedirect} {
		cfg := tproxyConfig()
		cfg.Mode = mode
		script := New(cfg).Render()

		if strings.Contains(script, "flush ruleset") {
			t.Errorf("%s: the script flushes the whole ruleset", mode)
		}
		// Deleting our own table by name is fine and is how re-applying works.
		if !strings.Contains(script, "delete table inet obelisk") {
			t.Errorf("%s: the script must replace its own table", mode)
		}
		for _, foreign := range []string{"table inet fw4", "table inet zapret", "table ip nat"} {
			if strings.Contains(script, foreign) {
				t.Errorf("%s: the script references a table it does not own: %s", mode, foreign)
			}
		}
	}
}

func TestRenderBypassesTheCoresOwnTraffic(t *testing.T) {
	// Without this the connection a core opens to a remote server is captured
	// and routed into the tunnel it is trying to establish.
	script := New(tproxyConfig()).Render()
	if !strings.Contains(script, "meta mark 0x4f42 return") {
		t.Error("the bypass mark is not honoured; a core's own traffic would loop")
	}
}

func TestRenderKeepsTheMarksDistinct(t *testing.T) {
	// One mark means "leave this alone", the other "send this to me". Sharing a
	// value would make every captured packet also look like a core's own.
	cfg := tproxyConfig()
	if cfg.BypassMark == cfg.TProxyMark {
		t.Fatal("the bypass and tproxy marks must differ")
	}

	script := New(cfg).Render()
	if !strings.Contains(script, "meta mark set 0x4f43 tproxy to :24011") {
		t.Error("captured traffic is not marked for the policy routing rule")
	}
}

func TestRenderProtectsReservedRanges(t *testing.T) {
	script := New(tproxyConfig()).Render()
	// Capturing the LAN would cut the router off from the devices it serves.
	for _, cidr := range []string{"192.168.0.0/16", "10.0.0.0/8", "127.0.0.0/8", "224.0.0.0/4"} {
		if !strings.Contains(script, cidr) {
			t.Errorf("reserved range %s is not bypassed", cidr)
		}
	}
	// And the configured server address must be there too.
	if !strings.Contains(script, "203.0.113.10/32") {
		t.Error("a configured bypass address did not reach the ruleset")
	}
}

func TestRenderLimitsCaptureToTheLAN(t *testing.T) {
	script := New(tproxyConfig()).Render()
	if !strings.Contains(script, `iifname != { "br-lan" } return`) {
		t.Error("capture is not limited to the configured LAN interfaces")
	}

	// With no interfaces configured the filter must be absent rather than
	// emitted empty, which would match nothing and silently capture everything.
	cfg := tproxyConfig()
	cfg.LANInterfaces = nil
	if strings.Contains(New(cfg).Render(), "iifname !=") {
		t.Error("an empty interface list must not produce an interface filter")
	}
}

func TestRedirectModeCapturesTCPOnly(t *testing.T) {
	cfg := tproxyConfig()
	cfg.Mode = ModeRedirect
	script := New(cfg).Render()

	if !strings.Contains(script, "meta l4proto tcp redirect to :24011") {
		t.Error("TCP is not redirected")
	}
	// REDIRECT cannot capture UDP; pretending otherwise would generate rules
	// that silently do nothing.
	if strings.Contains(script, "meta l4proto udp redirect") {
		t.Error("REDIRECT cannot capture UDP and must not claim to")
	}
	if strings.Contains(script, "tproxy to") {
		t.Error("REDIRECT mode must not emit tproxy rules")
	}
}

func TestQUICBlockIsOptionalAndBypassAware(t *testing.T) {
	cfg := tproxyConfig()
	cfg.Mode = ModeRedirect
	cfg.BlockQUIC = true
	script := New(cfg).Render()

	if !strings.Contains(script, "udp dport { 443, 8443 } reject") {
		t.Error("QUIC is not rejected")
	}
	// Rejecting QUIC to the VPN server itself would break QUIC-based nodes.
	quic := script[strings.Index(script, "chain quic"):]
	if !strings.Contains(quic, "ip daddr @bypass4 return") {
		t.Error("the QUIC block must let bypassed destinations through")
	}

	cfg.BlockQUIC = false
	if strings.Contains(New(cfg).Render(), "chain quic") {
		t.Error("the QUIC block must not appear when it is switched off")
	}
}

func TestNoneModeInstallsNothing(t *testing.T) {
	// TUN needs no rules from us: sing-box installs its own with auto_route and
	// a second set would fight it.
	cfg := DefaultConfig()
	cfg.Mode = ModeNone

	rec := &recorder{}
	m := NewWithRunner(cfg, rec)
	if err := m.Apply(context.Background()); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	for _, call := range rec.calls {
		if strings.Contains(call, "nft -f") {
			t.Errorf("none mode installed rules: %s", call)
		}
	}
}

func TestApplyInstallsPolicyRoutingForTProxy(t *testing.T) {
	rec := &recorder{}
	m := NewWithRunner(tproxyConfig(), rec)

	if err := m.Apply(context.Background()); err != nil {
		t.Fatalf("Apply: %v", err)
	}

	if !rec.ran("nft -f -") {
		t.Error("the ruleset was never handed to nft")
	}
	// TPROXY only delivers to a local socket if the kernel thinks the packet is
	// locally destined, which is what the local default route arranges.
	if !rec.ran("rule add fwmark 0x4f43 lookup 20290") {
		t.Errorf("the policy routing rule was not added: %v", rec.calls)
	}
	if !rec.ran("route replace local default dev lo table 20290") {
		t.Errorf("the local route was not added: %v", rec.calls)
	}
	if len(rec.stdin) != 1 || !strings.Contains(rec.stdin[0], "table inet obelisk") {
		t.Error("the script piped to nft is not the rendered table")
	}
}

func TestApplyRollsBackWhenRoutingFails(t *testing.T) {
	// Rules without the routing that makes them work would black-hole traffic,
	// so a half-applied state must not survive.
	rec := &recorder{fail: map[string]bool{
		"ip -4 rule add fwmark 0x4f43 lookup 20290 pref 9000": true,
	}}
	m := NewWithRunner(tproxyConfig(), rec)

	if err := m.Apply(context.Background()); err == nil {
		t.Fatal("expected Apply to fail when policy routing cannot be installed")
	}
	if !rec.ran("table inet obelisk") {
		t.Error("the nftables table was not torn down after the failure")
	}
}

func TestRemoveIsIdempotent(t *testing.T) {
	rec := &recorder{}
	m := NewWithRunner(tproxyConfig(), rec)

	for i := 0; i < 2; i++ {
		if err := m.Remove(context.Background()); err != nil {
			t.Fatalf("Remove (pass %d): %v", i+1, err)
		}
	}
	if !rec.ran("destroy table inet obelisk") && !rec.ran("delete table inet obelisk") {
		t.Error("Remove never asked nft to drop the table")
	}
}

func TestKillSwitchDropsOnlyUncapturedLANTraffic(t *testing.T) {
	cfg := tproxyConfig()
	cfg.KillSwitch = true
	script := New(cfg).Render()

	idx := strings.Index(script, "chain killswitch")
	if idx < 0 {
		t.Fatal("the kill switch chain is missing")
	}
	chain := script[idx:]

	// It must sit after anything else on the forward hook, so it only sees what
	// nothing else claimed.
	if !strings.Contains(chain, "priority filter + 10") {
		t.Error("the kill switch must run after the other forward chains")
	}
	// Dropping bypassed destinations would cut off the LAN and the servers.
	if !strings.Contains(chain, "ip daddr @bypass4 return") {
		t.Error("the kill switch must let bypassed destinations through")
	}
	if !strings.Contains(chain, `iifname != { "br-lan" } return`) {
		t.Error("the kill switch must only apply to LAN traffic")
	}
	if !strings.Contains(chain, "drop") {
		t.Error("the kill switch does not drop anything")
	}

	cfg.KillSwitch = false
	if strings.Contains(New(cfg).Render(), "chain killswitch") {
		t.Error("the kill switch must not appear when it is switched off")
	}
}

func TestKillSwitchIsAbsentWhenNothingIsCaptured(t *testing.T) {
	// In TUN mode sing-box owns the routing; dropping forwarded traffic here
	// would break a tunnel we are not the ones capturing for.
	cfg := DefaultConfig()
	cfg.Mode = ModeNone
	cfg.KillSwitch = true
	if strings.Contains(New(cfg).Render(), "chain killswitch") {
		t.Error("no capture mode means no kill switch")
	}
}

func TestRenderIsDeterministic(t *testing.T) {
	// The runtime decides whether to re-apply by comparing output, so identical
	// input has to produce identical bytes.
	m := New(tproxyConfig())
	if m.Render() != m.Render() {
		t.Error("Render is not deterministic")
	}
}
