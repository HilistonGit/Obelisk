// Package netfw applies the firewall and policy-routing rules that the TPROXY
// and REDIRECT capture modes need.
//
// Two commitments shape everything here, and both come from the fact that a
// router is rarely running only one thing.
//
// Obelisk owns exactly one nftables table and never touches another. No
// "flush ruleset", no edits to fw4, no assumptions about what else is hooked
// where. A DPI-circumvention tool, a package manager's firewall and Obelisk can
// all keep chains on the same hooks; nftables evaluates them by priority and
// they coexist. Flushing on startup would be the fastest possible way to break
// somebody's router.
//
// And everything is expressed as a script that can be rendered without applying
// it. Render is what the tests exercise and what "obelisk firewall show" prints,
// so the rules can be reviewed before they are ever installed on the machine
// that is somebody's only way onto the internet.
package netfw

import (
	"context"
	"fmt"
	"os/exec"
	"strings"
	"time"
)

// Mode selects which capture the rules implement.
type Mode string

const (
	// ModeTProxy captures TCP and UDP with mark-based policy routing.
	ModeTProxy Mode = "tproxy"
	// ModeRedirect captures TCP only, through destination NAT.
	ModeRedirect Mode = "redirect"
	// ModeNone installs nothing. TUN needs no rules from us: sing-box installs
	// its own with auto_route, and a second set would fight it.
	ModeNone Mode = "none"
)

// Default identifiers. The mark and table are settable because a router may
// already have something using them; the zapret family, for one, marks packets
// with 0x40000000 and 0x20000000.
const (
	DefaultTable      = "obelisk"
	DefaultBypassMark = 0x4f42 // "OB" — set by the cores on their own sockets
	DefaultTProxyMark = 0x4f43 // set by us, matched by the policy routing rule
	DefaultRouteTable = 0x4f42
)

// Config describes the rules to install.
type Config struct {
	Mode  Mode
	Table string

	// BypassMark is stamped by the cores on their own outbound sockets. Traffic
	// carrying it is never captured, which is what stops a core's connection to
	// a remote server from being routed into the tunnel it is establishing.
	BypassMark int

	// TProxyMark is applied by these rules and matched by the policy routing
	// rule that diverts packets to the local table. It must differ from
	// BypassMark: one means "leave this alone", the other "send this to me".
	TProxyMark int

	// RouteTable is the routing table holding the local default route.
	RouteTable int

	// Port is where the front core listens for captured traffic.
	Port int

	// DNSPort, when set, captures DNS separately so the core's resolver answers
	// it even if the client was pointed somewhere else.
	DNSPort int

	// LANInterfaces limits capture to traffic arriving on these interfaces.
	// Empty captures from every interface, which is rarely what a router wants.
	LANInterfaces []string

	// BypassIPv4 and BypassIPv6 are destinations that must never be captured:
	// the VPN servers themselves, plus whatever the user excluded.
	BypassIPv4 []string
	BypassIPv6 []string

	// EnableIPv6 installs the v6 half of the rules.
	EnableIPv6 bool

	// BlockQUIC rejects UDP/443 so that browsers fall back to TCP. In REDIRECT
	// mode this is the difference between QUIC being proxied and QUIC quietly
	// escaping the tunnel entirely, because REDIRECT cannot capture UDP.
	BlockQUIC bool

	// KillSwitch drops LAN traffic that reached the forwarding path without
	// being captured.
	//
	// In both capture modes a captured packet is consumed before forwarding, so
	// anything from the LAN arriving there is by definition traffic the tunnel
	// did not take — a protocol the mode cannot handle, or a gap while the cores
	// are down. Failing closed turns a silent leak into an obvious outage, which
	// is the correct trade for a privacy tool: a user notices no internet, and
	// never notices traffic quietly going out in the clear.
	KillSwitch bool
}

// DefaultConfig returns the settings Obelisk installs out of the box.
func DefaultConfig() Config {
	return Config{
		Mode:       ModeNone,
		Table:      DefaultTable,
		BypassMark: DefaultBypassMark,
		TProxyMark: DefaultTProxyMark,
		RouteTable: DefaultRouteTable,
		Port:       24011,
		DNSPort:    24053,
		EnableIPv6: true,
		BlockQUIC:  false,
	}
}

func (c *Config) applyDefaults() {
	if c.Table == "" {
		c.Table = DefaultTable
	}
	if c.BypassMark == 0 {
		c.BypassMark = DefaultBypassMark
	}
	if c.TProxyMark == 0 {
		c.TProxyMark = DefaultTProxyMark
	}
	if c.RouteTable == 0 {
		c.RouteTable = DefaultRouteTable
	}
}

// Runner executes the system commands. It is an interface so that the rules can
// be tested, and dry-run inspected, without root or a kernel.
type Runner interface {
	Run(ctx context.Context, name string, args []string, stdin string) (string, error)
}

// execRunner runs commands for real.
type execRunner struct{}

func (execRunner) Run(ctx context.Context, name string, args []string, stdin string) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, name, args...)
	if stdin != "" {
		cmd.Stdin = strings.NewReader(stdin)
	}
	out, err := cmd.CombinedOutput()
	if err != nil {
		return string(out), fmt.Errorf("%s %s: %w: %s",
			name, strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
	return string(out), nil
}

// Manager installs and removes the rules.
type Manager struct {
	cfg    Config
	runner Runner

	// lookPath resolves an external tool. It is a field rather than a direct
	// call to exec.LookPath so that the apply path stays testable on a machine
	// that has neither nftables nor a Linux kernel.
	lookPath func(string) (string, error)

	applied bool
}

// New creates a manager.
func New(cfg Config) *Manager {
	cfg.applyDefaults()
	return &Manager{cfg: cfg, runner: execRunner{}, lookPath: exec.LookPath}
}

// NewWithRunner creates a manager driving a supplied Runner, for tests. Tool
// availability is assumed, since the Runner stands in for the tools.
func NewWithRunner(cfg Config, r Runner) *Manager {
	cfg.applyDefaults()
	return &Manager{
		cfg:      cfg,
		runner:   r,
		lookPath: func(name string) (string, error) { return name, nil },
	}
}

// Config returns the active configuration.
func (m *Manager) Config() Config { return m.cfg }

// Available reports whether the tools these rules need are installed.
//
// It is checked before anything is applied, because failing halfway through
// leaves a router in a state nobody asked for: some rules in, some not, and
// traffic going somewhere unexpected.
func (m *Manager) Available(ctx context.Context) error {
	if m.cfg.Mode == ModeNone {
		return nil
	}
	for _, tool := range []string{"nft", "ip"} {
		if _, err := m.lookPath(tool); err != nil {
			return fmt.Errorf("netfw: %s is not installed; %s mode needs it", tool, m.cfg.Mode)
		}
	}
	return nil
}

// Apply installs the rules, replacing any previous Obelisk table.
func (m *Manager) Apply(ctx context.Context) error {
	if m.cfg.Mode == ModeNone {
		return m.Remove(ctx)
	}
	if err := m.Available(ctx); err != nil {
		return err
	}

	// The table is deleted and rebuilt rather than edited: it makes applying a
	// changed configuration identical to applying a fresh one, and there is no
	// half-updated state to reason about. Only our own table is touched.
	script := m.Render()
	if _, err := m.runner.Run(ctx, "nft", []string{"-f", "-"}, script); err != nil {
		return fmt.Errorf("netfw: installing rules: %w", err)
	}

	if m.cfg.Mode == ModeTProxy {
		if err := m.applyPolicyRouting(ctx); err != nil {
			// Leaving the nftables rules in place without the routing that makes
			// them work would black-hole traffic, so undo them.
			_ = m.Remove(ctx)
			return err
		}
	}

	m.applied = true
	return nil
}

// Remove takes the rules back out. It is safe to call when nothing is installed.
func (m *Manager) Remove(ctx context.Context) error {
	var firstErr error

	// "destroy" removes the table if present and says nothing if it is not,
	// which is exactly the idempotence a teardown path wants.
	for _, family := range []string{"inet"} {
		if _, err := m.runner.Run(ctx, "nft",
			[]string{"destroy", "table", family, m.cfg.Table}, ""); err != nil && firstErr == nil {
			// Older nft has no "destroy"; fall back to delete and ignore a
			// missing table.
			if _, delErr := m.runner.Run(ctx, "nft",
				[]string{"delete", "table", family, m.cfg.Table}, ""); delErr != nil {
				_ = delErr // a table that was never created is not an error
			}
		}
	}

	if err := m.removePolicyRouting(ctx); err != nil && firstErr == nil {
		firstErr = err
	}

	m.applied = false
	return firstErr
}

// applyPolicyRouting installs the rule and route that make TPROXY work.
//
// TPROXY hands a packet to a local socket while leaving its destination address
// untouched, and the kernel will only do that for packets it considers locally
// destined. The "local default" route in a dedicated table is what makes it
// think so, and the fwmark rule is what sends marked packets to that table.
func (m *Manager) applyPolicyRouting(ctx context.Context) error {
	families := []string{"-4"}
	if m.cfg.EnableIPv6 {
		families = append(families, "-6")
	}

	for _, family := range families {
		// Remove first so that re-applying does not stack duplicate rules.
		_, _ = m.runner.Run(ctx, "ip", []string{family, "rule", "del", "fwmark",
			hex(m.cfg.TProxyMark), "lookup", itoa(m.cfg.RouteTable)}, "")

		if _, err := m.runner.Run(ctx, "ip", []string{family, "rule", "add", "fwmark",
			hex(m.cfg.TProxyMark), "lookup", itoa(m.cfg.RouteTable), "pref", "9000"}, ""); err != nil {
			return fmt.Errorf("netfw: adding the policy routing rule: %w", err)
		}

		dst := "local"
		route := []string{family, "route", "replace", dst, "default", "dev", "lo", "table", itoa(m.cfg.RouteTable)}
		if _, err := m.runner.Run(ctx, "ip", route, ""); err != nil {
			return fmt.Errorf("netfw: adding the local route: %w", err)
		}
	}
	return nil
}

// removePolicyRouting undoes applyPolicyRouting.
func (m *Manager) removePolicyRouting(ctx context.Context) error {
	families := []string{"-4"}
	if m.cfg.EnableIPv6 {
		families = append(families, "-6")
	}
	for _, family := range families {
		_, _ = m.runner.Run(ctx, "ip", []string{family, "rule", "del", "fwmark",
			hex(m.cfg.TProxyMark), "lookup", itoa(m.cfg.RouteTable)}, "")
		_, _ = m.runner.Run(ctx, "ip", []string{family, "route", "flush", "table", itoa(m.cfg.RouteTable)}, "")
	}
	return nil
}

// Status describes what is currently installed.
type Status struct {
	Mode      Mode   `json:"mode"`
	Applied   bool   `json:"applied"`
	Table     string `json:"table"`
	TableLive bool   `json:"table_live"`
	Detail    string `json:"detail,omitempty"`
}

// Status inspects the live ruleset rather than trusting what we believe we did.
func (m *Manager) Status(ctx context.Context) Status {
	st := Status{Mode: m.cfg.Mode, Applied: m.applied, Table: m.cfg.Table}
	if m.cfg.Mode == ModeNone {
		st.Detail = "no rules needed in this mode"
		return st
	}

	out, err := m.runner.Run(ctx, "nft", []string{"list", "table", "inet", m.cfg.Table}, "")
	if err != nil {
		st.Detail = "table is not installed"
		return st
	}
	st.TableLive = strings.Contains(out, "table inet "+m.cfg.Table)
	return st
}
