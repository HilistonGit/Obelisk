// Package config holds Obelisk's persistent state: the subscriptions to follow,
// the routing rules to apply, and the settings that shape both.
//
// It is a JSON file rather than a database, deliberately. This state is small,
// changes rarely, and is exactly what a user wants to read, back up, diff and
// restore by hand when something goes wrong on a router they cannot easily get a
// screen onto. Traffic statistics and latency history are a different problem —
// they are large, append-heavy and nobody edits them — and those will live in
// SQLite when they arrive.
package config

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/obelisk-project/obelisk/internal/model"
	"github.com/obelisk-project/obelisk/internal/routing"
)

// CurrentVersion is the schema version written by this build. It exists so that
// a future change can migrate an old file instead of misreading it.
const CurrentVersion = 2

// Config is the whole of Obelisk's persistent state.
type Config struct {
	Version       int             `json:"version"`
	Subscriptions []Subscription  `json:"subscriptions"`
	Rules         []routing.Entry `json:"rules"`
	Settings      Settings        `json:"settings"`
}

// Subscription is one source of nodes.
type Subscription struct {
	ID      string `json:"id"`
	Name    string `json:"name"`
	URL     string `json:"url"`
	Enabled bool   `json:"enabled"`

	// UserAgent overrides the default. Panels serve different payload formats
	// to different clients, so this is occasionally the only way to get a usable
	// node list out of one.
	UserAgent string `json:"user_agent,omitempty"`

	// ImportRules takes the routing decisions the subscription ships alongside
	// its servers. They are applied beneath the user's own rules, so importing
	// them can never override something the user set, and they are discarded
	// when the subscription is removed.
	ImportRules bool `json:"import_rules"`

	UpdateInterval Duration  `json:"update_interval,omitempty"`
	LastUpdate     time.Time `json:"last_update,omitempty"`
	LastError      string    `json:"last_error,omitempty"`
	NodeCount      int       `json:"node_count,omitempty"`

	// Format is what the payload turned out to be, recorded so the interface can
	// explain why a subscription contributes no routing rules: a list of share
	// links has nowhere to put them, while a sing-box or Clash document does.
	Format string `json:"format,omitempty"`

	// RuleCount is how many routing rules were imported from it.
	RuleCount int `json:"rule_count,omitempty"`

	// ETag and LastModified let a refresh end in a 304 instead of a re-parse.
	ETag         string `json:"etag,omitempty"`
	LastModified string `json:"last_modified,omitempty"`
}

// SplitMode is how the routing rules are meant to be read.
//
// It exists because the question a user actually has is "what goes through the
// VPN", and the honest answer is one of three shapes. Expressing it as a
// fallback action instead — the previous design — asked them to work backwards
// from the leftovers to the intent, which is the wrong way round and produces a
// setting that is easy to leave in a state where the tunnel does nothing at all.
type SplitMode string

const (
	// SplitProxyList sends only what the rules name into the tunnel; the rest
	// goes out the ordinary way.
	SplitProxyList SplitMode = "proxy-list"

	// SplitBypassList sends everything into the tunnel except what the rules
	// name. This is the mode a provider's own routing is written for: those
	// lists say what should stay outside, and they mean nothing unless the
	// default is to go in.
	SplitBypassList SplitMode = "bypass-list"

	// SplitOff sends everything into the tunnel and consults no rules at all,
	// the user's or the provider's.
	SplitOff SplitMode = "off"
)

// Fallback is where traffic goes when no rule matched it.
func (m SplitMode) Fallback() routing.Action {
	if m == SplitProxyList {
		return routing.ActionDirect
	}
	return routing.ActionProxy
}

// UsesRules reports whether the rule lists are consulted at all.
func (m SplitMode) UsesRules() bool { return m != SplitOff }

// AddAction is what a newly added entry should do in this mode. It is the
// opposite of the fallback, because an entry that agrees with the fallback is
// the one thing that cannot change any outcome.
func (m SplitMode) AddAction() routing.Action {
	if m.Fallback() == routing.ActionProxy {
		return routing.ActionDirect
	}
	return routing.ActionProxy
}

// Valid reports whether m is one of the three modes.
func (m SplitMode) Valid() bool {
	switch m {
	case SplitProxyList, SplitBypassList, SplitOff:
		return true
	}
	return false
}

// ZapretMode is how Obelisk shares a router with a DPI desynchroniser.
//
// The two tools overlap by construction. In TUN mode every connection the LAN
// makes is terminated by the core and re-opened from the router, so what zapret
// sees is no longer the client's connection but the core's — and what it does to
// that connection decides whether both tools work or neither does.
type ZapretMode string

const (
	// ZapretShare leaves the desynchroniser in charge of the direct path and
	// routes its injected packets around the tunnel so they still reach the
	// provider. Both tools keep doing their job: blocked sites that zapret can
	// unblock stay direct and fast, and the tunnel carries the rest.
	ZapretShare ZapretMode = "share"

	// ZapretExempt keeps the cores' own connections away from the
	// desynchroniser entirely. Nothing the tunnel carries is desynchronised,
	// which is safe but costs the DPI bypass on the direct path.
	ZapretExempt ZapretMode = "exempt"

	// ZapretIgnore makes no accommodation at all. Kept because a future zapret
	// may not need one, and because a user who has read the trade-offs is
	// entitled to say so.
	ZapretIgnore ZapretMode = "off"
)

// Valid reports whether m is a known mode.
func (m ZapretMode) Valid() bool {
	switch m {
	case ZapretShare, ZapretExempt, ZapretIgnore:
		return true
	}
	return false
}

// Settings are the knobs that are not rules and not subscriptions.
type Settings struct {
	// Mode is the traffic capture mode: tun, tproxy, redirect or proxy.
	Mode string `json:"mode"`

	// ProxyGroup is the outbound tag that ActionProxy rules resolve to.
	ProxyGroup string `json:"proxy_group"`

	// SelectedNode is the outbound tag the proxy group points at. Empty means
	// automatic, where the fastest node is chosen by latency.
	//
	// It is stored rather than only pushed to the running core, because
	// choosing a server is a decision about configuration and has to be
	// possible before anything is running — and has to survive a restart.
	SelectedNode string `json:"selected_node,omitempty"`

	// AutoConnect brings the tunnel up when the daemon starts.
	//
	// On a router this is the ordinary case rather than a convenience: the box
	// reboots after a power cut and nobody is watching, and a VPN that waits to
	// be switched on by hand is off for as long as it takes somebody to notice.
	AutoConnect bool `json:"auto_connect"`

	// Split says what the rule list means as a whole: whether it names what
	// goes through the tunnel, what stays out of it, or nothing at all.
	Split SplitMode `json:"split"`

	// DefaultAction is the older spelling of the same idea, kept so an existing
	// configuration keeps working. It is read on load, migrated into Split, and
	// never written again.
	DefaultAction routing.Action `json:"default_action,omitempty"`

	DNS      DNSSettings      `json:"dns"`
	Health   HealthSettings   `json:"health"`
	Core     CoreSettings     `json:"core"`
	Firewall FirewallSettings `json:"firewall"`

	// SubscriptionInterval is the default refresh period for subscriptions that
	// do not specify their own.
	SubscriptionInterval Duration `json:"subscription_interval,omitempty"`
}

// HealthSettings names the hosts used to answer "does the internet work" and
// "does the VPN work" — two questions that fail separately and need separate
// evidence.
type HealthSettings struct {
	// Internet holds hosts that are never blocked, so a failure means the line
	// is down rather than that somebody censored the probe. Checking a foreign
	// site here gives a false alarm on a censored network every time.
	Internet []string `json:"internet,omitempty"`

	// Tunnel holds hosts that are definitely blocked, so reaching one is proof
	// the traffic actually left through the tunnel. A reachable host would prove
	// nothing: it answers whether the tunnel is up or down.
	Tunnel []string `json:"tunnel,omitempty"`
}

// DNSSettings configures name resolution.
type DNSSettings struct {
	// Proxy is the upstream resolved through the tunnel, Direct the one resolved
	// outside it. Splitting them is what keeps a split tunnel from leaking every
	// name it looks up.
	Proxy  string `json:"proxy"`
	Direct string `json:"direct"`

	// FakeIP answers with placeholder addresses so that domain rules work for
	// clients that only ever hand the router an address. It must be off when
	// something else on the router already owns port 53.
	FakeIP bool `json:"fake_ip"`

	// Listen is the port Obelisk's own resolver binds. Zero disables it, which is
	// the right setting when an existing resolver stays in charge.
	Listen int `json:"listen,omitempty"`

	Strategy string `json:"strategy,omitempty"`
}

// FirewallSettings configures the rules the TPROXY and REDIRECT modes need.
//
// None of it applies in TUN mode: sing-box installs its own routing there with
// auto_route, and a second set of rules would fight it.
type FirewallSettings struct {
	// Manage lets Obelisk install and remove the rules. Turning it off is for
	// people who maintain their own nftables configuration and want Obelisk to
	// generate the core config and nothing else.
	Manage bool `json:"manage"`

	// LANInterfaces limits capture to traffic arriving on these interfaces.
	// Empty captures from everywhere, which on a router also means the WAN.
	LANInterfaces []string `json:"lan_interfaces,omitempty"`

	// Bypass lists destinations that must never be captured, on top of the
	// reserved ranges that are always excluded.
	Bypass []string `json:"bypass,omitempty"`

	// BlockQUIC rejects UDP/443 so browsers fall back to TCP. It matters in
	// REDIRECT mode, which cannot capture UDP at all: without it QUIC leaves the
	// router untouched and the user sees a working connection that is not going
	// through the tunnel.
	BlockQUIC bool `json:"block_quic"`

	// KillSwitch drops LAN traffic that reached the forwarding path without
	// being captured. It turns a silent leak into an obvious outage, which is
	// the right trade: a user notices no internet, and never notices traffic
	// quietly leaving in the clear.
	KillSwitch bool `json:"kill_switch"`

	// Zapret decides how to coexist with a DPI desynchroniser on the same
	// router. See ZapretMode.
	Zapret ZapretMode `json:"zapret,omitempty"`

	// Marks. Both are settable because a router may already use these values;
	// zapret, for instance, marks with 0x40000000 and 0x20000000.
	BypassMark int `json:"bypass_mark,omitempty"`
	TProxyMark int `json:"tproxy_mark,omitempty"`
	RouteTable int `json:"route_table,omitempty"`
}

// CoreSettings configures how work is divided between the two cores.
type CoreSettings struct {
	// Policy resolves which core carries a node when both are capable.
	Policy model.Policy `json:"policy"`

	// Dir holds cores installed by Obelisk. Empty uses the default.
	Dir string `json:"dir,omitempty"`

	// AutoUpdate checks for new core releases on a schedule.
	AutoUpdate bool `json:"auto_update"`
}

// Default returns the configuration a fresh installation starts from.
//
// The defaults describe a split tunnel: nothing is proxied until a rule says so.
// That is the safer starting point on a router, where the alternative is a box
// that silently sends the whole household's traffic somewhere new the moment it
// is switched on.
func Default() Config {
	return Config{
		Version: CurrentVersion,
		// Empty slices rather than nil, so the file a user opens shows "[]" and
		// invites them to add something instead of showing a bare "null".
		Subscriptions: []Subscription{},
		Rules:         []routing.Entry{},
		Settings: Settings{
			Mode:        "tun",
			AutoConnect: true,
			ProxyGroup:  "proxy",
			// A fresh install proxies only what it is asked to. Sending a
			// household's whole connection through a server it has not chosen
			// yet is not a default anyone should get by accident.
			Split: SplitProxyList,
			Health: HealthSettings{
				Internet: []string{"https://yandex.ru/", "https://mail.ru/", "https://2ip.ru/"},
				Tunnel:   []string{"https://telegram.org/", "https://rutracker.net/", "https://meduza.io/"},
			},
			DNS: DNSSettings{
				Proxy: "https://1.1.1.1/dns-query",
				// A public resolver, not the router's own. The core binds its
				// outbound sockets to the WAN interface, so a packet addressed to
				// the router's LAN address is handed to the ISP and lost — and a
				// core that cannot resolve names takes the whole network with it.
				Direct: "udp://1.1.1.1",
				// Off by default: sniffing already recovers the domain from the
				// TLS handshake, while FakeIP throws away the client's answer and
				// makes every connection, direct ones included, depend on a second
				// resolution inside the core.
				FakeIP:   false,
				Listen:   24053,
				Strategy: "prefer_ipv4",
			},
			Core: CoreSettings{
				Policy:     model.DefaultPolicy(),
				AutoUpdate: false,
			},
			Firewall: FirewallSettings{
				// Obelisk manages the capture rules by default; it only ever
				// touches its own nftables table, never anyone else's.
				Manage: true,
				Zapret: ZapretShare,
			},
			SubscriptionInterval: Duration(time.Hour),
		},
	}
}

// Load reads the configuration, returning defaults when the file does not exist
// yet. A missing file is a first run, not an error.
func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		cfg := Default()
		return &cfg, nil
	}
	if err != nil {
		return nil, fmt.Errorf("config: %w", err)
	}

	var cfg Config
	if err := json.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("config: %s is not valid JSON: %w", path, err)
	}
	if cfg.Version > CurrentVersion {
		return nil, fmt.Errorf(
			"config: %s was written by a newer Obelisk (schema %d, this build understands %d)",
			path, cfg.Version, CurrentVersion)
	}

	cfg.applyDefaults()
	return &cfg, nil
}

// applyDefaults fills in fields absent from an older or hand-edited file.
func (c *Config) applyDefaults() {
	d := Default()

	// Schema 2 introduced auto-connect, and a new boolean cannot be given a
	// default the way a new string can: JSON cannot tell a field that was absent
	// from one that was written as false, so every existing installation would
	// silently read the new setting as off. The version number is the only thing
	// that distinguishes them, which is what it is for.
	if c.Version < 2 {
		c.Settings.AutoConnect = d.Settings.AutoConnect
	}

	if c.Version == 0 || c.Version < CurrentVersion {
		c.Version = CurrentVersion
	}
	if c.Settings.Mode == "" {
		c.Settings.Mode = d.Settings.Mode
	}
	if c.Settings.ProxyGroup == "" {
		c.Settings.ProxyGroup = d.Settings.ProxyGroup
	}
	// Migrate the older fallback-action setting. A file written before split
	// modes existed says only what happened to unmatched traffic, and that maps
	// onto exactly one of the three modes.
	if !c.Settings.Split.Valid() {
		switch c.Settings.DefaultAction {
		case routing.ActionProxy:
			c.Settings.Split = SplitBypassList
		default:
			c.Settings.Split = d.Settings.Split
		}
	}
	c.Settings.DefaultAction = ""
	if c.Settings.DNS.Proxy == "" {
		c.Settings.DNS.Proxy = d.Settings.DNS.Proxy
	}
	if c.Settings.DNS.Direct == "" {
		c.Settings.DNS.Direct = d.Settings.DNS.Direct
	}
	if c.Settings.DNS.Strategy == "" {
		c.Settings.DNS.Strategy = d.Settings.DNS.Strategy
	}
	if c.Settings.Core.Policy.Default == "" {
		c.Settings.Core.Policy = model.DefaultPolicy()
	}
	if len(c.Settings.Health.Internet) == 0 {
		c.Settings.Health.Internet = d.Settings.Health.Internet
	}
	if len(c.Settings.Health.Tunnel) == 0 {
		c.Settings.Health.Tunnel = d.Settings.Health.Tunnel
	}
	if !c.Settings.Firewall.Zapret.Valid() {
		c.Settings.Firewall.Zapret = d.Settings.Firewall.Zapret
	}
	if c.Settings.SubscriptionInterval == 0 {
		c.Settings.SubscriptionInterval = d.Settings.SubscriptionInterval
	}
}

// Save writes the configuration atomically.
//
// The temporary file is created beside the target so the rename stays inside one
// filesystem. An interrupted write must never be able to leave a router with a
// half-written configuration it cannot parse on the next boot.
func (c *Config) Save(path string) error {
	c.Version = CurrentVersion

	if dir := filepath.Dir(path); dir != "" {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return fmt.Errorf("config: %w", err)
		}
	}

	data, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return fmt.Errorf("config: %w", err)
	}
	data = append(data, '\n')

	tmp := path + ".tmp"
	// The file holds subscription URLs, which carry credentials.
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return fmt.Errorf("config: %w", err)
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("config: %w", err)
	}
	return nil
}

// AddRule appends an entry, replacing any existing one that matches the same
// thing in the same way. Re-adding a rule is a correction, not a duplicate.
func (c *Config) AddRule(entry routing.Entry) (replaced bool) {
	for i := range c.Rules {
		if c.Rules[i].ID == entry.ID {
			c.Rules[i] = entry
			return true
		}
	}
	c.Rules = append(c.Rules, entry)
	return false
}

// RemoveRule deletes entries by ID, or by the value they match. Matching on the
// value means a user can remove "youtube.com" by typing it, without first
// looking up an identifier they never chose.
func (c *Config) RemoveRule(idOrValue string) []routing.Entry {
	needle := strings.ToLower(strings.TrimSpace(idOrValue))

	var (
		kept    []routing.Entry
		removed []routing.Entry
	)
	for _, r := range c.Rules {
		if r.ID == needle || strings.ToLower(r.Value) == needle || strings.ToLower(r.Raw) == needle {
			removed = append(removed, r)
			continue
		}
		kept = append(kept, r)
	}
	c.Rules = kept
	return removed
}

// EnabledSubscriptions returns the subscriptions that should be fetched.
func (c *Config) EnabledSubscriptions() []Subscription {
	var out []Subscription
	for _, s := range c.Subscriptions {
		if s.Enabled {
			out = append(out, s)
		}
	}
	return out
}

// Duration is a time.Duration that serializes as a human-readable string, so the
// configuration file says "1h" rather than 3600000000000.
type Duration time.Duration

// MarshalJSON implements json.Marshaler.
func (d Duration) MarshalJSON() ([]byte, error) {
	return json.Marshal(time.Duration(d).String())
}

// UnmarshalJSON implements json.Unmarshaler, accepting both the string form and
// a bare number of nanoseconds.
func (d *Duration) UnmarshalJSON(data []byte) error {
	var s string
	if err := json.Unmarshal(data, &s); err == nil {
		parsed, err := time.ParseDuration(s)
		if err != nil {
			return fmt.Errorf("config: %q is not a duration: %w", s, err)
		}
		*d = Duration(parsed)
		return nil
	}

	var n int64
	if err := json.Unmarshal(data, &n); err != nil {
		return fmt.Errorf("config: cannot read duration: %w", err)
	}
	*d = Duration(n)
	return nil
}

// Duration returns the value as a time.Duration.
func (d Duration) Duration() time.Duration { return time.Duration(d) }
