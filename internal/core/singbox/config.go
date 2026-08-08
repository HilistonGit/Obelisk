package singbox

import (
	"encoding/json"
	"fmt"
)

// InboundMode selects how LAN traffic is captured. All three are generated from
// the same routing tree; only the inbound differs, which is what allows the mode
// to be switched at runtime without rebuilding anything else.
type InboundMode string

const (
	// ModeTUN puts a virtual interface on the router and takes the whole L3
	// flow, including UDP, QUIC and ICMP. The most complete capture, and the one
	// that needs /dev/net/tun inside the container.
	ModeTUN InboundMode = "tun"

	// ModeTProxy captures TCP and UDP through nftables marks and policy routing.
	// Lighter than TUN and the traditional choice on routers.
	ModeTProxy InboundMode = "tproxy"

	// ModeRedirect captures TCP only through NAT redirection. The most
	// compatible mode and the last resort on kernels without TPROXY, but UDP —
	// and therefore QUIC — has to be blocked rather than proxied.
	ModeRedirect InboundMode = "redirect"

	// ModeProxy exposes only a mixed SOCKS/HTTP listener and captures nothing.
	// Clients opt in by pointing at it.
	ModeProxy InboundMode = "proxy"
)

// Options configures the generated sing-box instance.
type Options struct {
	Mode     InboundMode
	LogLevel string

	// TUN settings, used only in ModeTUN.
	TUNName     string
	TUNAddress  []string
	TUNMTU      int
	TUNStack    string // system, gvisor or mixed
	AutoRoute   bool
	StrictRoute bool

	// Transparent proxy settings, used in ModeTProxy and ModeRedirect.
	TransparentListen string
	TransparentPort   int

	// Mixed SOCKS/HTTP listener. Always generated: it is how a client opts into
	// the proxy explicitly, and how Obelisk's own latency probes reach a node.
	MixedListen string
	MixedPort   int

	// DNS.
	DNSListen   string
	DNSPort     int
	DNSProxy    string // upstream resolved through the proxy, e.g. https://1.1.1.1/dns-query
	DNSDirect   string // upstream resolved directly, e.g. udp://192.168.1.1
	FakeIP      bool
	DNSStrategy string // prefer_ipv4, prefer_ipv6, ipv4_only, ipv6_only

	// IPv6 says whether this host has IPv6 connectivity of its own.
	//
	// When it does not, the tunnel must not offer any. A tun interface with an
	// IPv6 address installs an IPv6 default route where the system had none, and
	// from that moment every dual-stack name is tried over IPv6 first — into a
	// tunnel whose direct outbound has no IPv6 path at all. Sites then fail
	// instantly rather than slowly, which reads as "the internet is broken" and
	// disappears the moment the tunnel is switched off, making it very hard to
	// attribute.
	IPv6 bool

	// DefaultMark is stamped on sing-box's own outbound sockets.
	//
	// It is the counterpart of the mark Xray sets, and it matters for exactly
	// the same reason: in TPROXY mode the capture rules see the front core's
	// connection to a remote server and would send it back into the tunnel it is
	// establishing. The firewall layer lets marked packets past.
	DefaultMark int

	// Control plane.
	ClashAPIListen string
	ClashAPISecret string
	CacheFile      string
}

// DefaultOptions returns the settings Obelisk runs sing-box with out of the box.
func DefaultOptions() Options {
	return Options{
		Mode:              ModeTUN,
		LogLevel:          "warn",
		TUNName:           "obelisk0",
		TUNAddress:        []string{"172.19.0.1/30", "fdfe:dcba:9876::1/126"},
		TUNMTU:            9000,
		TUNStack:          "system",
		AutoRoute:         true,
		StrictRoute:       true,
		TransparentListen: "::",
		TransparentPort:   24011,
		MixedListen:       "::",
		MixedPort:         24010,
		DNSListen:         "::",
		DNSPort:           24053,
		DNSProxy:          "https://1.1.1.1/dns-query",
		DNSDirect:         "udp://1.1.1.1",
		// FakeIP off by default. It exists so that domain rules work for clients
		// that only ever hand the router an address, but sniffing already
		// recovers the name from the TLS handshake or the Host header, which
		// covers nearly all of it. What it costs is real: the client's own
		// answer is thrown away, so every connection — including every direct
		// one — has to be resolved a second time inside the core, and any
		// hiccup in that resolution turns into a connection to 198.18.x.x that
		// goes nowhere.
		FakeIP:         false,
		DNSStrategy:    "prefer_ipv4",
		IPv6:           true,
		ClashAPIListen: "127.0.0.1:24090",
	}
}

// Group is a selector or urltest outbound: the policy layer that lets a routing
// rule name "the streaming group" rather than one specific server.
type Group struct {
	Tag       string   `json:"tag"`
	Type      string   `json:"type"` // selector or urltest
	Outbounds []string `json:"outbounds"`
	Default   string   `json:"default,omitempty"`
	URL       string   `json:"url,omitempty"`
	Interval  string   `json:"interval,omitempty"`
	Tolerance int      `json:"tolerance,omitempty"`
	Interrupt bool     `json:"interrupt_exist_connections,omitempty"`
}

// Rule is one routing decision in Obelisk's own vocabulary, rendered into
// sing-box's rule schema on the way out.
type Rule struct {
	// Matchers. An empty matcher is simply not emitted, and a rule with no
	// matcher at all matches everything.
	Domain        []string `json:"domain,omitempty"`
	DomainSuffix  []string `json:"domain_suffix,omitempty"`
	DomainKeyword []string `json:"domain_keyword,omitempty"`
	DomainRegex   []string `json:"domain_regex,omitempty"`
	IPCIDR        []string `json:"ip_cidr,omitempty"`
	SourceIPCIDR  []string `json:"source_ip_cidr,omitempty"`
	Port          []int    `json:"port,omitempty"`
	PortRange     []string `json:"port_range,omitempty"`
	Network       []string `json:"network,omitempty"`
	Protocol      []string `json:"protocol,omitempty"`
	RuleSet       []string `json:"rule_set,omitempty"`
	Inbound       []string `json:"inbound,omitempty"`
	ClashMode     string   `json:"clash_mode,omitempty"`
	IPIsPrivate   bool     `json:"ip_is_private,omitempty"`
	Invert        bool     `json:"invert,omitempty"`

	// Outcome. Outbound names a node, a group, "direct" or "block".
	Outbound string `json:"outbound,omitempty"`
}

// RuleSet is a remote or local set of routing rules, the mechanism behind
// geosite/geoip style matching without shipping the databases in the image.
type RuleSet struct {
	Tag            string `json:"tag"`
	Type           string `json:"type"` // remote or local
	Format         string `json:"format"`
	URL            string `json:"url,omitempty"`
	Path           string `json:"path,omitempty"`
	DownloadDetour string `json:"download_detour,omitempty"`
	UpdateInterval string `json:"update_interval,omitempty"`
}

// Config is everything the manager hands to the generator.
type Config struct {
	Options   Options
	Outbounds []map[string]any
	Endpoints []map[string]any
	Groups    []Group
	Rules     []Rule
	RuleSets  []RuleSet

	// FinalTag receives traffic that matched no rule.
	FinalTag string

	// ProxyTag is the group that carries proxied traffic. It is distinct from
	// FinalTag: in a split tunnel the final route is "direct" while the proxy
	// group still exists and still has to be reachable by name — the DNS server
	// that resolves through the tunnel detours through this, not through
	// whatever unmatched traffic happens to do.
	ProxyTag string
}

// Well-known tags. They are referenced by generated rules and by the API, so
// they are defined once here rather than spelled out at each use.
const (
	TagDirect   = "direct"
	TagBlock    = "block"
	TagDNSOut   = "dns-out"
	TagTUNIn    = "tun-in"
	TagTProxyIn = "tproxy-in"
	TagRedirIn  = "redirect-in"
	TagMixedIn  = "mixed-in"
	TagDNSIn    = "dns-in"
)

// BuildConfig renders the complete sing-box configuration.
func BuildConfig(c Config) ([]byte, error) {
	opts := c.Options
	if opts.Mode == "" {
		opts.Mode = ModeTUN
	}

	inbounds, err := buildInbounds(opts)
	if err != nil {
		return nil, err
	}

	outbounds := make([]any, 0, len(c.Outbounds)+len(c.Groups)+2)
	for _, o := range c.Outbounds {
		outbounds = append(outbounds, o)
	}
	for _, g := range c.Groups {
		group, err := renderGroup(g)
		if err != nil {
			return nil, err
		}
		outbounds = append(outbounds, group)
	}
	outbounds = append(outbounds,
		map[string]any{"type": "direct", "tag": TagDirect},
		map[string]any{"type": "block", "tag": TagBlock},
	)

	cfg := map[string]any{
		"log": map[string]any{
			"level":     orDefault(opts.LogLevel, "warn"),
			"timestamp": true,
		},
		"inbounds":  inbounds,
		"outbounds": outbounds,
		"route":     buildRoute(c, opts),
		"dns":       buildDNS(c, opts),
	}

	if len(c.Endpoints) > 0 {
		endpoints := make([]any, 0, len(c.Endpoints))
		for _, e := range c.Endpoints {
			endpoints = append(endpoints, e)
		}
		cfg["endpoints"] = endpoints
	}

	experimental := map[string]any{}
	if opts.ClashAPIListen != "" {
		clash := map[string]any{"external_controller": opts.ClashAPIListen}
		setNonEmpty(clash, "secret", opts.ClashAPISecret)
		experimental["clash_api"] = clash
	}
	if opts.CacheFile != "" {
		experimental["cache_file"] = map[string]any{
			"enabled":      true,
			"path":         opts.CacheFile,
			"store_fakeip": opts.FakeIP,
			// Remembering which node a selector was pointed at means a restart
			// does not silently move the user back to a default.
			"store_rdrc": true,
		}
	}
	if len(experimental) > 0 {
		cfg["experimental"] = experimental
	}

	return json.MarshalIndent(cfg, "", "  ")
}

// tunAddresses returns the addresses to give the tunnel interface.
//
// The IPv6 address is dropped when the host has no IPv6 of its own. Keeping it
// would hand the system an IPv6 default route it did not have a moment earlier,
// and every dual-stack destination would then be attempted over a family that
// cannot leave the building.
func tunAddresses(opts Options) []string {
	if opts.IPv6 {
		return opts.TUNAddress
	}
	out := make([]string, 0, len(opts.TUNAddress))
	for _, addr := range opts.TUNAddress {
		if !containsColon(addr) {
			out = append(out, addr)
		}
	}
	return out
}

// buildInbounds renders the capture inbound for the selected mode, plus the
// always-present mixed and DNS listeners.
func buildInbounds(opts Options) ([]any, error) {
	var inbounds []any

	switch opts.Mode {
	case ModeTUN:
		tun := map[string]any{
			"type":         "tun",
			"tag":          TagTUNIn,
			"address":      tunAddresses(opts),
			"auto_route":   opts.AutoRoute,
			"strict_route": opts.StrictRoute,
			"stack":        orDefault(opts.TUNStack, "system"),
		}
		setNonEmpty(tun, "interface_name", opts.TUNName)
		setPositive(tun, "mtu", opts.TUNMTU)
		inbounds = append(inbounds, tun)

	case ModeTProxy:
		inbounds = append(inbounds, map[string]any{
			"type":        "tproxy",
			"tag":         TagTProxyIn,
			"listen":      orDefault(opts.TransparentListen, "::"),
			"listen_port": opts.TransparentPort,
		})

	case ModeRedirect:
		// REDIRECT is TCP-only by construction; the UDP half of the capture is
		// handled by the firewall layer, which rejects QUIC so that clients fall
		// back to TCP rather than leaking.
		inbounds = append(inbounds, map[string]any{
			"type":        "redirect",
			"tag":         TagRedirIn,
			"listen":      orDefault(opts.TransparentListen, "::"),
			"listen_port": opts.TransparentPort,
		})

	case ModeProxy:
		// Nothing to capture; the mixed listener below is the only entry point.

	default:
		return nil, fmt.Errorf("sing-box: unknown inbound mode %q", opts.Mode)
	}

	if opts.MixedPort > 0 {
		inbounds = append(inbounds, map[string]any{
			"type":        "mixed",
			"tag":         TagMixedIn,
			"listen":      orDefault(opts.MixedListen, "::"),
			"listen_port": opts.MixedPort,
		})
	}
	if opts.DNSPort > 0 {
		inbounds = append(inbounds, map[string]any{
			"type":        "direct",
			"tag":         TagDNSIn,
			"listen":      orDefault(opts.DNSListen, "::"),
			"listen_port": opts.DNSPort,
			"network":     "udp",
		})
	}
	return inbounds, nil
}

// buildRoute renders the routing tree.
func buildRoute(c Config, opts Options) map[string]any {
	rules := make([]any, 0, len(c.Rules)+4)

	// Sniffing is a routing action in current sing-box rather than an inbound
	// flag. It must run first: every domain-based rule below depends on the
	// destination name it recovers from the first packet.
	rules = append(rules, map[string]any{"action": "sniff"})

	// DNS queries arriving on any inbound are answered by the DNS engine rather
	// than forwarded, which is what makes split DNS and FakeIP possible.
	rules = append(rules, map[string]any{
		"protocol": "dns",
		"action":   "hijack-dns",
	})
	if opts.DNSPort > 0 {
		rules = append(rules, map[string]any{
			"inbound": []any{TagDNSIn},
			"action":  "hijack-dns",
		})
	}

	for _, r := range c.Rules {
		if rendered := renderRule(r); rendered != nil {
			rules = append(rules, rendered)
		}
	}

	route := map[string]any{
		"rules": rules,
		"final": orDefault(c.FinalTag, TagDirect),
		// Without this, sing-box cannot tell which interface to send a node's
		// own traffic out of, and the tunnel routes into itself.
		"auto_detect_interface": true,

		// Which resolver turns a node's hostname into an address when dialling
		// it. sing-box 1.12 made this mandatory and refuses to start without it.
		//
		// It has to be the direct resolver. Resolving a VPN server's own name
		// through the tunnel that is not up yet is circular, and through a
		// tunnel that is up sends the lookup to the very server being located.
		"default_domain_resolver": "dns-direct",
	}
	setPositive(route, "default_mark", opts.DefaultMark)

	if len(c.RuleSets) > 0 {
		sets := make([]any, 0, len(c.RuleSets))
		for _, rs := range c.RuleSets {
			set := map[string]any{
				"tag":    rs.Tag,
				"type":   orDefault(rs.Type, "remote"),
				"format": orDefault(rs.Format, "binary"),
			}
			setNonEmpty(set, "url", rs.URL)
			setNonEmpty(set, "path", rs.Path)
			setNonEmpty(set, "download_detour", rs.DownloadDetour)
			setNonEmpty(set, "update_interval", rs.UpdateInterval)
			sets = append(sets, set)
		}
		route["rule_set"] = sets
	}
	return route
}

// renderRule converts one Obelisk rule into sing-box's schema, returning nil for
// a rule that would match nothing or route nowhere.
func renderRule(r Rule) map[string]any {
	out := map[string]any{}

	setStrings(out, "domain", r.Domain)
	setStrings(out, "domain_suffix", r.DomainSuffix)
	setStrings(out, "domain_keyword", r.DomainKeyword)
	setStrings(out, "domain_regex", r.DomainRegex)
	setStrings(out, "ip_cidr", r.IPCIDR)
	setStrings(out, "source_ip_cidr", r.SourceIPCIDR)
	setStrings(out, "port_range", r.PortRange)
	setStrings(out, "network", r.Network)
	setStrings(out, "protocol", r.Protocol)
	setStrings(out, "rule_set", r.RuleSet)
	setStrings(out, "inbound", r.Inbound)
	setNonEmpty(out, "clash_mode", r.ClashMode)

	if len(r.Port) > 0 {
		ports := make([]any, 0, len(r.Port))
		for _, p := range r.Port {
			ports = append(ports, p)
		}
		out["port"] = ports
	}
	if r.IPIsPrivate {
		out["ip_is_private"] = true
	}
	if r.Invert {
		out["invert"] = true
	}

	if len(out) == 0 || r.Outbound == "" {
		return nil
	}

	// "block" is an action in current sing-box rather than an outbound, though
	// the block outbound is still generated for configs that reference it.
	if r.Outbound == TagBlock {
		out["action"] = "reject"
	} else {
		out["outbound"] = r.Outbound
	}
	return out
}

// renderGroup converts a selector or urltest group.
func renderGroup(g Group) (map[string]any, error) {
	if g.Tag == "" {
		return nil, fmt.Errorf("sing-box: group has no tag")
	}
	if len(g.Outbounds) == 0 {
		return nil, fmt.Errorf("sing-box: group %q has no members", g.Tag)
	}

	out := map[string]any{
		"type":      orDefault(g.Type, "selector"),
		"tag":       g.Tag,
		"outbounds": g.Outbounds,
	}
	setNonEmpty(out, "default", g.Default)

	if out["type"] == "urltest" {
		delete(out, "default")
		out["url"] = orDefault(g.URL, "https://www.gstatic.com/generate_204")
		out["interval"] = orDefault(g.Interval, "3m")
		setPositive(out, "tolerance", g.Tolerance)
	}
	if g.Interrupt {
		out["interrupt_exist_connections"] = true
	}
	return out, nil
}

// buildDNS renders the DNS engine: one upstream reached through the proxy, one
// reached directly, and a rule tree that decides which name goes where.
//
// Splitting DNS this way is what keeps a split tunnel honest. Resolving a
// proxied domain through the local resolver leaks both the query and, via the
// answer, the geography of the client; resolving a direct domain through the
// proxy breaks every CDN that answers based on resolver location.
func buildDNS(c Config, opts Options) map[string]any {
	// No detour on the direct resolver. Sending it through the direct outbound
	// is what it does anyway, and sing-box 1.13 rejects the redundancy outright
	// rather than ignoring it: "detour to an empty direct outbound makes no
	// sense". The proxy resolver below does need one, because there the detour
	// is the entire point.
	servers := []any{
		mapOf(
			"tag", "dns-direct",
			"type", dnsType(opts.DNSDirect),
			"server", dnsHost(opts.DNSDirect),
		),
	}
	// The proxied resolver detours through the proxy group. Pointing it at the
	// final route instead was a real defect: in a split tunnel the final route
	// is "direct", and sing-box refuses a DNS detour to a plain direct outbound
	// outright — "detour to an empty direct outbound makes no sense" — because
	// it would be a no-op dressed up as a tunnel.
	proxyDetour := c.ProxyTag
	if proxyDetour == "" {
		proxyDetour = c.FinalTag
	}
	if opts.DNSProxy != "" && proxyDetour != "" && proxyDetour != TagDirect {
		servers = append(servers, mapOf(
			"tag", "dns-proxy",
			"type", dnsType(opts.DNSProxy),
			"server", dnsHost(opts.DNSProxy),
			"detour", proxyDetour,
		))
	}

	rules := []any{}
	if opts.FakeIP {
		servers = append(servers, map[string]any{
			"tag":         "dns-fakeip",
			"type":        "fakeip",
			"inet4_range": "198.18.0.0/15",
			"inet6_range": "fc00::/18",
		})
		// FakeIP is what makes domain-based routing work for clients that only
		// ever hand the router an IP address: the answer is a placeholder, and
		// the real name travels with the connection.
		rules = append(rules, map[string]any{
			"query_type": []any{"A", "AAAA"},
			"server":     "dns-fakeip",
		})
	}

	haveProxyResolver := opts.DNSProxy != "" && proxyDetour != "" && proxyDetour != TagDirect

	// Names that route through the proxy are resolved through it, so that the
	// answer comes from where the connection will. Everything else is resolved
	// directly. This is the half of split DNS that has to be built from the
	// routing rules rather than declared, and without it the comment above this
	// function is a description of something that is not happening.
	if haveProxyResolver {
		for _, rule := range c.Rules {
			if rule.Outbound != c.ProxyTag {
				continue
			}
			if dnsRule := domainSelector(rule); dnsRule != nil {
				dnsRule["server"] = "dns-proxy"
				rules = append(rules, dnsRule)
			}
		}
	}

	// The fallback follows the traffic. When unmatched traffic goes direct —
	// which is the whole point of a proxy list — resolving every name through
	// the tunnel would be slower than the connection it precedes, and would make
	// every name on the network depend on a tunnel that most of it does not use.
	final := "dns-direct"
	if haveProxyResolver && c.FinalTag != TagDirect {
		final = "dns-proxy"
	}

	strategy := orDefault(opts.DNSStrategy, "prefer_ipv4")
	if !opts.IPv6 {
		// Handing out AAAA records for a family with no route out produces a
		// timeout per connection, not a fallback.
		strategy = "ipv4_only"
	}

	dns := map[string]any{
		"servers":           servers,
		"final":             final,
		"strategy":          strategy,
		"independent_cache": true,
	}
	if len(rules) > 0 {
		dns["rules"] = rules
	}
	return dns
}

// domainSelector copies just the name-matching half of a routing rule, which is
// all a DNS rule can act on. A rule that matches only on address or port has no
// DNS equivalent and returns nil: a query carries a name and nothing else.
func domainSelector(rule Rule) map[string]any {
	out := map[string]any{}
	setStrings(out, "domain", rule.Domain)
	setStrings(out, "domain_suffix", rule.DomainSuffix)
	setStrings(out, "domain_keyword", rule.DomainKeyword)
	setStrings(out, "domain_regex", rule.DomainRegex)
	setStrings(out, "rule_set", rule.RuleSet)
	if len(out) == 0 {
		return nil
	}
	return out
}

// dnsType extracts the server type from a DNS upstream URL. sing-box's current
// schema names the transport explicitly instead of inferring it from a prefix.
func dnsType(upstream string) string {
	switch {
	case upstream == "":
		return "udp"
	case hasPrefix(upstream, "https://"):
		return "https"
	case hasPrefix(upstream, "tls://"):
		return "tls"
	case hasPrefix(upstream, "quic://"):
		return "quic"
	case hasPrefix(upstream, "h3://"):
		return "h3"
	case hasPrefix(upstream, "tcp://"):
		return "tcp"
	default:
		return "udp"
	}
}

// dnsHost strips the scheme from a DNS upstream URL, leaving the host that the
// typed server object expects.
func dnsHost(upstream string) string {
	if upstream == "" {
		return "1.1.1.1"
	}
	for _, prefix := range []string{"https://", "tls://", "quic://", "h3://", "tcp://", "udp://"} {
		if hasPrefix(upstream, prefix) {
			return trimPath(upstream[len(prefix):])
		}
	}
	return trimPath(upstream)
}

// containsColon distinguishes an IPv6 address literal from an IPv4 one.
func containsColon(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] == ':' {
			return true
		}
	}
	return false
}

func hasPrefix(s, prefix string) bool {
	return len(s) >= len(prefix) && s[:len(prefix)] == prefix
}

func trimPath(s string) string {
	for i := 0; i < len(s); i++ {
		if s[i] == '/' {
			return s[:i]
		}
	}
	return s
}

func setStrings(m map[string]any, key string, values []string) {
	if len(values) == 0 {
		return
	}
	out := make([]any, 0, len(values))
	for _, v := range values {
		out = append(out, v)
	}
	m[key] = out
}

// mapOf builds a map from alternating key/value arguments, skipping pairs whose
// value is an empty string.
func mapOf(kv ...any) map[string]any {
	out := make(map[string]any, len(kv)/2)
	for i := 0; i+1 < len(kv); i += 2 {
		key, ok := kv[i].(string)
		if !ok {
			continue
		}
		if s, isString := kv[i+1].(string); isString && s == "" {
			continue
		}
		out[key] = kv[i+1]
	}
	return out
}
