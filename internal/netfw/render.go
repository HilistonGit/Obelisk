package netfw

import (
	"fmt"
	"strconv"
	"strings"
)

// reservedIPv4 and reservedIPv6 are destinations that must never be sent into a
// tunnel. Capturing them would cut the router off from the LAN it serves, break
// DHCP and mDNS, and send loopback traffic to a proxy.
var (
	reservedIPv4 = []string{
		"0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8",
		"169.254.0.0/16", "172.16.0.0/12", "192.0.0.0/24", "192.168.0.0/16",
		"224.0.0.0/4", "240.0.0.0/4", "255.255.255.255/32",
	}
	reservedIPv6 = []string{
		"::/128", "::1/128", "fc00::/7", "fe80::/10", "ff00::/8",
	}
)

// Render produces the nftables script for the current configuration.
//
// It is deterministic and side-effect free, which is what allows the rules to be
// unit tested and read by a human before they are ever installed on a router.
func (m *Manager) Render() string {
	c := m.cfg
	var b strings.Builder

	fmt.Fprintf(&b, "# Obelisk %s capture rules.\n", c.Mode)
	fmt.Fprintf(&b, "# Generated — edit the Obelisk configuration, not this.\n")
	fmt.Fprintf(&b, "# Only table inet %s is touched; nothing else on this router is modified.\n\n", c.Table)

	// Replacing our own table is idempotent and leaves every other table alone.
	fmt.Fprintf(&b, "table inet %s {}\n", c.Table)
	fmt.Fprintf(&b, "delete table inet %s\n\n", c.Table)

	fmt.Fprintf(&b, "table inet %s {\n", c.Table)
	renderSets(&b, c)

	switch c.Mode {
	case ModeTProxy:
		renderTProxy(&b, c)
	case ModeRedirect:
		renderRedirect(&b, c)
	}

	if c.BlockQUIC {
		renderQUICBlock(&b, c)
	}
	if c.KillSwitch && c.Mode != ModeNone {
		renderKillSwitch(&b, c)
	}
	b.WriteString("}\n")

	return b.String()
}

// renderSets emits the bypass sets.
func renderSets(b *strings.Builder, c Config) {
	v4 := append(append([]string{}, reservedIPv4...), c.BypassIPv4...)
	fmt.Fprintf(b, "  set bypass4 {\n")
	fmt.Fprintf(b, "    type ipv4_addr\n    flags interval\n    auto-merge\n")
	fmt.Fprintf(b, "    elements = { %s }\n  }\n\n", strings.Join(dedupe(v4), ", "))

	if c.EnableIPv6 {
		v6 := append(append([]string{}, reservedIPv6...), c.BypassIPv6...)
		fmt.Fprintf(b, "  set bypass6 {\n")
		fmt.Fprintf(b, "    type ipv6_addr\n    flags interval\n    auto-merge\n")
		fmt.Fprintf(b, "    elements = { %s }\n  }\n\n", strings.Join(dedupe(v6), ", "))
	}
}

// renderTProxy emits the TCP+UDP capture used on routers.
func renderTProxy(b *strings.Builder, c Config) {
	// Forwarded traffic. Priority mangle puts this before the routing decision,
	// which is where TPROXY has to act.
	fmt.Fprintf(b, "  chain prerouting {\n")
	fmt.Fprintf(b, "    type filter hook prerouting priority mangle; policy accept;\n\n")
	renderBypasses(b, c, "    ")
	renderLANFilter(b, c, "    ")

	if c.DNSPort > 0 {
		fmt.Fprintf(b, "\n    # DNS goes to the core's resolver so split DNS and FakeIP work\n")
		fmt.Fprintf(b, "    meta l4proto { tcp, udp } th dport 53 meta mark set %s tproxy to :%d accept\n",
			hex(c.TProxyMark), c.Port)
	}

	fmt.Fprintf(b, "\n    # everything else from the LAN\n")
	fmt.Fprintf(b, "    meta l4proto tcp meta mark set %s tproxy to :%d accept\n", hex(c.TProxyMark), c.Port)
	fmt.Fprintf(b, "    meta l4proto udp meta mark set %s tproxy to :%d accept\n", hex(c.TProxyMark), c.Port)
	fmt.Fprintf(b, "  }\n\n")

	// Traffic the router itself originates. It cannot be TPROXY'd directly —
	// TPROXY only works in prerouting — so it is marked here and the policy
	// routing rule sends it back around through prerouting.
	fmt.Fprintf(b, "  chain output {\n")
	fmt.Fprintf(b, "    type route hook output priority mangle; policy accept;\n\n")
	fmt.Fprintf(b, "    # the cores' own sockets carry the bypass mark and must never come back here\n")
	fmt.Fprintf(b, "    meta mark %s return\n", hex(c.BypassMark))
	fmt.Fprintf(b, "    meta mark %s return\n", hex(c.TProxyMark))
	fmt.Fprintf(b, "    ip daddr @bypass4 return\n")
	if c.EnableIPv6 {
		fmt.Fprintf(b, "    ip6 daddr @bypass6 return\n")
	}
	fmt.Fprintf(b, "    meta l4proto { tcp, udp } meta mark set %s\n", hex(c.TProxyMark))
	fmt.Fprintf(b, "  }\n")
}

// renderRedirect emits the NAT-based TCP capture.
func renderRedirect(b *strings.Builder, c Config) {
	fmt.Fprintf(b, "  chain prerouting {\n")
	fmt.Fprintf(b, "    type nat hook prerouting priority dstnat; policy accept;\n\n")
	renderBypasses(b, c, "    ")
	renderLANFilter(b, c, "    ")
	fmt.Fprintf(b, "\n    meta l4proto tcp redirect to :%d\n", c.Port)
	fmt.Fprintf(b, "  }\n\n")

	fmt.Fprintf(b, "  chain output {\n")
	fmt.Fprintf(b, "    type nat hook output priority dstnat; policy accept;\n\n")
	fmt.Fprintf(b, "    meta mark %s return\n", hex(c.BypassMark))
	fmt.Fprintf(b, "    ip daddr @bypass4 return\n")
	if c.EnableIPv6 {
		fmt.Fprintf(b, "    ip6 daddr @bypass6 return\n")
	}
	fmt.Fprintf(b, "    meta l4proto tcp redirect to :%d\n", c.Port)
	fmt.Fprintf(b, "  }\n")
}

// renderQUICBlock rejects QUIC so browsers fall back to TCP.
//
// This exists because REDIRECT cannot capture UDP at all. Without it, a browser
// negotiates QUIC, the UDP escapes the capture entirely, and the user sees a
// working connection that is not going through the tunnel — the worst possible
// failure for a privacy tool, because it is invisible.
func renderQUICBlock(b *strings.Builder, c Config) {
	fmt.Fprintf(b, "\n  chain quic {\n")
	fmt.Fprintf(b, "    type filter hook forward priority filter; policy accept;\n\n")
	fmt.Fprintf(b, "    ip daddr @bypass4 return\n")
	if c.EnableIPv6 {
		fmt.Fprintf(b, "    ip6 daddr @bypass6 return\n")
	}
	fmt.Fprintf(b, "    udp dport { 443, 8443 } reject with icmpx type admin-prohibited\n")
	fmt.Fprintf(b, "  }\n")
}

// renderKillSwitch drops LAN traffic that escaped the capture.
//
// It sits on the forward hook at a later priority than the QUIC block, so it
// sees only what nothing else claimed. Captured traffic never reaches here: the
// prerouting chain consumes it. What is left is a leak, and this is where it
// stops.
func renderKillSwitch(b *strings.Builder, c Config) {
	fmt.Fprintf(b, "\n  chain killswitch {\n")
	fmt.Fprintf(b, "    type filter hook forward priority filter + 10; policy accept;\n\n")
	fmt.Fprintf(b, "    ip daddr @bypass4 return\n")
	if c.EnableIPv6 {
		fmt.Fprintf(b, "    ip6 daddr @bypass6 return\n")
	}
	if len(c.LANInterfaces) > 0 {
		quoted := make([]string, 0, len(c.LANInterfaces))
		for _, name := range c.LANInterfaces {
			quoted = append(quoted, strconv.Quote(name))
		}
		fmt.Fprintf(b, "    iifname != { %s } return\n", strings.Join(quoted, ", "))
	}
	fmt.Fprintf(b, "    # reached the forwarding path without being captured\n")
	fmt.Fprintf(b, "    counter drop\n")
	fmt.Fprintf(b, "  }\n")
}

// renderBypasses emits the checks that come before any capture.
func renderBypasses(b *strings.Builder, c Config, indent string) {
	fmt.Fprintf(b, "%s# traffic the cores originate, so a tunnel cannot swallow itself\n", indent)
	fmt.Fprintf(b, "%smeta mark %s return\n", indent, hex(c.BypassMark))
	fmt.Fprintf(b, "%s# established local traffic and anything explicitly excluded\n", indent)
	fmt.Fprintf(b, "%sip daddr @bypass4 return\n", indent)
	if c.EnableIPv6 {
		fmt.Fprintf(b, "%sip6 daddr @bypass6 return\n", indent)
	}
}

// renderLANFilter limits capture to the configured LAN interfaces.
func renderLANFilter(b *strings.Builder, c Config, indent string) {
	if len(c.LANInterfaces) == 0 {
		return
	}
	quoted := make([]string, 0, len(c.LANInterfaces))
	for _, name := range c.LANInterfaces {
		quoted = append(quoted, strconv.Quote(name))
	}
	fmt.Fprintf(b, "%s# only traffic arriving from the LAN\n", indent)
	fmt.Fprintf(b, "%siifname != { %s } return\n", indent, strings.Join(quoted, ", "))
}

// dedupe removes repeats while keeping first-seen order, so a server address
// that is also in a reserved range does not appear twice.
func dedupe(values []string) []string {
	seen := make(map[string]bool, len(values))
	out := make([]string, 0, len(values))
	for _, v := range values {
		v = strings.TrimSpace(v)
		if v == "" || seen[v] {
			continue
		}
		seen[v] = true
		out = append(out, v)
	}
	return out
}

func hex(v int) string { return fmt.Sprintf("0x%x", v) }

func itoa(v int) string { return strconv.Itoa(v) }
