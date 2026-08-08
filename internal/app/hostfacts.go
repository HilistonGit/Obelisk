package app

import (
	"net"
	"strings"
)

// This file answers two questions about the machine Obelisk is running on that
// the generated configuration cannot be correct without. Both were learned the
// hard way, on a live router, from a symptom that looked nothing like its cause.

// hasGlobalIPv6 reports whether this host has IPv6 connectivity of its own.
//
// The tunnel must not offer IPv6 that the system does not otherwise have. A tun
// interface carrying an IPv6 address installs an IPv6 default route where there
// was none, and from that instant every dual-stack name is attempted over IPv6
// first — into a tunnel whose direct outbound has no IPv6 path. The connection
// fails in milliseconds rather than timing out, so it does not even look like a
// network problem, and it vanishes the moment the tunnel is switched off.
//
// Link-local and unique-local addresses do not count: fe80::/10 never leaves the
// segment, and fc00::/7 is private space that a router hands out to its own LAN
// — including, in this case, the address on Obelisk's own tunnel.
func hasGlobalIPv6() bool {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return false
	}
	for _, a := range addrs {
		var ip net.IP
		switch v := a.(type) {
		case *net.IPNet:
			ip = v.IP
		case *net.IPAddr:
			ip = v.IP
		}
		if ip == nil || ip.To4() != nil {
			continue
		}
		if ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsPrivate() {
			continue
		}
		if ip.IsGlobalUnicast() {
			return true
		}
	}
	return false
}

// reachableFromCore reports whether the core could actually talk to this DNS
// upstream.
//
// sing-box binds its outbound sockets to the interface of the default route, so
// that its own connections cannot re-enter the tunnel it is building. The cost
// is that any address which is *not* reachable over that interface becomes
// unreachable to it — including every address on the router itself and on the
// LAN behind it.
//
// This is not a hypothetical. Obelisk's default direct resolver used to be
// udp://192.168.1.1, the router's own address, chosen because that is where the
// resolver a router runs actually lives. From the core's point of view a packet
// addressed there leaves via the WAN and is delivered to the ISP, where a
// private address goes nowhere. The core could then resolve nothing at all: not
// the names on the direct path, and not even the hostname of the proxy server it
// was supposed to tunnel through. Every connection failed, DNS on the whole LAN
// stopped, and the only visible symptom was that the internet broke when the VPN
// was turned on.
func reachableFromCore(upstream string) bool {
	host := dnsUpstreamHost(upstream)
	if host == "" {
		return false
	}
	ip := net.ParseIP(host)
	if ip == nil {
		// A hostname has to be resolved to be used, which is the very thing this
		// upstream is needed for. Treat it as usable and let the core report it.
		return true
	}
	if ip.IsLoopback() || ip.IsUnspecified() {
		return false
	}
	return !isLocalAddress(ip)
}

// isLocalAddress reports whether the address belongs to this machine.
func isLocalAddress(ip net.IP) bool {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return false
	}
	for _, a := range addrs {
		if n, ok := a.(*net.IPNet); ok && n.IP.Equal(ip) {
			return true
		}
	}
	return false
}

// dnsUpstreamHost pulls the host out of a DNS upstream URL, which may be a bare
// address, a scheme-prefixed one, or a DoH URL with a path.
func dnsUpstreamHost(upstream string) string {
	s := strings.TrimSpace(upstream)
	if s == "" {
		return ""
	}
	if i := strings.Index(s, "://"); i >= 0 {
		s = s[i+3:]
	}
	if i := strings.IndexByte(s, '/'); i >= 0 {
		s = s[:i]
	}
	// Strip a port, taking care not to cut an IPv6 literal in half.
	if strings.HasPrefix(s, "[") {
		if i := strings.IndexByte(s, ']'); i >= 0 {
			return s[1:i]
		}
		return strings.TrimPrefix(s, "[")
	}
	if strings.Count(s, ":") == 1 {
		s = s[:strings.IndexByte(s, ':')]
	}
	return s
}

// fallbackDirectResolver is used when the configured one cannot be reached from
// the core. It is a public resolver rather than the router's own, because the
// router's own is exactly the address that cannot work here.
const fallbackDirectResolver = "udp://1.1.1.1"
