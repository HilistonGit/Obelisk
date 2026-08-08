package app

import "testing"

// The default direct resolver used to be udp://192.168.1.1 — the router's own
// address, which is where a router's resolver actually lives and is exactly the
// one place the core cannot reach. sing-box binds its outbound sockets to the
// default route's interface, so that packet is handed to the ISP and lost. The
// core could then resolve nothing at all: not the direct path, and not even the
// hostname of the proxy it was meant to tunnel through. DNS stopped for the
// whole LAN the moment the tunnel came up.
func TestDirectResolverMustNotBeThisMachine(t *testing.T) {
	unreachable := []string{
		"udp://127.0.0.1",
		"udp://127.0.0.53",
		"127.0.0.1",
		"udp://0.0.0.0",
		"",
	}
	for _, u := range unreachable {
		if reachableFromCore(u) {
			t.Errorf("%q was accepted as a direct resolver, but the core cannot reach it", u)
		}
	}

	reachable := []string{
		"udp://1.1.1.1",
		"udp://8.8.8.8:53",
		"https://1.1.1.1/dns-query",
		"tls://dns.google",
		"udp://192.168.1.1", // reachable in principle; only *this host's own* addresses are not
	}
	for _, u := range reachable {
		if !reachableFromCore(u) {
			t.Errorf("%q was rejected, but nothing is wrong with it here", u)
		}
	}
}

func TestDNSUpstreamHost(t *testing.T) {
	cases := map[string]string{
		"udp://1.1.1.1":              "1.1.1.1",
		"https://1.1.1.1/dns-query":  "1.1.1.1",
		"8.8.8.8":                    "8.8.8.8",
		"udp://8.8.8.8:53":           "8.8.8.8",
		"tls://dns.google":           "dns.google",
		"https://[2606:4700::1111]/": "2606:4700::1111",
		"udp://[::1]:53":             "::1",
		"":                           "",
	}
	for in, want := range cases {
		if got := dnsUpstreamHost(in); got != want {
			t.Errorf("dnsUpstreamHost(%q) = %q, want %q", in, got, want)
		}
	}
}

// An IPv6 literal must not be cut in half by the port-stripping.
func TestIPv6LiteralSurvivesHostExtraction(t *testing.T) {
	if got := dnsUpstreamHost("udp://2606:4700:4700::1111"); got != "2606:4700:4700::1111" {
		t.Errorf("bare IPv6 upstream mangled to %q", got)
	}
}
