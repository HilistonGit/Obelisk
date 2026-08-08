package singbox

import (
	"encoding/json"
	"testing"
)

// render builds a config and decodes it, so assertions are made against what the
// core would actually be handed rather than against the builder's internals.
func render(t *testing.T, c Config, opts Options) map[string]any {
	t.Helper()
	c.Options = opts
	data, err := BuildConfig(c)
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	var doc map[string]any
	if err := json.Unmarshal(data, &doc); err != nil {
		t.Fatalf("the config is not valid JSON: %v", err)
	}
	return doc
}

func proxyListConfig() Config {
	return Config{
		Groups: []Group{
			{Tag: "proxy", Type: "selector", Outbounds: []string{"node-a"}, Default: "node-a"},
		},
		Rules: []Rule{
			{IPIsPrivate: true, Outbound: TagDirect},
			{DomainSuffix: []string{"speedtest.net", ".speedtest.net"}, Outbound: "proxy"},
		},
		// A proxy list: unmatched traffic goes direct.
		FinalTag: TagDirect,
		ProxyTag: "proxy",
	}
}

// In a proxy list the tunnel carries only what was named, so sending every DNS
// query through it makes the whole network's name resolution depend on a tunnel
// that almost none of its traffic uses — and each lookup costs a round trip to
// another country before the connection it precedes even starts.
func TestDNSFallbackFollowsWhereTrafficGoes(t *testing.T) {
	opts := DefaultOptions()

	proxyList := render(t, proxyListConfig(), opts)
	if got := proxyList["dns"].(map[string]any)["final"]; got != "dns-direct" {
		t.Errorf("proxy-list resolves through %v, want dns-direct", got)
	}

	full := proxyListConfig()
	full.FinalTag = "proxy" // everything goes through the tunnel
	if got := render(t, full, opts)["dns"].(map[string]any)["final"]; got != "dns-proxy" {
		t.Errorf("full tunnel resolves through %v, want dns-proxy", got)
	}
}

// A name that will be reached through the proxy has to be resolved through it,
// or the answer comes from the wrong side of the world and the CDN sends the
// connection somewhere the proxy cannot usefully reach.
func TestProxiedDomainsResolveThroughTheProxy(t *testing.T) {
	doc := render(t, proxyListConfig(), DefaultOptions())
	dns := doc["dns"].(map[string]any)

	rules, _ := dns["rules"].([]any)
	found := false
	for _, r := range rules {
		rule := r.(map[string]any)
		if rule["server"] != "dns-proxy" {
			continue
		}
		suffixes, _ := rule["domain_suffix"].([]any)
		for _, s := range suffixes {
			if s == "speedtest.net" {
				found = true
			}
		}
	}
	if !found {
		t.Errorf("no DNS rule sends the proxied domain to dns-proxy: %v", rules)
	}
}

// A tunnel must not hand the system an IPv6 default route it did not have. Every
// dual-stack name would then be tried over a family with no way out, failing in
// milliseconds — which does not look like a network fault and disappears as soon
// as the tunnel is switched off.
func TestTunnelOffersNoIPv6WhenTheHostHasNone(t *testing.T) {
	opts := DefaultOptions()
	opts.IPv6 = false

	doc := render(t, proxyListConfig(), opts)
	tun := doc["inbounds"].([]any)[0].(map[string]any)

	for _, a := range tun["address"].([]any) {
		if containsColon(a.(string)) {
			t.Errorf("the tunnel carries %v with no IPv6 upstream to reach", a)
		}
	}
	if len(tun["address"].([]any)) == 0 {
		t.Error("the tunnel was left with no address at all")
	}

	if got := doc["dns"].(map[string]any)["strategy"]; got != "ipv4_only" {
		t.Errorf("DNS strategy is %v; handing out AAAA with no IPv6 route costs a timeout per connection", got)
	}
}

func TestTunnelKeepsIPv6WhenTheHostHasIt(t *testing.T) {
	opts := DefaultOptions()
	opts.IPv6 = true

	tun := render(t, proxyListConfig(), opts)["inbounds"].([]any)[0].(map[string]any)
	sawV6 := false
	for _, a := range tun["address"].([]any) {
		if containsColon(a.(string)) {
			sawV6 = true
		}
	}
	if !sawV6 {
		t.Error("IPv6 was dropped from a host that has it")
	}
}

// FakeIP throws away the answer the client already has and makes every
// connection — direct ones included — wait on a second resolution inside the
// core. When that resolution is unavailable the core dials 198.18.x.x literally
// and the connection goes nowhere.
func TestFakeIPIsOffByDefault(t *testing.T) {
	if DefaultOptions().FakeIP {
		t.Error("FakeIP is on by default")
	}

	doc := render(t, proxyListConfig(), DefaultOptions())
	dns := doc["dns"].(map[string]any)
	for _, s := range dns["servers"].([]any) {
		if s.(map[string]any)["type"] == "fakeip" {
			t.Error("a fakeip server was generated with FakeIP off")
		}
	}
}

func TestFakeIPStillWorksWhenAskedFor(t *testing.T) {
	opts := DefaultOptions()
	opts.FakeIP = true

	dns := render(t, proxyListConfig(), opts)["dns"].(map[string]any)
	sawServer := false
	for _, s := range dns["servers"].([]any) {
		if s.(map[string]any)["type"] == "fakeip" {
			sawServer = true
		}
	}
	if !sawServer {
		t.Error("FakeIP was requested and no fakeip server was generated")
	}
}
