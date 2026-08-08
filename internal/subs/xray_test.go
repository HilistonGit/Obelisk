package subs

import (
	"strings"
	"testing"

	"github.com/obelisk-project/obelisk/internal/routing"
)

// The document below has the shape a panel serves to a recognised client: an
// Xray configuration whose routing section is the provider's own list of what
// should bypass the tunnel. The same URL returns a bare list of share links to a
// client sending a different User-Agent, which is why Obelisk once concluded
// that such providers shipped no routing rules at all.
const realXrayConfig = `{
  "outbounds": [
    {"protocol":"trojan","tag":"proxy",
     "settings":{"servers":[{"address":"node4.example-vpn.net","password":"secret","port":443}]},
     "streamSettings":{"network":"ws","security":"tls",
       "tlsSettings":{"alpn":["http/1.1"],"fingerprint":"firefox","serverName":"node4.example-vpn.net"},
       "wsSettings":{"headers":{"Host":"node4.example-vpn.net"},"path":"/api/v2/push"}}},
    {"protocol":"freedom","tag":"direct"},
    {"protocol":"blackhole","tag":"block"}
  ],
  "remarks": "RU-11 | Trojan | Example VPN",
  "routing": {
    "domainStrategy": "IPIfNonMatch",
    "rules": [
      {"outboundTag":"direct","protocol":["bittorrent"],"type":"field"},
      {"domain":["geosite:category-ru"],"outboundTag":"direct","type":"field"},
      {"domain":["domain:sberbank.ru","domain:gosuslugi.ru","full:ya.ru"],"outboundTag":"direct","type":"field"},
      {"ip":["geoip:ru","203.0.113.0/24"],"outboundTag":"direct","type":"field"},
      {"domain":["regexp:.*\\.ru$"],"outboundTag":"direct","type":"field"},
      {"network":"tcp,udp","outboundTag":"proxy","type":"field"}
    ]
  }
}`

func TestParseRealXraySubscription(t *testing.T) {
	res, err := Parse([]byte(realXrayConfig))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if res.Format != FormatXray {
		t.Errorf("Format = %q, want xray", res.Format)
	}

	// freedom and blackhole are Xray's own direct and block outbounds, not servers.
	if len(res.Nodes) != 1 {
		t.Fatalf("got %d nodes, want 1: %+v", len(res.Nodes), res.Nodes)
	}
	n := res.Nodes[0]
	if n.Server != "node4.example-vpn.net" || n.Port != 443 || string(n.Protocol) != "trojan" {
		t.Errorf("node = %s:%d %s", n.Server, n.Port, n.Protocol)
	}
	if n.DisplayName() != "RU-11 | Trojan | Example VPN" {
		t.Errorf("name = %q, want the remarks", n.DisplayName())
	}
	if string(n.Transport.Type) != "ws" || n.Transport.Path != "/api/v2/push" {
		t.Errorf("transport = %+v", n.Transport)
	}
	if len(n.Transport.Host) != 1 || n.Transport.Host[0] != "node4.example-vpn.net" {
		t.Errorf("ws Host header lost: %+v", n.Transport.Host)
	}
	if n.TLS.Fingerprint != "firefox" || n.TLS.SNI != "node4.example-vpn.net" {
		t.Errorf("tls = %+v", n.TLS)
	}

	if res.Rules == nil || res.Rules.Count() == 0 {
		t.Fatal("no provider rules imported from a config that plainly has them")
	}
	byValue := map[string]routing.Entry{}
	for _, e := range res.Rules.Entries {
		byValue[e.Value] = e
	}

	// Xray's prefixes are a language of their own and each means something
	// different; getting them wrong would route the wrong traffic.
	if e := byValue["sberbank.ru"]; e.Kind != routing.KindDomainSuffix || e.Action != routing.ActionDirect {
		t.Errorf("domain: prefix means the name and everything under it, got %+v", e)
	}
	if e := byValue["ya.ru"]; e.Kind != routing.KindDomainExact {
		t.Errorf("full: prefix means exactly that name, got %+v", e)
	}
	if e := byValue[`.*\.ru$`]; e.Kind != routing.KindDomainRegex {
		t.Errorf("regexp: prefix means a regular expression, got %+v", e)
	}
	if e := byValue["203.0.113.0/24"]; e.Kind != routing.KindIPCIDR {
		t.Errorf("a bare subnet should stay a subnet, got %+v", e)
	}

	// geosite and geoip become rule sets pointing at the same upstream lists
	// Xray's own databases are built from.
	for _, tag := range []string{"geosite-category-ru", "geoip-ru"} {
		e, ok := byValue[tag]
		if !ok || e.Kind != routing.KindRuleSet {
			t.Errorf("%s was not imported as a rule set: %+v", tag, e)
		}
	}
	if len(res.Rules.RuleSets) != 2 {
		t.Fatalf("got %d rule sets, want 2: %+v", len(res.Rules.RuleSets), res.Rules.RuleSets)
	}
	for _, rs := range res.Rules.RuleSets {
		if !strings.HasPrefix(rs.URL, "https://raw.githubusercontent.com/SagerNet/") {
			t.Errorf("rule set points somewhere unexpected: %s", rs.URL)
		}
		// The lists are fetched through the tunnel, so a network that blocks the
		// source cannot leave the router with no rules at all.
		if rs.DownloadDetour != "proxy" {
			t.Errorf("rule set %s is not fetched through the tunnel", rs.Tag)
		}
	}

	// The catch-all decides what happens to everything unmatched, which is the
	// user's own setting, and a protocol match has no equivalent here.
	for _, e := range res.Rules.Entries {
		if e.Value == "proxy" || e.Value == "bittorrent" {
			t.Errorf("a rule that should have been skipped was imported: %+v", e)
		}
	}
	if len(res.Rules.Skipped) != 1 {
		t.Errorf("the bittorrent rule should be reported as skipped: %+v", res.Rules.Skipped)
	}
}

func TestXrayAndSingBoxAreToldApart(t *testing.T) {
	// Both call the list "outbounds"; only what an outbound calls its kind
	// distinguishes them.
	singbox := `{"outbounds":[{"type":"trojan","tag":"a","server":"a.example.com","server_port":443,"password":"pw"}]}`
	res, err := Parse([]byte(singbox))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if res.Format != FormatSingBox {
		t.Errorf("Format = %q, want sing-box", res.Format)
	}
}
