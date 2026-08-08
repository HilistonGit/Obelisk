package subs

import (
	"testing"

	"github.com/obelisk-project/obelisk/internal/routing"
)

func TestExtractSingBoxRules(t *testing.T) {
	doc := `{
	  "outbounds": [
	    {"type": "trojan", "tag": "a", "server": "a.example.com", "server_port": 443, "password": "pw"}
	  ],
	  "route": {
	    "rule_set": [
	      {"tag": "geosite-ads", "type": "remote", "format": "binary", "url": "https://example.com/ads.srs"},
	      {"tag": "local-list", "type": "local", "format": "binary", "path": "/etc/provider/list.srs"}
	    ],
	    "rules": [
	      {"action": "sniff"},
	      {"protocol": "dns", "action": "hijack-dns"},
	      {"domain_suffix": [".bank.local", "gov.example"], "outbound": "direct"},
	      {"ip_cidr": ["203.0.113.0/24"], "outbound": "direct"},
	      {"rule_set": ["geosite-ads"], "action": "reject"},
	      {"rule_set": ["local-list"], "outbound": "direct"},
	      {"domain": ["streaming.example"], "outbound": "proxy-group"}
	    ]
	  }
	}`

	_, _, rules, err := ParseSingBox([]byte(doc))
	if err != nil {
		t.Fatalf("ParseSingBox: %v", err)
	}
	if rules == nil {
		t.Fatal("no provider rules extracted")
	}

	byValue := map[string]routing.Entry{}
	for _, e := range rules.Entries {
		byValue[e.Value] = e
	}

	// The suffix arrives with a leading dot and must be stored bare, because the
	// compiler re-adds both the exact name and the dotted suffix.
	if e, ok := byValue["bank.local"]; !ok || e.Kind != routing.KindDomainSuffix || e.Action != routing.ActionDirect {
		t.Errorf("bank.local: %+v (present=%v)", e, ok)
	}
	if e := byValue["203.0.113.0/24"]; e.Action != routing.ActionDirect || e.Kind != routing.KindIPCIDR {
		t.Errorf("subnet rule: %+v", e)
	}
	// An outbound that is neither direct nor a reject means the provider wanted
	// it proxied, whatever they called the group.
	if e := byValue["streaming.example"]; e.Action != routing.ActionProxy {
		t.Errorf("unknown outbound should mean proxy, got %+v", e)
	}
	if e := byValue["geosite-ads"]; e.Action != routing.ActionBlock || e.Kind != routing.KindRuleSet {
		t.Errorf("reject rule set: %+v", e)
	}

	// Processing actions are not routing decisions and Obelisk installs its own.
	for _, e := range rules.Entries {
		if e.Value == "dns" || e.Kind == "" {
			t.Errorf("a processing action leaked into the rules: %+v", e)
		}
	}

	// A rule set defined as a local file on the provider's machine cannot be
	// used here, and a rule referring to it must be dropped rather than left
	// dangling — sing-box rejects a whole config over one unknown tag.
	if _, ok := byValue["local-list"]; ok {
		t.Error("a rule referring to an unusable local rule set was imported")
	}
	if len(rules.RuleSets) != 1 || rules.RuleSets[0].Tag != "geosite-ads" {
		t.Errorf("rule sets = %+v, want only the remote one", rules.RuleSets)
	}
	if len(rules.Skipped) < 2 {
		t.Errorf("both the local set and the rule using it should be reported: %+v", rules.Skipped)
	}
}

func TestExtractClashRules(t *testing.T) {
	doc := `
proxies:
  - name: "A"
    type: trojan
    server: a.example.com
    port: 443
    password: pw
rules:
  - DOMAIN-SUFFIX,bank.local,DIRECT
  - DOMAIN,exact.example,REJECT
  - DOMAIN-KEYWORD,tracker,REJECT
  - IP-CIDR,203.0.113.0/24,DIRECT,no-resolve
  - GEOSITE,category-ads,REJECT
  - MATCH,PROXY
`
	_, _, rules, err := ParseClash([]byte(doc))
	if err != nil {
		t.Fatalf("ParseClash: %v", err)
	}
	if rules == nil {
		t.Fatal("no provider rules extracted")
	}

	byValue := map[string]routing.Entry{}
	for _, e := range rules.Entries {
		byValue[e.Value] = e
	}

	if e := byValue["bank.local"]; e.Kind != routing.KindDomainSuffix || e.Action != routing.ActionDirect {
		t.Errorf("bank.local: %+v", e)
	}
	if e := byValue["exact.example"]; e.Kind != routing.KindDomainExact || e.Action != routing.ActionBlock {
		t.Errorf("exact.example: %+v", e)
	}
	if e := byValue["203.0.113.0/24"]; e.Kind != routing.KindIPCIDR {
		t.Errorf("the trailing no-resolve flag broke the parse: %+v", e)
	}

	// MATCH decides what happens to everything unmatched. That is the user's
	// setting, not a rule, and importing it would silently overwrite their
	// choice of split versus full tunnel.
	for _, e := range rules.Entries {
		if e.Value == "proxy" || e.Value == "" {
			t.Errorf("the catch-all was imported as a rule: %+v", e)
		}
	}
	// GEOSITE needs a database Obelisk does not carry; guessing a public
	// replacement would route traffic on someone else's definition.
	if len(rules.Skipped) != 1 {
		t.Errorf("GEOSITE should be reported as unimportable: %+v", rules.Skipped)
	}
}

func TestUserRulesBeatProviderRules(t *testing.T) {
	// The property the whole feature rests on. The provider says this domain
	// bypasses the tunnel; the user says it goes through. Compiling the user's
	// list first is what makes first-match-wins settle it their way — and the
	// user's rule is the one that survives changing provider.
	userRule, err := routing.ParseEntry("streaming.example")
	if err != nil {
		t.Fatalf("ParseEntry: %v", err)
	}
	userRule.Action = routing.ActionProxy
	userRule.Reindex()

	doc := `{
	  "outbounds": [{"type":"trojan","tag":"a","server":"a.example.com","server_port":443,"password":"pw"}],
	  "route": {"rules": [{"domain_suffix": ["streaming.example"], "outbound": "direct"}]}
	}`
	_, _, provider, err := ParseSingBox([]byte(doc))
	if err != nil {
		t.Fatalf("ParseSingBox: %v", err)
	}
	if provider.Count() != 1 {
		t.Fatalf("expected one provider rule, got %d", provider.Count())
	}

	merged := append([]routing.Entry{*userRule}, provider.Entries...)
	decision, err := routing.Test(merged, "streaming.example", "")
	if err != nil {
		t.Fatalf("Test: %v", err)
	}
	if decision.Action != routing.ActionProxy {
		t.Errorf("got %q; the user's rule must win over the provider's", decision.Action)
	}
	if decision.Index != 0 {
		t.Errorf("matched rule #%d, want the user's at position 0", decision.Index)
	}

	// And where the user said nothing, the provider's rule still applies.
	provider.Entries[0].Value = "bank.local"
	provider.Entries[0].Reindex()
	merged = append([]routing.Entry{*userRule}, provider.Entries...)

	decision, err = routing.Test(merged, "bank.local", "")
	if err != nil {
		t.Fatalf("Test: %v", err)
	}
	if decision.Action != routing.ActionDirect {
		t.Errorf("got %q; the provider's rule should apply where the user has none", decision.Action)
	}
}

func TestLinkListsCarryNoProviderRules(t *testing.T) {
	// A plain list of share links has nowhere to put routing, so nothing should
	// be invented for it.
	res, err := Parse([]byte("trojan://pw@a.example.com:443#A\n"))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if res.Rules.Count() != 0 {
		t.Errorf("a link list produced rules: %+v", res.Rules)
	}
}
