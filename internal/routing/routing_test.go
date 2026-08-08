package routing

import (
	"testing"

	"github.com/obelisk-project/obelisk/internal/core/singbox"
)

func TestParseEntryDetectsWhatTheUserTyped(t *testing.T) {
	tests := []struct {
		name      string
		raw       string
		wantKind  MatchKind
		wantValue string
	}{
		{"bare domain", "youtube.com", KindDomainSuffix, "youtube.com"},
		{"subdomain", "www.youtube.com", KindDomainSuffix, "www.youtube.com"},
		{"wildcard", "*.googlevideo.com", KindDomainSuffix, "googlevideo.com"},
		{"leading dot", ".discord.gg", KindDomainSuffix, "discord.gg"},
		{"uppercase is folded", "YouTube.COM", KindDomainSuffix, "youtube.com"},

		{"url from a browser bar", "https://www.youtube.com/watch?v=dQw4w9WgXcQ", KindDomainSuffix, "www.youtube.com"},
		{"url without a path", "https://discord.com", KindDomainSuffix, "discord.com"},
		{"url with a port", "http://example.com:8080/x", KindDomainSuffix, "example.com"},

		{"single address", "142.250.150.100", KindIPCIDR, "142.250.150.100/32"},
		{"subnet", "142.250.0.0/15", KindIPCIDR, "142.250.0.0/15"},
		{"ipv6", "2a00:1450:4010::1", KindIPCIDR, "2a00:1450:4010::1/128"},
		{"ipv6 subnet", "2a00:1450::/32", KindIPCIDR, "2a00:1450::/32"},
		{"url pointing at an address", "https://1.1.1.1/help", KindIPCIDR, "1.1.1.1/32"},

		{"keyword without a dot", "torrent", KindDomainKeyword, "torrent"},
		{"explicit exact", "full:example.com", KindDomainExact, "example.com"},
		{"explicit keyword", "keyword:netflix", KindDomainKeyword, "netflix"},
		{"explicit geosite", "geosite:google", KindRuleSet, "google"},
		{"regex between slashes", "/^ads?\\..*/", KindDomainRegex, `^ads?\..*`},

		{"host and port", "example.com:443", KindDomainSuffix, "example.com"},
		{"trailing comma from a paste", "example.com,", KindDomainSuffix, "example.com"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			e, err := ParseEntry(tc.raw)
			if err != nil {
				t.Fatalf("ParseEntry(%q): %v", tc.raw, err)
			}
			if e.Kind != tc.wantKind {
				t.Errorf("Kind = %q, want %q", e.Kind, tc.wantKind)
			}
			if e.Value != tc.wantValue {
				t.Errorf("Value = %q, want %q", e.Value, tc.wantValue)
			}
			if !e.Enabled {
				t.Error("a new entry must be enabled")
			}
			if e.Raw != tc.raw {
				t.Errorf("Raw = %q, want the original input preserved", e.Raw)
			}
		})
	}
}

func TestParseEntryExplainsWhatItDiscarded(t *testing.T) {
	// A user who pastes a full URL has to be told that the path cannot be part
	// of the rule, or they will believe they scoped it more narrowly than they
	// did. The router never sees a path on an encrypted connection.
	e, err := ParseEntry("https://www.youtube.com/watch?v=dQw4w9WgXcQ")
	if err != nil {
		t.Fatalf("ParseEntry: %v", err)
	}
	if e.Note == "" {
		t.Error("dropping the path must be explained in Note")
	}

	withPort, err := ParseEntry("example.com:8443")
	if err != nil {
		t.Fatalf("ParseEntry: %v", err)
	}
	if withPort.Note == "" {
		t.Error("dropping the port must be explained in Note")
	}
}

func TestParseEntryRejectsNonsense(t *testing.T) {
	// A keyword containing a space can never match, because no domain contains
	// one; accepting it would put a dead rule in the list that looks fine.
	for _, raw := range []string{
		"", "   ", "http://", "domain:", "exa mple.com",
		"not a domain", "keyword:two words", "домен с пробелом",
		"domain:has space.com",
	} {
		if e, err := ParseEntry(raw); err == nil {
			t.Errorf("ParseEntry(%q) = %+v, want an error", raw, e)
		}
	}
}

func TestParseEntryAcceptsUnicodeKeywords(t *testing.T) {
	// Rejecting spaces must not also reject internationalized names, which
	// arrive already punycoded from a browser but may be typed as-is.
	for _, raw := range []string{"почта.рф", "münchen"} {
		if _, err := ParseEntry(raw); err != nil {
			t.Errorf("ParseEntry(%q): %v", raw, err)
		}
	}
}

func TestSuffixMatchingDoesNotLeakToSimilarDomains(t *testing.T) {
	// A bare suffix of "youtube.com" would also match "notyoutube.com", because
	// the core compares strings rather than domain labels. The compiler has to
	// emit the exact name plus a dot-prefixed suffix to mean what the user said.
	e, err := ParseEntry("youtube.com")
	if err != nil {
		t.Fatalf("ParseEntry: %v", err)
	}

	rules, err := Compile([]Entry{*e}, CompileOptions{ProxyTag: "proxy"})
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}
	if len(rules) != 1 {
		t.Fatalf("got %d rules, want 1", len(rules))
	}

	if len(rules[0].Domain) != 1 || rules[0].Domain[0] != "youtube.com" {
		t.Errorf("Domain = %v, want the exact name", rules[0].Domain)
	}
	if len(rules[0].DomainSuffix) != 1 || rules[0].DomainSuffix[0] != ".youtube.com" {
		t.Errorf("DomainSuffix = %v, want a dot-prefixed suffix", rules[0].DomainSuffix)
	}

	// And the matcher must agree with the config it generated.
	entries := []Entry{*e}
	for _, host := range []string{"youtube.com", "www.youtube.com", "a.b.youtube.com"} {
		d, err := Test(entries, host, "")
		if err != nil {
			t.Fatalf("Test(%q): %v", host, err)
		}
		if d.Matched == nil {
			t.Errorf("%s should match youtube.com", host)
		}
	}
	for _, host := range []string{"notyoutube.com", "youtube.com.evil.net"} {
		d, err := Test(entries, host, "")
		if err != nil {
			t.Fatalf("Test(%q): %v", host, err)
		}
		if d.Matched != nil {
			t.Errorf("%s must NOT match youtube.com", host)
		}
	}
}

func TestCompileMergesRunsButPreservesOrder(t *testing.T) {
	// Grouping every entry by action would reorder them, and order is meaning:
	// the specific block must be written above the general proxy to survive, and
	// the compiler must not move it.
	entries := mustParse(t,
		spec{"ads.youtube.com", ActionBlock},
		spec{"youtube.com", ActionProxy},
		spec{"googlevideo.com", ActionProxy},
		spec{"speedtest.net", ActionDirect},
		spec{"discord.com", ActionProxy},
	)

	rules, err := Compile(entries, CompileOptions{ProxyTag: "proxy", DirectTag: "direct"})
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}

	// Four runs: [block] [proxy proxy] [direct] [proxy].
	if len(rules) != 4 {
		t.Fatalf("got %d rules, want 4 runs: %+v", len(rules), rules)
	}
	if len(rules[1].Domain) != 2 {
		t.Errorf("the second run should have merged two domains, got %v", rules[1].Domain)
	}
	if rules[0].Outbound != singbox.TagBlock || rules[1].Outbound != "proxy" ||
		rules[2].Outbound != "direct" || rules[3].Outbound != "proxy" {
		t.Errorf("run order was not preserved: %q %q %q %q",
			rules[0].Outbound, rules[1].Outbound, rules[2].Outbound, rules[3].Outbound)
	}

	// The behaviour that ordering protects: the specific block still wins.
	d, err := Test(entries, "ads.youtube.com", "")
	if err != nil {
		t.Fatalf("Test: %v", err)
	}
	if d.Action != ActionBlock {
		t.Errorf("ads.youtube.com resolved to %q, want block — order was lost", d.Action)
	}
}

func TestFirstMatchWinsEvenWhenTheLaterRuleIsMoreSpecific(t *testing.T) {
	// This is the trap the linter exists for. Written in this order, the block
	// is unreachable, and the routing engine must not silently "fix" it by
	// guessing what the user meant.
	entries := mustParse(t,
		spec{"youtube.com", ActionProxy},
		spec{"ads.youtube.com", ActionBlock},
	)

	d, err := Test(entries, "ads.youtube.com", "")
	if err != nil {
		t.Fatalf("Test: %v", err)
	}
	if d.Action != ActionProxy {
		t.Errorf("got %q; first match must win, however unhelpful", d.Action)
	}

	conflicts := FindShadowed(entries)
	if len(conflicts) != 1 {
		t.Fatalf("got %d conflicts, want the dead rule reported: %+v", len(conflicts), conflicts)
	}
	if !conflicts[0].Harmful {
		t.Error("a shadow that changes the outcome must be marked harmful")
	}
	if conflicts[0].Index != 1 || conflicts[0].ShadowedBy != 0 {
		t.Errorf("conflict points at the wrong rules: %+v", conflicts[0])
	}
}

func TestFindShadowedIsQuietWhenRulesAreFine(t *testing.T) {
	entries := mustParse(t,
		spec{"ads.youtube.com", ActionBlock},
		spec{"youtube.com", ActionProxy},
		spec{"discord.com", ActionProxy},
		spec{"10.8.0.0/24", ActionDirect},
	)
	if c := FindShadowed(entries); len(c) != 0 {
		t.Errorf("correctly ordered rules must produce no warnings: %+v", c)
	}
}

func TestFindShadowedCoversSubnetsAndRedundancy(t *testing.T) {
	// A broad subnet listed first swallows a narrower one below it.
	subnets := mustParse(t,
		spec{"10.0.0.0/8", ActionDirect},
		spec{"10.8.0.0/24", ActionProxy},
	)
	conflicts := FindShadowed(subnets)
	if len(conflicts) != 1 || !conflicts[0].Harmful {
		t.Errorf("a contained subnet must be reported as harmful: %+v", conflicts)
	}

	// The same action twice is only redundant, not harmful.
	dupes := mustParse(t,
		spec{"youtube.com", ActionProxy},
		spec{"www.youtube.com", ActionProxy},
	)
	redundant := FindShadowed(dupes)
	if len(redundant) != 1 {
		t.Fatalf("got %d conflicts, want 1: %+v", len(redundant), redundant)
	}
	if redundant[0].Harmful {
		t.Error("a shadow that does not change the outcome must not be called harmful")
	}
}

func TestCompileSkipsDisabledEntries(t *testing.T) {
	entries := mustParse(t, spec{"youtube.com", ActionProxy}, spec{"discord.com", ActionProxy})
	entries[1].Enabled = false

	rules, err := Compile(entries, CompileOptions{ProxyTag: "proxy"})
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}
	if len(rules) != 1 || len(rules[0].Domain) != 1 {
		t.Errorf("a disabled entry must not reach the config: %+v", rules)
	}
}

func TestCompileDeduplicates(t *testing.T) {
	entries := mustParse(t,
		spec{"youtube.com", ActionProxy},
		spec{"YOUTUBE.COM", ActionProxy},
		spec{"https://youtube.com/feed", ActionProxy},
	)
	rules, err := Compile(entries, CompileOptions{ProxyTag: "proxy"})
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}
	if len(rules) != 1 || len(rules[0].Domain) != 1 {
		t.Errorf("the same domain typed three ways must collapse to one: %+v", rules)
	}
}

func TestIPRulesMatchSubnets(t *testing.T) {
	entries := mustParse(t, spec{"142.250.0.0/15", ActionProxy})

	d, err := Test(entries, "142.250.150.100", "")
	if err != nil {
		t.Fatalf("Test: %v", err)
	}
	if d.Matched == nil || d.Action != ActionProxy {
		t.Errorf("an address inside the subnet should be proxied, got %+v", d)
	}

	outside, err := Test(entries, "8.8.8.8", "")
	if err != nil {
		t.Fatalf("Test: %v", err)
	}
	if outside.Matched != nil {
		t.Errorf("8.8.8.8 is outside the subnet, got %+v", outside)
	}
}

func TestSourceScopedRules(t *testing.T) {
	// The routing dimension a router has and a desktop client does not.
	entries := mustParse(t, spec{"netflix.com", ActionProxy})
	entries[0].Sources = []string{"192.168.1.50"}

	onTV, err := Test(entries, "netflix.com", "192.168.1.50")
	if err != nil {
		t.Fatalf("Test: %v", err)
	}
	if onTV.Matched == nil {
		t.Error("the scoped client should match")
	}

	onLaptop, err := Test(entries, "netflix.com", "192.168.1.51")
	if err != nil {
		t.Fatalf("Test: %v", err)
	}
	if onLaptop.Matched != nil {
		t.Error("a client outside the scope must not match")
	}

	rules, err := Compile(entries, CompileOptions{ProxyTag: "proxy"})
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}
	if len(rules) != 1 || len(rules[0].SourceIPCIDR) != 1 {
		t.Errorf("the client scope must survive into the config: %+v", rules)
	}
}

func TestParseListCollectsPerLineErrors(t *testing.T) {
	list := `
# streaming
youtube.com
*.googlevideo.com

exa mple.com
142.250.0.0/15
// a comment
https://discord.com/channels/1/2
`
	entries, errs := ParseList(list, ActionProxy)
	if len(entries) != 4 {
		t.Errorf("got %d entries, want 4: %+v", len(entries), entries)
	}
	// One bad line must be reported, not silently swallow the whole paste.
	if len(errs) != 1 {
		t.Errorf("got %d line errors, want 1: %+v", len(errs), errs)
	}
	if len(errs) == 1 && errs[0].Line == 0 {
		t.Error("a line error must carry its line number")
	}
}

func TestTestFallsThroughWhenNothingMatches(t *testing.T) {
	entries := mustParse(t, spec{"youtube.com", ActionProxy})
	d, err := Test(entries, "example.org", "")
	if err != nil {
		t.Fatalf("Test: %v", err)
	}
	if d.Matched != nil || d.Index != -1 {
		t.Errorf("expected no match, got %+v", d)
	}
	if d.Explanation == "" {
		t.Error("even a non-match needs an explanation")
	}
}

func TestCompileRejectsMissingProxyTag(t *testing.T) {
	entries := mustParse(t, spec{"youtube.com", ActionProxy})
	if _, err := Compile(entries, CompileOptions{}); err == nil {
		t.Error("compiling without a proxy tag must fail rather than emit a dangling reference")
	}
}

type spec struct {
	raw    string
	action Action
}

func mustParse(t *testing.T, specs ...spec) []Entry {
	t.Helper()
	out := make([]Entry, 0, len(specs))
	for _, s := range specs {
		e, err := ParseEntry(s.raw)
		if err != nil {
			t.Fatalf("ParseEntry(%q): %v", s.raw, err)
		}
		e.Action = s.action
		e.Reindex()
		out = append(out, *e)
	}
	return out
}
