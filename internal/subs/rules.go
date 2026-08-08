package subs

import (
	"fmt"
	"strings"

	"github.com/obelisk-project/obelisk/internal/core/singbox"
	"github.com/obelisk-project/obelisk/internal/routing"
)

// ProviderRules are the routing decisions a subscription shipped alongside its
// servers.
//
// Panels routinely publish a curated list — local banking, government portals,
// the national CDN — that should bypass the tunnel. That knowledge is worth
// having, and Obelisk used to throw all of it away.
//
// It is imported as a distinct layer rather than merged into the user's rules,
// because the two have opposite lifetimes: provider rules are regenerated from
// scratch on every refresh and vanish when the subscription is removed, while
// the user's own must survive changing provider entirely. Keeping them separate
// is what lets the compiler put the user's first, where first-match-wins makes
// them win.
type ProviderRules struct {
	Entries  []routing.Entry   `json:"entries"`
	RuleSets []singbox.RuleSet `json:"rule_sets,omitempty"`
	Skipped  []SkipReason      `json:"skipped,omitempty"`
}

// Count returns how many usable rules were imported.
func (p *ProviderRules) Count() int {
	if p == nil {
		return 0
	}
	return len(p.Entries)
}

// extractSingBoxRules reads the routing section of a sing-box configuration.
func extractSingBoxRules(doc map[string]any) *ProviderRules {
	out := &ProviderRules{}

	route := mMap(doc, "route")
	if len(route) == 0 {
		return out
	}

	// Rule sets have to come across too. A rule referring to a set that was not
	// imported would leave a dangling tag, and sing-box rejects the whole
	// configuration over one — turning a helpful import into a dead router.
	known := map[string]bool{}
	for _, rs := range mList(route, "rule_set") {
		tag := mStr(rs, "tag")
		if tag == "" {
			continue
		}
		set := singbox.RuleSet{
			Tag:            tag,
			Type:           mStr(rs, "type"),
			Format:         mStr(rs, "format"),
			URL:            mStr(rs, "url"),
			UpdateInterval: mStr(rs, "update_interval"),
		}
		// A local set points at a file on the provider's machine, not ours.
		if set.Type == "local" || (set.Type == "remote" && set.URL == "") {
			out.Skipped = append(out.Skipped, SkipReason{
				Line: "rule_set " + tag,
				Err:  "refers to a local file that does not exist on this router",
			})
			continue
		}
		known[tag] = true
		out.RuleSets = append(out.RuleSets, set)
	}

	for i, rule := range mList(route, "rules") {
		// Actions like sniff, hijack-dns and resolve are processing steps, not
		// routing decisions, and Obelisk installs its own.
		if action := mStr(rule, "action"); action != "" && action != "route" && action != "reject" {
			continue
		}

		outbound := mStr(rule, "outbound")
		if outbound == "" && mStr(rule, "action") == "reject" {
			outbound = "block"
		}
		if outbound == "" {
			continue
		}

		entries, skipped := singBoxRuleEntries(rule, providerAction(outbound), known)
		if skipped != "" {
			out.Skipped = append(out.Skipped, SkipReason{
				Line: fmt.Sprintf("route.rules[%d]", i),
				Err:  skipped,
			})
		}
		out.Entries = append(out.Entries, entries...)
	}
	return out
}

// singBoxRuleEntries flattens one sing-box rule into individual entries.
//
// A rule matching four domains and two subnets becomes six entries. That is not
// a loss: the compiler merges consecutive entries sharing an action back into
// one rule, so the generated configuration is the same shape it started as,
// while each line stays individually inspectable and removable in the interface.
func singBoxRuleEntries(rule map[string]any, action routing.Action, knownSets map[string]bool) ([]routing.Entry, string) {
	var (
		out     []routing.Entry
		skipped string
	)

	add := func(kind routing.MatchKind, value string) {
		value = strings.TrimSpace(value)
		if value == "" {
			return
		}
		e := routing.Entry{
			Raw: value, Kind: kind, Value: strings.ToLower(value),
			Action: action, Enabled: true,
		}
		if kind == routing.KindDomainRegex || kind == routing.KindRuleSet {
			e.Value = value
		}
		e.Reindex()
		out = append(out, e)
	}

	for _, v := range mStrSlice(rule, "domain") {
		add(routing.KindDomainExact, v)
	}
	for _, v := range mStrSlice(rule, "domain_suffix") {
		// sing-box suffixes are often written with a leading dot; Obelisk stores
		// the bare name and re-adds both forms when it compiles.
		add(routing.KindDomainSuffix, strings.TrimPrefix(v, "."))
	}
	for _, v := range mStrSlice(rule, "domain_keyword") {
		add(routing.KindDomainKeyword, v)
	}
	for _, v := range mStrSlice(rule, "domain_regex") {
		add(routing.KindDomainRegex, v)
	}
	for _, v := range mStrSlice(rule, "ip_cidr") {
		add(routing.KindIPCIDR, v)
	}
	for _, v := range mStrSlice(rule, "rule_set") {
		if !knownSets[v] {
			skipped = fmt.Sprintf("refers to rule set %q, which the subscription did not define", v)
			continue
		}
		add(routing.KindRuleSet, v)
	}
	return out, skipped
}

// clashRuleTypes maps Clash rule verbs onto Obelisk's match kinds.
var clashRuleTypes = map[string]routing.MatchKind{
	"DOMAIN":         routing.KindDomainExact,
	"DOMAIN-SUFFIX":  routing.KindDomainSuffix,
	"DOMAIN-KEYWORD": routing.KindDomainKeyword,
	"DOMAIN-REGEX":   routing.KindDomainRegex,
	"IP-CIDR":        routing.KindIPCIDR,
	"IP-CIDR6":       routing.KindIPCIDR,
	"SRC-IP-CIDR":    routing.KindIPCIDR,
}

// extractClashRules reads the "rules" list of a Clash configuration.
func extractClashRules(doc map[string]any) *ProviderRules {
	out := &ProviderRules{}

	raw, ok := doc["rules"].([]any)
	if !ok {
		return out
	}

	for i, item := range raw {
		line, ok := item.(string)
		if !ok {
			continue
		}
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		parts := strings.Split(line, ",")
		for j := range parts {
			parts[j] = strings.TrimSpace(parts[j])
		}
		verb := strings.ToUpper(parts[0])

		// MATCH is the catch-all. Importing it would silently replace the user's
		// own choice of what happens to unmatched traffic, which is a setting,
		// not a rule.
		if verb == "MATCH" || verb == "FINAL" {
			continue
		}
		if len(parts) < 3 {
			continue
		}

		kind, known := clashRuleTypes[verb]
		if !known {
			// GEOSITE and GEOIP rely on databases mihomo has built in and
			// Obelisk does not; guessing a public replacement would route
			// traffic on someone else's idea of what the name means.
			out.Skipped = append(out.Skipped, SkipReason{
				Line: fmt.Sprintf("rules[%d]: %s", i, truncate(line, 60)),
				Err:  fmt.Sprintf("%s rules are not importable", verb),
			})
			continue
		}

		value := parts[1]
		if kind == routing.KindDomainSuffix {
			value = strings.TrimPrefix(value, ".")
		}

		e := routing.Entry{
			Raw: line, Kind: kind, Value: strings.ToLower(value),
			Action: providerAction(parts[2]), Enabled: true,
		}
		if kind == routing.KindDomainRegex {
			e.Value = parts[1]
		}
		if verb == "SRC-IP-CIDR" {
			// A source rule scopes who it applies to, not where traffic goes.
			e.Kind = routing.KindIPCIDR
			e.Sources = []string{parts[1]}
			e.Value = "0.0.0.0/0"
		}
		e.Reindex()
		out.Entries = append(out.Entries, e)
	}
	return out
}

// providerAction maps an outbound or policy name onto an Obelisk action.
//
// Anything that is not recognisably "direct" or "reject" means the provider
// wanted it proxied, whatever they named the group.
func providerAction(name string) routing.Action {
	switch strings.ToLower(strings.TrimSpace(name)) {
	case "direct", "direct-out":
		return routing.ActionDirect
	case "block", "reject", "reject-drop", "blackhole":
		return routing.ActionBlock
	default:
		return routing.ActionProxy
	}
}
