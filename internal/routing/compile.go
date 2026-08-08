package routing

import (
	"fmt"
	"strings"

	"github.com/obelisk-project/obelisk/internal/core/singbox"
)

// CompileOptions says where each action sends traffic.
type CompileOptions struct {
	// ProxyTag receives ActionProxy entries that name no specific target. It is
	// normally the selector group holding every node.
	ProxyTag string

	// DirectTag receives ActionDirect entries.
	DirectTag string
}

// Compile turns an ordered list of entries into sing-box routing rules.
//
// Rules are evaluated in order and the first match wins, so the order the user
// put their entries in is the order the rules must keep. That rules out the
// obvious optimization of bucketing every domain by action, because it would
// silently reorder them: a general "youtube.com → tunnel" placed before a
// specific "ads.youtube.com → block" must keep beating it, and bucketing would
// invert that.
//
// What is safe is merging *runs* — consecutive entries that share an action, a
// target and a client scope produce identical routing behaviour whatever their
// internal order, so they collapse into one rule. In practice a user's list is
// mostly one long run of "send this to the tunnel", so a hundred domains become
// a single rule while the semantics stay exactly as written.
func Compile(entries []Entry, opts CompileOptions) ([]singbox.Rule, error) {
	if opts.ProxyTag == "" {
		return nil, fmt.Errorf("routing: no proxy tag configured")
	}
	if opts.DirectTag == "" {
		opts.DirectTag = singbox.TagDirect
	}

	var (
		rules   []singbox.Rule
		current *group
	)

	flush := func() error {
		if current == nil {
			return nil
		}
		rule, err := current.render(opts)
		if err != nil {
			return err
		}
		if rule != nil {
			rules = append(rules, *rule)
		}
		current = nil
		return nil
	}

	for i := range entries {
		e := entries[i]
		if !e.Enabled {
			continue
		}

		key := groupKey(e)
		if current != nil && current.key != key {
			if err := flush(); err != nil {
				return nil, err
			}
		}
		if current == nil {
			current = &group{
				key:     key,
				action:  e.Action,
				target:  e.Target,
				sources: e.Sources,
			}
		}
		if err := current.add(e); err != nil {
			return nil, err
		}
	}
	if err := flush(); err != nil {
		return nil, err
	}
	return rules, nil
}

// groupKey identifies entries that may share one rule.
func groupKey(e Entry) string {
	return string(e.Action) + "\x00" + e.Target + "\x00" + strings.Join(e.Sources, ",")
}

// group accumulates one run of compatible entries.
type group struct {
	key     string
	action  Action
	target  string
	sources []string

	domains  []string
	suffixes []string
	keywords []string
	regexes  []string
	ipcidrs  []string
	rulesets []string
}

// add folds one entry into the group.
func (g *group) add(e Entry) error {
	switch e.Kind {
	case KindDomainExact:
		g.domains = append(g.domains, e.Value)

	case KindDomainSuffix:
		// "youtube.com" as a bare suffix would also match "notyoutube.com",
		// because sing-box compares strings rather than domain labels. The
		// faithful expression of "this domain and everything under it" is the
		// exact name plus a dot-prefixed suffix.
		g.domains = append(g.domains, e.Value)
		g.suffixes = append(g.suffixes, "."+e.Value)

	case KindDomainKeyword:
		g.keywords = append(g.keywords, e.Value)

	case KindDomainRegex:
		g.regexes = append(g.regexes, e.Value)

	case KindIPCIDR:
		g.ipcidrs = append(g.ipcidrs, e.Value)

	case KindRuleSet:
		g.rulesets = append(g.rulesets, e.Value)

	default:
		return fmt.Errorf("routing: unknown match kind %q", e.Kind)
	}
	return nil
}

// render produces the sing-box rule for the group.
func (g *group) render(opts CompileOptions) (*singbox.Rule, error) {
	rule := singbox.Rule{
		Domain:        dedupe(g.domains),
		DomainSuffix:  dedupe(g.suffixes),
		DomainKeyword: dedupe(g.keywords),
		DomainRegex:   dedupe(g.regexes),
		IPCIDR:        dedupe(g.ipcidrs),
		RuleSet:       dedupe(g.rulesets),
		SourceIPCIDR:  dedupe(g.sources),
	}
	if len(rule.Domain) == 0 && len(rule.DomainSuffix) == 0 && len(rule.DomainKeyword) == 0 &&
		len(rule.DomainRegex) == 0 && len(rule.IPCIDR) == 0 && len(rule.RuleSet) == 0 {
		return nil, nil
	}

	switch g.action {
	case ActionProxy:
		rule.Outbound = opts.ProxyTag
		if g.target != "" {
			rule.Outbound = g.target
		}
	case ActionDirect:
		rule.Outbound = opts.DirectTag
	case ActionBlock:
		rule.Outbound = singbox.TagBlock
	default:
		return nil, fmt.Errorf("routing: unknown action %q", g.action)
	}
	return &rule, nil
}

// dedupe removes repeats while preserving first-seen order, so that a list
// pasted twice does not double the size of the generated config.
func dedupe(values []string) []string {
	if len(values) == 0 {
		return nil
	}
	seen := make(map[string]bool, len(values))
	out := make([]string, 0, len(values))
	for _, v := range values {
		if v == "" || seen[v] {
			continue
		}
		seen[v] = true
		out = append(out, v)
	}
	return out
}

// Summary counts what a rule list contains, for display in the UI and CLI.
type Summary struct {
	Total    int `json:"total"`
	Enabled  int `json:"enabled"`
	Proxied  int `json:"proxied"`
	Direct   int `json:"direct"`
	Blocked  int `json:"blocked"`
	Domains  int `json:"domains"`
	Networks int `json:"networks"`
}

// Summarize counts the entries by action and kind.
func Summarize(entries []Entry) Summary {
	var s Summary
	s.Total = len(entries)
	for _, e := range entries {
		if !e.Enabled {
			continue
		}
		s.Enabled++
		switch e.Action {
		case ActionProxy:
			s.Proxied++
		case ActionDirect:
			s.Direct++
		case ActionBlock:
			s.Blocked++
		}
		if e.Kind == KindIPCIDR {
			s.Networks++
		} else {
			s.Domains++
		}
	}
	return s
}
