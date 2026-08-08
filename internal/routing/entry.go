// Package routing turns what a user types into routing decisions.
//
// The entry point is ParseEntry, which accepts a single line of text and works
// out what it is: a full URL, a bare domain, a wildcard, an IP address, a
// subnet, or a keyword. That permissiveness is the point. Somebody who wants
// YouTube in the tunnel should be able to paste the address from their browser's
// URL bar, type "youtube.com", or type "*.googlevideo.com", and get a rule that
// works in all three cases without first learning what a domain suffix is.
package routing

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"
)

// Action is what happens to traffic that matches an entry.
type Action string

const (
	// ActionProxy sends the traffic through the tunnel.
	ActionProxy Action = "proxy"
	// ActionDirect keeps the traffic off the tunnel.
	ActionDirect Action = "direct"
	// ActionBlock drops it.
	ActionBlock Action = "block"
)

// ParseAction normalizes an action written by a user.
func ParseAction(s string) (Action, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "proxy", "vpn", "tunnel", "":
		return ActionProxy, nil
	case "direct", "bypass":
		return ActionDirect, nil
	case "block", "reject", "drop":
		return ActionBlock, nil
	default:
		return "", fmt.Errorf("unknown action %q (expected proxy, direct or block)", s)
	}
}

// MatchKind is how an entry is matched against a connection.
type MatchKind string

const (
	// KindDomainSuffix matches a domain and everything under it.
	KindDomainSuffix MatchKind = "domain-suffix"
	// KindDomainExact matches one domain and nothing below it.
	KindDomainExact MatchKind = "domain"
	// KindDomainKeyword matches any domain containing a substring.
	KindDomainKeyword MatchKind = "domain-keyword"
	// KindDomainRegex matches a domain against a regular expression.
	KindDomainRegex MatchKind = "domain-regex"
	// KindIPCIDR matches a destination address or subnet.
	KindIPCIDR MatchKind = "ip-cidr"
	// KindRuleSet references an external list, such as a geosite database.
	KindRuleSet MatchKind = "rule-set"
)

// Entry is one routing decision as the user expressed it.
type Entry struct {
	ID  string `json:"id"`
	Raw string `json:"raw"` // exactly what was typed, kept so the UI can show it back

	Kind  MatchKind `json:"kind"`
	Value string    `json:"value"` // normalized form actually matched against

	Action Action `json:"action"`

	// Target names a specific group or node for ActionProxy. Empty means the
	// default proxy group, which is what almost every entry wants.
	Target string `json:"target,omitempty"`

	// Sources scopes the entry to particular LAN clients, given as addresses or
	// subnets. Empty means every client. This is the one routing dimension a
	// router has and a desktop client does not: "the TV goes through the tunnel,
	// the work laptop does not" is only expressible here.
	Sources []string `json:"sources,omitempty"`

	Enabled bool   `json:"enabled"`
	Comment string `json:"comment,omitempty"`

	// Origin names the subscription that supplied the rule, empty for the
	// user's own. Provider rules are rebuilt from scratch on every refresh and
	// disappear with the subscription; the user's persist across changing
	// provider entirely, which is why the two are never mixed into one list.
	Origin string `json:"origin,omitempty"`

	// Note explains any normalization that changed the meaning of what was
	// typed. It exists because silently discarding part of a user's input is how
	// a rule ends up not doing what they believe it does.
	Note string `json:"note,omitempty"`
}

// explicitPrefixes lets a user override detection with the vocabulary used by
// Xray, Clash and sing-box rule files, so an existing list can be pasted in.
var explicitPrefixes = map[string]MatchKind{
	"full":     KindDomainExact,
	"domain":   KindDomainExact,
	"suffix":   KindDomainSuffix,
	"keyword":  KindDomainKeyword,
	"regexp":   KindDomainRegex,
	"regex":    KindDomainRegex,
	"ip":       KindIPCIDR,
	"ip-cidr":  KindIPCIDR,
	"geosite":  KindRuleSet,
	"geoip":    KindRuleSet,
	"rule-set": KindRuleSet,
	"ruleset":  KindRuleSet,
}

// ParseEntry works out what a single line of user input means.
//
// Detection order matters: the more specific a form is, the earlier it is
// tested, so that "10.0.0.0/8" is never mistaken for a domain and
// "https://example.com/watch?v=x" never becomes a keyword.
func ParseEntry(raw string) (*Entry, error) {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return nil, fmt.Errorf("empty entry")
	}
	// Trailing commas and semicolons survive most copy-paste; drop them rather
	// than turning them into part of a domain.
	trimmed = strings.Trim(trimmed, " \t,;\"'")
	if trimmed == "" {
		return nil, fmt.Errorf("empty entry")
	}

	e := &Entry{Raw: raw, Action: ActionProxy, Enabled: true}

	// 1. An explicit "kind:value" prefix wins over everything.
	if kind, value, ok := splitExplicitPrefix(trimmed); ok {
		if value == "" {
			return nil, fmt.Errorf("%q has a type prefix but no value", raw)
		}
		e.Kind = kind
		e.Value = value
		switch kind {
		case KindIPCIDR:
			normalized, err := normalizeIPCIDR(value)
			if err != nil {
				return nil, err
			}
			e.Value = normalized
		case KindDomainRegex, KindRuleSet:
			// Left verbatim: a regular expression and an external list name are
			// not domains and must not be folded or validated as such.
		case KindDomainKeyword:
			if err := validateKeyword(value); err != nil {
				return nil, err
			}
			e.Value = strings.ToLower(value)
		default:
			if err := validateDomain(strings.ToLower(value)); err != nil {
				return nil, err
			}
			e.Value = strings.ToLower(value)
		}
		e.assignID()
		return e, nil
	}

	// 2. A regular expression written between slashes.
	if len(trimmed) > 2 && strings.HasPrefix(trimmed, "/") && strings.HasSuffix(trimmed, "/") {
		e.Kind = KindDomainRegex
		e.Value = trimmed[1 : len(trimmed)-1]
		e.assignID()
		return e, nil
	}

	// 3. A subnet or a bare address.
	if strings.Contains(trimmed, "/") && !strings.Contains(trimmed, "://") {
		if _, _, err := net.ParseCIDR(trimmed); err == nil {
			e.Kind = KindIPCIDR
			e.Value = trimmed
			e.assignID()
			return e, nil
		}
	}
	if ip := net.ParseIP(strings.Trim(trimmed, "[]")); ip != nil {
		e.Kind = KindIPCIDR
		e.Value = singleHostCIDR(ip)
		e.Note = "single address, matched as " + e.Value
		e.assignID()
		return e, nil
	}

	// 4. A URL. Everything past the host is discarded, and the user is told so.
	if strings.Contains(trimmed, "://") {
		return parseURLEntry(e, trimmed)
	}

	// 5. A wildcard or leading-dot suffix.
	if rest, ok := strings.CutPrefix(trimmed, "*."); ok {
		return finishDomain(e, rest, KindDomainSuffix, "")
	}
	if rest, ok := strings.CutPrefix(trimmed, "."); ok {
		return finishDomain(e, rest, KindDomainSuffix, "")
	}

	// 6. A "host:port" pair. Routing happens per connection, and the port is a
	// separate dimension from the name, so it is dropped with an explanation.
	host := trimmed
	if h, port, err := net.SplitHostPort(trimmed); err == nil && isPort(port) {
		host = h
		e.Note = fmt.Sprintf("port %s ignored: routing matches the destination, not the port", port)
	}

	// 7. Anything with a dot is a domain; anything else is a keyword.
	if strings.Contains(host, ".") {
		return finishDomain(e, host, KindDomainSuffix, e.Note)
	}

	if err := validateKeyword(host); err != nil {
		return nil, err
	}
	e.Kind = KindDomainKeyword
	e.Value = strings.ToLower(host)
	if e.Note == "" {
		e.Note = "no dot in the value, so it is matched as a keyword anywhere in the domain"
	}
	e.assignID()
	return e, nil
}

// validateKeyword rejects text that could never appear inside a domain name.
//
// Without this, a stray sentence typed into the box becomes a keyword rule that
// looks perfectly valid in the list and can never match anything, because no
// domain contains a space. Failing loudly at the point of entry is the only
// moment the user is still looking at what they typed.
func validateKeyword(value string) error {
	if value == "" {
		return fmt.Errorf("empty keyword")
	}
	for _, r := range value {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z',
			r >= '0' && r <= '9', r == '-', r == '_', r == '.':
		case r >= 0x80:
		default:
			return fmt.Errorf("%q cannot be part of a domain name, so %q would never match anything",
				string(r), value)
		}
	}
	return nil
}

// parseURLEntry reduces a pasted URL to the host it addresses.
func parseURLEntry(e *Entry, raw string) (*Entry, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return nil, fmt.Errorf("%q is not a usable address: %w", raw, err)
	}
	host := u.Hostname()
	if host == "" {
		return nil, fmt.Errorf("%q has no host to route on", raw)
	}

	// The path is not merely unused, it is unusable: for an HTTPS connection the
	// router sees a destination and a TLS handshake, never a path. Saying so
	// prevents a user from believing they scoped a rule more narrowly than they
	// did.
	note := ""
	if u.Path != "" && u.Path != "/" || u.RawQuery != "" {
		note = "the path and query were dropped: an encrypted connection exposes only the host, so routing cannot see them"
	}

	if ip := net.ParseIP(host); ip != nil {
		e.Kind = KindIPCIDR
		e.Value = singleHostCIDR(ip)
		e.Note = strings.TrimSpace(note + " address matched as " + e.Value)
		e.assignID()
		return e, nil
	}
	return finishDomain(e, host, KindDomainSuffix, note)
}

// finishDomain validates and stores a domain-shaped value.
func finishDomain(e *Entry, host string, kind MatchKind, note string) (*Entry, error) {
	host = strings.ToLower(strings.Trim(strings.TrimSpace(host), "."))
	if host == "" {
		return nil, fmt.Errorf("%q has no domain to match on", e.Raw)
	}
	if err := validateDomain(host); err != nil {
		return nil, err
	}

	e.Kind = kind
	e.Value = host
	if note != "" {
		e.Note = strings.TrimSpace(note)
	}
	e.assignID()
	return e, nil
}

// splitExplicitPrefix recognizes the "kind:value" form.
func splitExplicitPrefix(s string) (MatchKind, string, bool) {
	prefix, value, ok := strings.Cut(s, ":")
	if !ok {
		return "", "", false
	}
	kind, known := explicitPrefixes[strings.ToLower(strings.TrimSpace(prefix))]
	if !known {
		return "", "", false
	}
	return kind, strings.TrimSpace(value), true
}

// validateDomain rejects values that cannot be a hostname. It is deliberately
// loose about internationalized names, which arrive already punycoded from a
// browser and are otherwise the user's problem.
func validateDomain(host string) error {
	if len(host) > 253 {
		return fmt.Errorf("%q is too long to be a domain", host)
	}
	for _, label := range strings.Split(host, ".") {
		if label == "" {
			return fmt.Errorf("%q has an empty label", host)
		}
		if len(label) > 63 {
			return fmt.Errorf("%q has a label longer than 63 characters", host)
		}
		for _, r := range label {
			switch {
			case r >= 'a' && r <= 'z', r >= '0' && r <= '9', r == '-', r == '_':
			case r >= 0x80: // already-punycoded or unicode; leave it alone
			default:
				return fmt.Errorf("%q contains %q, which is not valid in a domain", host, r)
			}
		}
	}
	return nil
}

// normalizeIPCIDR accepts an address or a subnet and returns a subnet.
func normalizeIPCIDR(value string) (string, error) {
	if _, _, err := net.ParseCIDR(value); err == nil {
		return value, nil
	}
	if ip := net.ParseIP(strings.Trim(value, "[]")); ip != nil {
		return singleHostCIDR(ip), nil
	}
	return "", fmt.Errorf("%q is neither an address nor a subnet", value)
}

// singleHostCIDR expresses one address as the subnet containing only itself.
func singleHostCIDR(ip net.IP) string {
	if ip.To4() != nil {
		return ip.String() + "/32"
	}
	return ip.String() + "/128"
}

func isPort(s string) bool {
	n, err := strconv.Atoi(s)
	return err == nil && n > 0 && n <= 65535
}

// assignID derives a stable identifier from what the entry actually matches, so
// that re-adding the same rule updates it instead of duplicating it.
func (e *Entry) assignID() {
	sum := sha256.Sum256([]byte(string(e.Kind) + "|" + e.Value + "|" + string(e.Action) + "|" + e.Target))
	e.ID = hex.EncodeToString(sum[:6])
}

// Reindex recomputes the entry's identifier after its action, target or scope
// has been changed by a caller.
func (e *Entry) Reindex() { e.assignID() }

// Describe renders the entry as a sentence, for confirming to a user what their
// input was understood to mean.
func (e *Entry) Describe() string {
	var what string
	switch e.Kind {
	case KindDomainSuffix:
		what = fmt.Sprintf("%s and every subdomain", e.Value)
	case KindDomainExact:
		what = fmt.Sprintf("exactly %s", e.Value)
	case KindDomainKeyword:
		what = fmt.Sprintf("any domain containing %q", e.Value)
	case KindDomainRegex:
		what = fmt.Sprintf("domains matching /%s/", e.Value)
	case KindIPCIDR:
		what = e.Value
	case KindRuleSet:
		what = fmt.Sprintf("the %s list", e.Value)
	default:
		what = e.Value
	}

	where := "through the tunnel"
	switch e.Action {
	case ActionDirect:
		where = "directly, bypassing the tunnel"
	case ActionBlock:
		where = "blocked"
	default:
		if e.Target != "" {
			where = "through " + e.Target
		}
	}
	return what + " → " + where
}

// ParseList parses a block of text, one entry per line, collecting per-line
// failures instead of abandoning the whole paste. Blank lines and comments are
// skipped, so a list copied from a config file works as-is.
func ParseList(text string, action Action) ([]*Entry, []LineError) {
	var (
		entries []*Entry
		errs    []LineError
	)
	for i, line := range strings.Split(text, "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") || strings.HasPrefix(trimmed, "//") {
			continue
		}
		entry, err := ParseEntry(trimmed)
		if err != nil {
			errs = append(errs, LineError{Line: i + 1, Text: trimmed, Err: err.Error()})
			continue
		}
		entry.Action = action
		entry.assignID()
		entries = append(entries, entry)
	}
	return entries, errs
}

// LineError reports one unusable line from a pasted list.
type LineError struct {
	Line int    `json:"line"`
	Text string `json:"text"`
	Err  string `json:"error"`
}
