package routing

import (
	"fmt"
	"net"
	"regexp"
	"strings"
)

// Decision is the outcome of testing one destination against a rule list.
type Decision struct {
	// Matched is the entry that decided it, or nil when nothing matched.
	Matched *Entry `json:"matched,omitempty"`

	// Index is the position of the matching entry in the list, or -1.
	Index int `json:"index"`

	Action Action `json:"action"`
	Target string `json:"target,omitempty"`

	// Explanation says in words why this entry won.
	Explanation string `json:"explanation"`
}

// Test reports what would happen to a destination under the given rules.
//
// This mirrors the matching sing-box will perform, and exists so a user can find
// out what their rules do before committing them to a router that the whole
// household depends on. Rules are checked in order and the first match wins,
// exactly as the generated configuration behaves.
//
// The destination may be a domain, an address, or a URL; source is the client
// address and may be empty.
func Test(entries []Entry, destination, source string) (*Decision, error) {
	host, isIP, err := normalizeDestination(destination)
	if err != nil {
		return nil, err
	}

	var clientIP net.IP
	if source != "" {
		if clientIP = net.ParseIP(strings.TrimSpace(source)); clientIP == nil {
			return nil, fmt.Errorf("%q is not a client address", source)
		}
	}

	for i := range entries {
		e := entries[i]
		if !e.Enabled {
			continue
		}
		if !sourceMatches(e, clientIP) {
			continue
		}

		ok, why := entryMatches(e, host, isIP)
		if !ok {
			continue
		}
		return &Decision{
			Matched:     &entries[i],
			Index:       i,
			Action:      e.Action,
			Target:      e.Target,
			Explanation: why,
		}, nil
	}

	return &Decision{
		Index:       -1,
		Action:      "",
		Explanation: "no rule matched; the default route decides",
	}, nil
}

// entryMatches applies one entry's matcher, mirroring sing-box's semantics.
func entryMatches(e Entry, host string, isIP bool) (bool, string) {
	switch e.Kind {
	case KindIPCIDR:
		if !isIP {
			return false, ""
		}
		_, network, err := net.ParseCIDR(e.Value)
		if err != nil {
			return false, ""
		}
		ip := net.ParseIP(host)
		if ip != nil && network.Contains(ip) {
			return true, fmt.Sprintf("%s is inside %s", host, e.Value)
		}
		return false, ""

	case KindDomainExact:
		if !isIP && host == e.Value {
			return true, fmt.Sprintf("%s is exactly %s", host, e.Value)
		}
		return false, ""

	case KindDomainSuffix:
		if isIP {
			return false, ""
		}
		// The compiled rule emits the exact name plus a dot-prefixed suffix;
		// both halves are checked here so the test agrees with the config.
		if host == e.Value {
			return true, fmt.Sprintf("%s is %s itself", host, e.Value)
		}
		if strings.HasSuffix(host, "."+e.Value) {
			return true, fmt.Sprintf("%s is a subdomain of %s", host, e.Value)
		}
		return false, ""

	case KindDomainKeyword:
		if !isIP && strings.Contains(host, e.Value) {
			return true, fmt.Sprintf("%s contains %q", host, e.Value)
		}
		return false, ""

	case KindDomainRegex:
		if isIP {
			return false, ""
		}
		re, err := regexp.Compile(e.Value)
		if err != nil {
			return false, ""
		}
		if re.MatchString(host) {
			return true, fmt.Sprintf("%s matches /%s/", host, e.Value)
		}
		return false, ""

	case KindRuleSet:
		// External lists are resolved by the core at runtime, not here; saying
		// "maybe" would be worse than admitting the test cannot see inside them.
		return false, ""
	}
	return false, ""
}

// sourceMatches reports whether a client falls in an entry's scope.
func sourceMatches(e Entry, client net.IP) bool {
	if len(e.Sources) == 0 {
		return true
	}
	if client == nil {
		return false
	}
	for _, s := range e.Sources {
		if _, network, err := net.ParseCIDR(s); err == nil {
			if network.Contains(client) {
				return true
			}
			continue
		}
		if ip := net.ParseIP(s); ip != nil && ip.Equal(client) {
			return true
		}
	}
	return false
}

// normalizeDestination reduces what a user typed to a bare host or address.
func normalizeDestination(destination string) (host string, isIP bool, err error) {
	d := strings.TrimSpace(destination)
	if d == "" {
		return "", false, fmt.Errorf("no destination given")
	}

	entry, err := ParseEntry(d)
	if err != nil {
		return "", false, err
	}
	switch entry.Kind {
	case KindIPCIDR:
		addr, _, _ := strings.Cut(entry.Value, "/")
		return addr, true, nil
	default:
		return entry.Value, false, nil
	}
}
