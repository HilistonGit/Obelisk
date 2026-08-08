package subs

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/obelisk-project/obelisk/internal/model"
)

// Format names the payload shape a subscription turned out to have. It is
// reported back so the UI can tell the user what it actually received, which is
// the fastest way to diagnose a subscription URL that returns an error page.
type Format string

const (
	FormatURIList Format = "uri-list"
	FormatBase64  Format = "base64"
	FormatClash   Format = "clash"
	FormatSingBox Format = "sing-box"
	FormatXray    Format = "xray"
)

// SkipReason records one entry that could not be parsed. Subscriptions routinely
// contain a handful of malformed or unrecognized entries, and dropping them
// silently makes a short node list impossible to explain.
type SkipReason struct {
	Line string `json:"line"`
	Err  string `json:"error"`
}

// Result is the outcome of parsing one subscription payload.
type Result struct {
	Format  Format        `json:"format"`
	Nodes   []*model.Node `json:"nodes"`
	Skipped []SkipReason  `json:"skipped,omitempty"`

	// Rules are the routing decisions the subscription shipped with its
	// servers, when it is a format that can carry them. A plain list of share
	// links cannot, so this is nil for most subscriptions.
	Rules *ProviderRules `json:"rules,omitempty"`
}

// maxDecodeDepth bounds the base64-wrapping recursion. One level covers every
// real subscription; the bound exists so a hostile payload of nested base64
// cannot spin the parser.
const maxDecodeDepth = 3

// Parse detects the payload format and returns the nodes it contains.
func Parse(data []byte) (*Result, error) {
	return parseWithDepth(data, 0)
}

func parseWithDepth(data []byte, depth int) (*Result, error) {
	if depth > maxDecodeDepth {
		return nil, fmt.Errorf("payload is nested more than %d levels deep", maxDecodeDepth)
	}

	trimmed := bytes.TrimSpace(bytes.TrimPrefix(data, []byte{0xEF, 0xBB, 0xBF}))
	if len(trimmed) == 0 {
		return nil, fmt.Errorf("subscription payload is empty")
	}

	switch trimmed[0] {
	case '{', '[':
		body := trimmed
		if trimmed[0] == '[' {
			// An array is one of two quite different things. Panels commonly
			// serve a list of complete configurations, one per server, each with
			// its own routing section — and reading that as a list of outbounds
			// finds no servers at all. A list of bare outbounds is the other
			// shape, and gets wrapped so the parsers see what they expect.
			if docs, ok := documentList(trimmed); ok {
				return parseDocumentList(docs)
			}
			body = append(append([]byte(`{"outbounds":`), trimmed...), '}')
		}
		// Xray and sing-box both call the list "outbounds"; what an outbound
		// calls its kind tells them apart — Xray says "protocol", sing-box says
		// "type" — and only Xray has a top-level "routing" section.
		var doc map[string]any
		if err := json.Unmarshal(body, &doc); err == nil && looksLikeXray(doc) {
			nodes, skipped, rules, err := ParseXray(body)
			if err != nil {
				return nil, err
			}
			return &Result{Format: FormatXray, Nodes: nodes, Skipped: skipped, Rules: rules}, nil
		}

		nodes, skipped, rules, err := ParseSingBox(body)
		if err != nil {
			return nil, err
		}
		return &Result{Format: FormatSingBox, Nodes: nodes, Skipped: skipped, Rules: rules}, nil
	}

	if looksLikeClash(trimmed) {
		nodes, skipped, rules, err := ParseClash(trimmed)
		if err != nil {
			return nil, err
		}
		return &Result{Format: FormatClash, Nodes: nodes, Skipped: skipped, Rules: rules}, nil
	}

	// A payload with no scheme separator anywhere is almost certainly base64;
	// try to unwrap it before giving up on it as a link list.
	if !bytes.Contains(trimmed, []byte("://")) {
		if decoded, err := decodeBase64(stripWhitespace(string(trimmed))); err == nil {
			inner, err := parseWithDepth(decoded, depth+1)
			if err != nil {
				return nil, err
			}
			if depth == 0 {
				inner.Format = FormatBase64
			}
			return inner, nil
		}
	}

	nodes, skipped := parseURIList(string(trimmed))
	if len(nodes) == 0 && len(skipped) == 0 {
		return nil, fmt.Errorf("payload contains no recognizable share links")
	}
	return &Result{Format: FormatURIList, Nodes: nodes, Skipped: skipped}, nil
}

// parseURIList parses a newline-separated list of share links, tolerating blank
// lines and comments.
func parseURIList(text string) ([]*model.Node, []SkipReason) {
	var (
		nodes   []*model.Node
		skipped []SkipReason
	)
	for _, line := range strings.Split(text, "\n") {
		line = strings.TrimSpace(strings.TrimSuffix(line, "\r"))
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "//") {
			continue
		}
		n, err := ParseURI(line)
		if err != nil {
			skipped = append(skipped, SkipReason{Line: truncate(line, 120), Err: err.Error()})
			continue
		}
		nodes = append(nodes, n)
	}
	return nodes, skipped
}

// looksLikeClash reports whether the payload has a top-level "proxies:" key.
// Matching on the key rather than attempting a YAML parse avoids misreading a
// plain link list, which is also valid YAML.
func looksLikeClash(data []byte) bool {
	for _, line := range bytes.Split(data, []byte("\n")) {
		trimmed := bytes.TrimSpace(line)
		if len(trimmed) == 0 || trimmed[0] == '#' {
			continue
		}
		// A top-level key is unindented.
		if len(line) > 0 && (line[0] == ' ' || line[0] == '\t') {
			continue
		}
		if bytes.HasPrefix(trimmed, []byte("proxies:")) ||
			bytes.HasPrefix(trimmed, []byte("proxy-providers:")) {
			return true
		}
	}
	return false
}

// stripWhitespace removes every space and line break, which base64 payloads
// served as text files are frequently wrapped with.
func stripWhitespace(s string) string {
	return strings.Map(func(r rune) rune {
		switch r {
		case ' ', '\t', '\n', '\r':
			return -1
		}
		return r
	}, s)
}

// truncate shortens a string for display in an error list.
func truncate(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max] + "…"
}

// UserInfo is the quota and expiry metadata a panel reports in the
// "subscription-userinfo" response header.
type UserInfo struct {
	Upload   int64      `json:"upload"`
	Download int64      `json:"download"`
	Total    int64      `json:"total"`
	Expire   *time.Time `json:"expire,omitempty"`
}

// Used returns the total traffic consumed.
func (u *UserInfo) Used() int64 { return u.Upload + u.Download }

// Remaining returns the traffic left, or -1 when the plan is unmetered.
func (u *UserInfo) Remaining() int64 {
	if u.Total <= 0 {
		return -1
	}
	if r := u.Total - u.Used(); r > 0 {
		return r
	}
	return 0
}

// ParseUserInfo reads the "subscription-userinfo" header, whose format is
//
//	upload=0; download=1234; total=107374182400; expire=1735689600
//
// Every field is optional and panels are inconsistent about spacing, so absent
// or malformed fields are left at zero rather than failing the whole header.
func ParseUserInfo(header string) *UserInfo {
	header = strings.TrimSpace(header)
	if header == "" {
		return nil
	}

	info := &UserInfo{}
	found := false
	for _, field := range strings.Split(header, ";") {
		key, value, ok := strings.Cut(field, "=")
		if !ok {
			continue
		}
		key = strings.ToLower(strings.TrimSpace(key))
		value = strings.TrimSpace(value)

		switch key {
		case "upload":
			info.Upload, _ = strconv.ParseInt(value, 10, 64)
			found = true
		case "download":
			info.Download, _ = strconv.ParseInt(value, 10, 64)
			found = true
		case "total":
			info.Total, _ = strconv.ParseInt(value, 10, 64)
			found = true
		case "expire":
			if ts, err := strconv.ParseInt(value, 10, 64); err == nil && ts > 0 {
				t := time.Unix(ts, 0).UTC()
				info.Expire = &t
				found = true
			}
		}
	}
	if !found {
		return nil
	}
	return info
}

// documentList reports whether a JSON array holds complete configurations
// rather than bare outbounds, and returns them if so.
//
// The two are told apart by what the elements contain: a configuration has an
// "outbounds" list of its own, an outbound does not.
func documentList(data []byte) ([]json.RawMessage, bool) {
	var items []json.RawMessage
	if err := json.Unmarshal(data, &items); err != nil || len(items) == 0 {
		return nil, false
	}

	var first map[string]any
	if err := json.Unmarshal(items[0], &first); err != nil {
		return nil, false
	}
	if _, ok := first["outbounds"]; !ok {
		return nil, false
	}
	return items, true
}

// parseDocumentList parses a list of complete configurations and merges them.
//
// Every document contributes its servers. Their routing sections are normally
// identical copies of the provider's one list, so rules are merged by identity
// rather than concatenated — otherwise a subscription of twenty servers would
// produce twenty copies of every rule.
func parseDocumentList(items []json.RawMessage) (*Result, error) {
	out := &Result{Format: FormatXray, Rules: &ProviderRules{}}

	seenRules := map[string]bool{}
	seenSets := map[string]bool{}
	seenNodes := map[string]bool{}

	for i, item := range items {
		inner, err := parseWithDepth(item, maxDecodeDepth) // no further unwrapping
		if err != nil {
			out.Skipped = append(out.Skipped, SkipReason{
				Line: fmt.Sprintf("configuration %d", i+1),
				Err:  err.Error(),
			})
			continue
		}
		if i == 0 {
			out.Format = inner.Format
		}

		for _, n := range inner.Nodes {
			if seenNodes[n.ID] {
				continue
			}
			seenNodes[n.ID] = true
			out.Nodes = append(out.Nodes, n)
		}
		out.Skipped = append(out.Skipped, inner.Skipped...)

		if inner.Rules == nil {
			continue
		}
		for _, e := range inner.Rules.Entries {
			if seenRules[e.ID] {
				continue
			}
			seenRules[e.ID] = true
			out.Rules.Entries = append(out.Rules.Entries, e)
		}
		for _, rs := range inner.Rules.RuleSets {
			if seenSets[rs.Tag] {
				continue
			}
			seenSets[rs.Tag] = true
			out.Rules.RuleSets = append(out.Rules.RuleSets, rs)
		}
		if i == 0 {
			out.Rules.Skipped = inner.Rules.Skipped
		}
	}

	if len(out.Nodes) == 0 {
		return nil, fmt.Errorf("none of the %d configurations contained a usable server", len(items))
	}
	return out, nil
}
