// Package subs turns subscription payloads and share links into normalized
// model.Node values. It is the only package in Obelisk that knows what a
// "vmess://" link or a Clash YAML file looks like.
//
// Parsers here are deliberately permissive. Subscriptions in the wild are
// produced by dozens of panels with inconsistent escaping, mixed base64
// alphabets and optional padding, so a parser that insists on the specification
// would reject links that every real client accepts. The rule applied throughout
// is: accept anything that can be understood unambiguously, and reject only when
// the result would be a node that cannot possibly connect.
package subs

import (
	"encoding/base64"
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"

	"github.com/obelisk-project/obelisk/internal/model"
)

// ParseURI parses a single share link into a normalized node.
func ParseURI(raw string) (*model.Node, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil, fmt.Errorf("empty link")
	}

	scheme, _, ok := strings.Cut(raw, "://")
	if !ok {
		return nil, fmt.Errorf("not a share link: no scheme separator")
	}

	var (
		n   *model.Node
		err error
	)
	switch strings.ToLower(scheme) {
	case "vless":
		n, err = parseVLESS(raw)
	case "vmess":
		n, err = parseVMess(raw)
	case "trojan", "trojan-go":
		n, err = parseTrojan(raw)
	case "ss":
		n, err = parseShadowsocks(raw)
	case "ssr":
		n, err = parseShadowsocksR(raw)
	case "hysteria", "hy":
		n, err = parseHysteria(raw)
	case "hysteria2", "hy2":
		n, err = parseHysteria2(raw)
	case "tuic":
		n, err = parseTUIC(raw)
	case "anytls":
		n, err = parseAnyTLS(raw)
	case "socks", "socks5", "socks4", "socks4a":
		n, err = parseSOCKS(raw)
	case "http", "https":
		n, err = parseHTTPProxy(raw)
	case "ssh":
		n, err = parseSSH(raw)
	case "wireguard", "wg":
		n, err = parseWireGuard(raw)
	default:
		return nil, fmt.Errorf("unsupported scheme %q", scheme)
	}
	if err != nil {
		return nil, err
	}

	n.Raw = raw
	if err := n.Validate(); err != nil {
		return nil, err
	}
	n.AssignID()
	return n, nil
}

// splitFragment separates the trailing "#name" from a share link without going
// through url.Parse. Share links frequently carry raw UTF-8 and unescaped
// punctuation in the fragment, which makes strict URL parsing fail on links that
// every client in the wild accepts.
func splitFragment(raw string) (body, name string) {
	body, frag, ok := strings.Cut(raw, "#")
	if !ok {
		return raw, ""
	}
	if decoded, err := url.PathUnescape(frag); err == nil {
		return body, strings.TrimSpace(decoded)
	}
	return body, strings.TrimSpace(frag)
}

// parseHostPort splits an authority into host and port, accepting bracketed
// IPv6 literals and tolerating a missing port when a default is supplied.
func parseHostPort(authority string, defaultPort int) (string, int, error) {
	authority = strings.TrimSpace(authority)
	if authority == "" {
		return "", 0, fmt.Errorf("empty address")
	}

	host, portStr, err := net.SplitHostPort(authority)
	if err != nil {
		// No port present: acceptable only when the caller has a default.
		if defaultPort > 0 {
			return strings.Trim(authority, "[]"), defaultPort, nil
		}
		return "", 0, fmt.Errorf("invalid address %q: %w", authority, err)
	}

	port, err := strconv.Atoi(portStr)
	if err != nil {
		return "", 0, fmt.Errorf("invalid port %q", portStr)
	}
	if port <= 0 || port > 65535 {
		return "", 0, fmt.Errorf("port %d out of range", port)
	}
	return strings.Trim(host, "[]"), port, nil
}

// decodeBase64 decodes a base64 payload written in any of the four spellings
// found in the wild: standard or URL-safe alphabet, with or without padding.
func decodeBase64(s string) ([]byte, error) {
	s = strings.TrimSpace(s)
	s = strings.ReplaceAll(s, "\n", "")
	s = strings.ReplaceAll(s, "\r", "")
	if s == "" {
		return nil, fmt.Errorf("empty base64 payload")
	}

	encodings := []*base64.Encoding{
		base64.StdEncoding,
		base64.RawStdEncoding,
		base64.URLEncoding,
		base64.RawURLEncoding,
	}
	var lastErr error
	for _, enc := range encodings {
		if b, err := enc.DecodeString(s); err == nil {
			return b, nil
		} else {
			lastErr = err
		}
	}
	return nil, fmt.Errorf("invalid base64: %w", lastErr)
}

// applyStreamParams reads the query parameters shared by the VLESS/Trojan family
// of links (and the URI form of VMess) into the node's transport and TLS blocks.
// Keeping this in one place is what makes the parsers short and consistent: the
// panels all disagree about which spelling of a parameter to emit, and every one
// of those disagreements is resolved here rather than in five parsers.
func applyStreamParams(n *model.Node, q url.Values) {
	// Transport.
	transportRaw := firstNonEmpty(q.Get("type"), q.Get("network"), q.Get("net"), q.Get("obfs"))
	if t, ok := model.ParseTransport(transportRaw); ok {
		n.Transport.Type = t
	} else {
		n.Transport.Type = model.TransportTCP
	}

	if host := firstNonEmpty(q.Get("host"), q.Get("obfsParam")); host != "" {
		n.Transport.Host = splitList(host)
	}
	n.Transport.Path = firstNonEmpty(q.Get("path"), q.Get("obfsPath"))
	n.Transport.ServiceName = firstNonEmpty(q.Get("serviceName"), q.Get("servicename"))
	n.Transport.Method = q.Get("method")
	n.Transport.Seed = q.Get("seed")
	n.Transport.HeaderType = firstNonEmpty(q.Get("headerType"), q.Get("headertype"))

	if q.Get("mode") != "" {
		switch n.Transport.Type {
		case model.TransportGRPC:
			n.Transport.GRPCMultiMode = q.Get("mode") == "multi"
		case model.TransportXHTTP:
			n.Transport.XHTTPMode = q.Get("mode")
		}
	}
	n.Transport.XHTTPExtra = q.Get("extra")

	// gRPC links often carry the service name in "path" instead; normalize.
	if n.Transport.Type == model.TransportGRPC && n.Transport.ServiceName == "" && n.Transport.Path != "" {
		n.Transport.ServiceName = strings.TrimPrefix(n.Transport.Path, "/")
		n.Transport.Path = ""
	}

	// Security.
	securityRaw := firstNonEmpty(q.Get("security"), q.Get("tls"))
	if sec, ok := model.ParseSecurity(securityRaw); ok {
		n.TLS.Security = sec
	}
	// REALITY parameters imply REALITY even when "security" was omitted.
	if pbk := firstNonEmpty(q.Get("pbk"), q.Get("public-key"), q.Get("publicKey")); pbk != "" {
		n.TLS.Security = model.SecurityReality
		n.TLS.PublicKey = pbk
		n.TLS.ShortID = firstNonEmpty(q.Get("sid"), q.Get("short-id"), q.Get("shortId"))
		n.TLS.SpiderX = firstNonEmpty(q.Get("spx"), q.Get("spiderX"))
	}

	n.TLS.SNI = firstNonEmpty(q.Get("sni"), q.Get("peer"), q.Get("servername"), q.Get("serverName"))
	n.TLS.Fingerprint = firstNonEmpty(q.Get("fp"), q.Get("fingerprint"), q.Get("client-fingerprint"))
	if alpn := q.Get("alpn"); alpn != "" {
		n.TLS.ALPN = splitList(alpn)
	}
	n.TLS.AllowInsecure = parseBool(firstNonEmpty(q.Get("allowInsecure"), q.Get("insecure"), q.Get("skip-cert-verify")))

	if enc := q.Get("encryption"); enc != "" && enc != "none" {
		n.TLS.Encryption = enc
	}

	// A TLS-bearing link that omits the SNI still needs one; the Host header is
	// the conventional fallback, and failing that the server address itself.
	if n.TLS.Security != model.SecurityNone && n.TLS.SNI == "" {
		if len(n.Transport.Host) > 0 {
			n.TLS.SNI = n.Transport.Host[0]
		} else if net.ParseIP(n.Server) == nil {
			n.TLS.SNI = n.Server
		}
	}

	n.Flow = q.Get("flow")
	n.PacketEncoding = q.Get("packetEncoding")
}

// firstNonEmpty returns the first argument that is not empty after trimming.
func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if s := strings.TrimSpace(v); s != "" {
			return s
		}
	}
	return ""
}

// splitList splits a comma-separated parameter, dropping empty entries.
func splitList(s string) []string {
	parts := strings.Split(s, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// parseBool accepts the many truthy spellings used across panels.
func parseBool(s string) bool {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "1", "true", "yes", "on":
		return true
	default:
		return false
	}
}

// atoiOr parses an integer, falling back to a default on any error.
func atoiOr(s string, def int) int {
	if v, err := strconv.Atoi(strings.TrimSpace(s)); err == nil {
		return v
	}
	return def
}
