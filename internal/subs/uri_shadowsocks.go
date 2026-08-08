package subs

import (
	"fmt"
	"net/url"
	"strings"

	"github.com/obelisk-project/obelisk/internal/model"
)

// parseShadowsocks handles all three Shadowsocks link dialects:
//
//	SIP002:    ss://<base64(method:password)>@<host>:<port>?plugin=...#<tag>
//	SS2022:    ss://<method>:<base64key>@<host>:<port>#<tag>
//	legacy:    ss://<base64(method:password@host:port)>#<tag>
func parseShadowsocks(raw string) (*model.Node, error) {
	body, name := splitFragment(raw)
	payload := strings.TrimPrefix(body, "ss://")

	// SIP002 carries the plugin in a query string; the legacy form has none.
	var query url.Values
	if i := strings.Index(payload, "?"); i >= 0 {
		q, err := url.ParseQuery(payload[i+1:])
		if err != nil {
			return nil, fmt.Errorf("shadowsocks: malformed query: %w", err)
		}
		query = q
		payload = payload[:i]
	}

	// The legacy form base64-encodes the whole "method:password@host:port"
	// string, so when there is no separator left, decode and retry.
	if !strings.Contains(payload, "@") {
		decoded, err := decodeBase64(payload)
		if err != nil {
			return nil, fmt.Errorf("shadowsocks: not a recognizable link: %w", err)
		}
		payload = strings.TrimSpace(string(decoded))
		if !strings.Contains(payload, "@") {
			return nil, fmt.Errorf("shadowsocks: decoded payload has no address separator")
		}
	}

	// The password may itself contain "@", so the address is whatever follows
	// the *last* separator.
	at := strings.LastIndex(payload, "@")
	method, password, err := decodeShadowsocksUserInfo(payload[:at])
	if err != nil {
		return nil, err
	}
	host, port, err := parseHostPort(payload[at+1:], 0)
	if err != nil {
		return nil, fmt.Errorf("shadowsocks: %w", err)
	}

	n := &model.Node{
		Name:     name,
		Protocol: model.ProtoShadowsocks,
		Server:   host,
		Port:     port,
		Method:   method,
		Password: password,
	}

	if plugin := query.Get("plugin"); plugin != "" {
		// SIP003 packs the plugin name and its options into one semicolon
		// separated string: "obfs-local;obfs=http;obfs-host=example.com".
		nameArg, opts, _ := strings.Cut(plugin, ";")
		n.Plugin = normalizeSSPlugin(nameArg)
		n.PluginOpts = opts
	}
	if parseBool(query.Get("udp-over-tcp")) {
		n.UDPOverTCP = true
	}

	n.Transport.Type = model.TransportTCP
	n.TLS.Security = model.SecurityNone
	return n, nil
}

// decodeShadowsocksUserInfo splits the userinfo half of a Shadowsocks link into
// its cipher and password. Pre-2022 ciphers base64-encode the pair; the 2022
// AEAD ciphers carry a base64 key that must stay verbatim, so those links leave
// the userinfo in the clear.
func decodeShadowsocksUserInfo(userinfo string) (method, password string, err error) {
	if unescaped, e := url.PathUnescape(userinfo); e == nil {
		userinfo = unescaped
	}

	// The base64 alphabet contains no colon, so a colon here proves the userinfo
	// was not encoded.
	if !strings.Contains(userinfo, ":") {
		decoded, e := decodeBase64(userinfo)
		if e != nil {
			return "", "", fmt.Errorf("shadowsocks: cannot decode credentials: %w", e)
		}
		userinfo = string(decoded)
	}

	method, password, found := strings.Cut(userinfo, ":")
	if !found {
		return "", "", fmt.Errorf("shadowsocks: credentials are not in method:password form")
	}
	return strings.TrimSpace(method), password, nil
}

// normalizeSSPlugin folds the interchangeable plugin spellings onto the names
// sing-box expects.
func normalizeSSPlugin(name string) string {
	switch strings.ToLower(strings.TrimSpace(name)) {
	case "obfs-local", "simple-obfs", "obfs":
		return "obfs-local"
	case "v2ray-plugin", "v2ray":
		return "v2ray-plugin"
	default:
		return strings.TrimSpace(name)
	}
}

// parseShadowsocksR handles the ShadowsocksR link:
//
//	ssr://base64(host:port:protocol:method:obfs:base64(password)/?params)
//
// Neither Xray nor sing-box implements SSR, so these nodes will be reported as
// unsupported by the capability matrix. They are still parsed rather than
// dropped, because "your subscription contains 4 SSR nodes that no core can run"
// is a far more useful thing to show a user than a silently shorter list.
func parseShadowsocksR(raw string) (*model.Node, error) {
	payload := strings.TrimPrefix(raw, "ssr://")
	decoded, err := decodeBase64(payload)
	if err != nil {
		return nil, fmt.Errorf("shadowsocksr: %w", err)
	}

	main, rawQuery, _ := strings.Cut(string(decoded), "/?")

	parts := strings.Split(main, ":")
	if len(parts) < 6 {
		return nil, fmt.Errorf("shadowsocksr: expected 6 colon-separated fields, got %d", len(parts))
	}
	// Rejoin any surplus leading fields: an IPv6 literal would have split too.
	host := strings.Join(parts[:len(parts)-5], ":")
	tail := parts[len(parts)-5:]

	addr, port, err := parseHostPort(joinHostPort(host, tail[0]), 0)
	if err != nil {
		return nil, fmt.Errorf("shadowsocksr: %w", err)
	}

	passwordBytes, err := decodeBase64(tail[4])
	if err != nil {
		return nil, fmt.Errorf("shadowsocksr: cannot decode password: %w", err)
	}

	n := &model.Node{
		Protocol: model.ProtoShadowsocksR,
		Server:   addr,
		Port:     port,
		Method:   tail[2],
		Password: string(passwordBytes),
		SSR: &model.SSROpts{
			Protocol: tail[1],
			Obfs:     tail[3],
		},
	}

	if q, err := url.ParseQuery(rawQuery); err == nil {
		n.SSR.ObfsParam = decodeBase64String(q.Get("obfsparam"))
		n.SSR.ProtocolParam = decodeBase64String(q.Get("protoparam"))
		n.Name = decodeBase64String(q.Get("remarks"))
		n.SetExtra("group", decodeBase64String(q.Get("group")))
	}
	return n, nil
}

// decodeBase64String decodes a base64 field, returning "" rather than an error
// for the optional metadata fields where a malformed value is not worth failing
// the whole node over.
func decodeBase64String(s string) string {
	if s == "" {
		return ""
	}
	if b, err := decodeBase64(s); err == nil {
		return string(b)
	}
	return s
}
