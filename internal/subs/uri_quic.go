package subs

import (
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"

	"github.com/obelisk-project/obelisk/internal/model"
)

// parseHysteria2 handles the Hysteria 2 share link:
//
//	hy2://<auth>@<host>:<port>?sni=&insecure=&obfs=&obfs-password=#<tag>
//
// Hysteria 2 always runs over QUIC with TLS, so those are set unconditionally.
func parseHysteria2(raw string) (*model.Node, error) {
	body, name := splitFragment(raw)

	// net/url rejects a range in the authority, although Hysteria share links
	// allow it. Parse the URL with its first port, preserving the full range.
	var authorityPorts string
	schemeEnd := strings.Index(body, "://") + 3
	authorityEnd := strings.IndexAny(body[schemeEnd:], "/?")
	if authorityEnd < 0 {
		authorityEnd = len(body)
	} else {
		authorityEnd += schemeEnd
	}
	authority := body[schemeEnd:authorityEnd]
	if colon := strings.LastIndex(authority, ":"); colon > strings.LastIndex(authority, "]") && colon > strings.LastIndex(authority, "@") {
		ports := authority[colon+1:]
		if strings.ContainsAny(ports, ",-") {
			for _, part := range strings.Split(ports, ",") {
				ends := strings.Split(part, "-")
				if len(ends) > 2 {
					return nil, fmt.Errorf("hysteria2: invalid port range")
				}
				previous := 0
				for _, end := range ends {
					port, err := strconv.Atoi(end)
					if err != nil || port < 1 || port > 65535 || port < previous {
						return nil, fmt.Errorf("hysteria2: invalid port range")
					}
					previous = port
				}
			}
			authorityPorts = ports
			first := strings.FieldsFunc(ports, func(r rune) bool { return r == ',' || r == '-' })[0]
			body = body[:schemeEnd+colon+1] + first + body[authorityEnd:]
		}
	}

	u, err := url.Parse(body)
	if err != nil {
		return nil, fmt.Errorf("hysteria2: %w", err)
	}

	host, port, err := parseHostPort(u.Host, 443)
	if err != nil {
		return nil, fmt.Errorf("hysteria2: %w", err)
	}

	// The auth string is a single opaque credential, but servers configured for
	// userpass authentication expect it spelled "user:password", which arrives
	// split across the two halves of the userinfo.
	var auth string
	if u.User != nil {
		auth = u.User.Username()
		if pw, ok := u.User.Password(); ok {
			auth = auth + ":" + pw
		}
	}
	if auth == "" {
		return nil, fmt.Errorf("hysteria2: missing auth")
	}

	q := u.Query()
	n := &model.Node{
		Name:     name,
		Protocol: model.ProtoHysteria2,
		Server:   host,
		Port:     port,
		Password: auth,
		Hysteria: &model.HysteriaOpts{
			UpMbps:       parseBandwidth(firstNonEmpty(q.Get("up"), q.Get("upmbps"))),
			DownMbps:     parseBandwidth(firstNonEmpty(q.Get("down"), q.Get("downmbps"))),
			Obfs:         q.Get("obfs"),
			ObfsPassword: firstNonEmpty(q.Get("obfs-password"), q.Get("obfsParam"), q.Get("obfs_password")),
			Ports:        firstNonEmpty(authorityPorts, q.Get("mport"), q.Get("ports")),
			HopInterval:  atoiOr(firstNonEmpty(q.Get("hop-interval"), q.Get("hopInterval")), 0),
		},
	}

	n.Transport.Type = model.TransportQUIC
	applyQUICSecurity(n, q, host)
	return n, nil
}

// parseHysteria handles the legacy Hysteria 1 link, which puts the credential in
// the query rather than the userinfo.
func parseHysteria(raw string) (*model.Node, error) {
	body, name := splitFragment(raw)

	u, err := url.Parse(body)
	if err != nil {
		return nil, fmt.Errorf("hysteria: %w", err)
	}

	host, port, err := parseHostPort(u.Host, 443)
	if err != nil {
		return nil, fmt.Errorf("hysteria: %w", err)
	}

	q := u.Query()
	n := &model.Node{
		Name:     name,
		Protocol: model.ProtoHysteria,
		Server:   host,
		Port:     port,
		Hysteria: &model.HysteriaOpts{
			UpMbps:       parseBandwidth(firstNonEmpty(q.Get("upmbps"), q.Get("up"))),
			DownMbps:     parseBandwidth(firstNonEmpty(q.Get("downmbps"), q.Get("down"))),
			Auth:         firstNonEmpty(q.Get("auth"), q.Get("auth_str"), q.Get("authStr")),
			AuthBase64:   q.Get("auth-base64"),
			ObfsPassword: firstNonEmpty(q.Get("obfsParam"), q.Get("obfs")),
			Ports:        firstNonEmpty(q.Get("mport"), q.Get("ports")),
		},
	}

	n.Transport.Type = model.TransportQUIC
	applyQUICSecurity(n, q, host)
	return n, nil
}

// parseTUIC handles the TUIC v5 link:
//
//	tuic://<uuid>:<password>@<host>:<port>?congestion_control=&alpn=#<tag>
func parseTUIC(raw string) (*model.Node, error) {
	body, name := splitFragment(raw)

	u, err := url.Parse(body)
	if err != nil {
		return nil, fmt.Errorf("tuic: %w", err)
	}
	if u.User == nil || u.User.Username() == "" {
		return nil, fmt.Errorf("tuic: missing uuid")
	}

	host, port, err := parseHostPort(u.Host, 443)
	if err != nil {
		return nil, fmt.Errorf("tuic: %w", err)
	}

	password, _ := u.User.Password()
	q := u.Query()

	n := &model.Node{
		Name:     name,
		Protocol: model.ProtoTUIC,
		Server:   host,
		Port:     port,
		UUID:     u.User.Username(),
		Password: password,
		TUIC: &model.TUICOpts{
			CongestionControl: firstNonEmpty(q.Get("congestion_control"), q.Get("congestion-control"), "bbr"),
			UDPRelayMode:      firstNonEmpty(q.Get("udp_relay_mode"), q.Get("udp-relay-mode"), "native"),
			ZeroRTTHandshake:  parseBool(firstNonEmpty(q.Get("zero_rtt_handshake"), q.Get("reduce_rtt"))),
		},
	}

	n.Transport.Type = model.TransportQUIC
	applyQUICSecurity(n, q, host)
	if len(n.TLS.ALPN) == 0 {
		n.TLS.ALPN = []string{"h3"}
	}
	return n, nil
}

// parseAnyTLS handles the AnyTLS link:
//
//	anytls://<password>@<host>:<port>?sni=&insecure=#<tag>
func parseAnyTLS(raw string) (*model.Node, error) {
	body, name := splitFragment(raw)

	u, err := url.Parse(body)
	if err != nil {
		return nil, fmt.Errorf("anytls: %w", err)
	}
	if u.User == nil || u.User.Username() == "" {
		return nil, fmt.Errorf("anytls: missing password")
	}

	host, port, err := parseHostPort(u.Host, 443)
	if err != nil {
		return nil, fmt.Errorf("anytls: %w", err)
	}

	q := u.Query()
	n := &model.Node{
		Name:     name,
		Protocol: model.ProtoAnyTLS,
		Server:   host,
		Port:     port,
		Password: u.User.Username(),
		AnyTLS:   &model.AnyTLSOpts{},
	}

	n.Transport.Type = model.TransportTCP
	n.TLS.Security = model.SecurityTLS
	n.TLS.SNI = firstNonEmpty(q.Get("sni"), q.Get("peer"), q.Get("servername"), host)
	n.TLS.AllowInsecure = parseBool(firstNonEmpty(q.Get("insecure"), q.Get("allowInsecure"), q.Get("skip-cert-verify")))
	n.TLS.Fingerprint = firstNonEmpty(q.Get("fp"), q.Get("fingerprint"))
	if alpn := q.Get("alpn"); alpn != "" {
		n.TLS.ALPN = splitList(alpn)
	}
	return n, nil
}

// applyQUICSecurity fills in the TLS block shared by the QUIC-based protocols.
// All of them are TLS by construction, so the only questions are which name to
// verify against and whether verification is being skipped at all.
func applyQUICSecurity(n *model.Node, q url.Values, host string) {
	n.TLS.Security = model.SecurityTLS
	n.TLS.SNI = firstNonEmpty(q.Get("sni"), q.Get("peer"), q.Get("servername"))
	if n.TLS.SNI == "" && net.ParseIP(host) == nil {
		n.TLS.SNI = host
	}
	n.TLS.AllowInsecure = parseBool(firstNonEmpty(
		q.Get("insecure"), q.Get("allowInsecure"), q.Get("skip-cert-verify")))
	if alpn := q.Get("alpn"); alpn != "" {
		n.TLS.ALPN = splitList(alpn)
	}
	if pin := firstNonEmpty(q.Get("pinSHA256"), q.Get("pinsha256")); pin != "" {
		n.SetExtra("pin_sha256", pin)
	}
}

// parseBandwidth reads a Hysteria bandwidth hint. The value may be a bare
// number of megabits or carry a unit suffix ("100 mbps", "50m"); anything that
// is not a plain number is reduced to its leading digits, and an unusable value
// yields 0, which both cores read as "no limit".
func parseBandwidth(s string) int {
	s = strings.TrimSpace(strings.ToLower(s))
	if s == "" {
		return 0
	}
	end := 0
	for end < len(s) && s[end] >= '0' && s[end] <= '9' {
		end++
	}
	if end == 0 {
		return 0
	}
	value := atoiOr(s[:end], 0)
	switch unit := strings.TrimSpace(s[end:]); {
	case strings.HasPrefix(unit, "g"):
		return value * 1000
	case strings.HasPrefix(unit, "k"):
		return value / 1000
	default:
		return value
	}
}
