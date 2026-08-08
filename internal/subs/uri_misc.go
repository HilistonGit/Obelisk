package subs

import (
	"fmt"
	"net/url"
	"strings"

	"github.com/obelisk-project/obelisk/internal/model"
)

// parseSOCKS handles socks5://[user:password@]host:port#tag. The v2rayN dialect
// base64-encodes the credentials, so a userinfo without a colon is retried as
// base64 before being taken at face value.
func parseSOCKS(raw string) (*model.Node, error) {
	body, name := splitFragment(raw)

	u, err := url.Parse(body)
	if err != nil {
		return nil, fmt.Errorf("socks: %w", err)
	}
	host, port, err := parseHostPort(u.Host, 1080)
	if err != nil {
		return nil, fmt.Errorf("socks: %w", err)
	}

	username, password := decodeProxyUserInfo(u.User)
	n := &model.Node{
		Name:     name,
		Protocol: model.ProtoSOCKS,
		Server:   host,
		Port:     port,
		Username: username,
		Password: password,
	}
	n.Transport.Type = model.TransportTCP

	// socks5-tls and the ?tls=1 spelling both mean the SOCKS conversation itself
	// is wrapped in TLS.
	q := u.Query()
	if strings.EqualFold(u.Scheme, "socks5-tls") || parseBool(q.Get("tls")) {
		n.TLS.Security = model.SecurityTLS
		n.TLS.SNI = firstNonEmpty(q.Get("sni"), host)
		n.TLS.AllowInsecure = parseBool(firstNonEmpty(q.Get("allowInsecure"), q.Get("insecure")))
	}
	if parseBool(q.Get("udp-over-tcp")) {
		n.UDPOverTCP = true
	}
	return n, nil
}

// parseHTTPProxy handles http:// and https:// proxy links. The https scheme
// means the connection to the proxy is itself TLS, not that the proxy forwards
// HTTPS, which every proxy does anyway.
func parseHTTPProxy(raw string) (*model.Node, error) {
	body, name := splitFragment(raw)

	u, err := url.Parse(body)
	if err != nil {
		return nil, fmt.Errorf("http proxy: %w", err)
	}

	secure := strings.EqualFold(u.Scheme, "https")
	defaultPort := 80
	if secure {
		defaultPort = 443
	}
	host, port, err := parseHostPort(u.Host, defaultPort)
	if err != nil {
		return nil, fmt.Errorf("http proxy: %w", err)
	}

	username, password := decodeProxyUserInfo(u.User)
	n := &model.Node{
		Name:     name,
		Protocol: model.ProtoHTTP,
		Server:   host,
		Port:     port,
		Username: username,
		Password: password,
	}
	n.Transport.Type = model.TransportTCP

	q := u.Query()
	if secure || parseBool(q.Get("tls")) {
		n.TLS.Security = model.SecurityTLS
		n.TLS.SNI = firstNonEmpty(q.Get("sni"), host)
		n.TLS.AllowInsecure = parseBool(firstNonEmpty(q.Get("allowInsecure"), q.Get("insecure")))
	}
	return n, nil
}

// parseSSH handles ssh://user[:password]@host:port#tag. Key-based
// authentication cannot be expressed in a link and is configured per node.
func parseSSH(raw string) (*model.Node, error) {
	body, name := splitFragment(raw)

	u, err := url.Parse(body)
	if err != nil {
		return nil, fmt.Errorf("ssh: %w", err)
	}
	host, port, err := parseHostPort(u.Host, 22)
	if err != nil {
		return nil, fmt.Errorf("ssh: %w", err)
	}

	username, password := decodeProxyUserInfo(u.User)
	n := &model.Node{
		Name:     name,
		Protocol: model.ProtoSSH,
		Server:   host,
		Port:     port,
		Username: username,
		Password: password,
		SSH:      &model.SSHOpts{},
	}
	n.Transport.Type = model.TransportTCP
	return n, nil
}

// parseWireGuard handles the WireGuard link used by several panels:
//
//	wireguard://<private key>@<host>:<port>?publickey=&address=&mtu=#<tag>
//
// There is no standard for this link, so the parameter names accepted here cover
// the spellings emitted by the panels that produce them.
func parseWireGuard(raw string) (*model.Node, error) {
	body, name := splitFragment(raw)

	u, err := url.Parse(body)
	if err != nil {
		return nil, fmt.Errorf("wireguard: %w", err)
	}
	if u.User == nil || u.User.Username() == "" {
		return nil, fmt.Errorf("wireguard: missing private key")
	}
	host, port, err := parseHostPort(u.Host, 51820)
	if err != nil {
		return nil, fmt.Errorf("wireguard: %w", err)
	}

	q := u.Query()
	privateKey, _ := url.QueryUnescape(u.User.Username())

	wg := &model.WireGuardOpts{
		PrivateKey:    privateKey,
		PeerPublicKey: firstNonEmpty(q.Get("publickey"), q.Get("public_key"), q.Get("pubkey"), q.Get("peer")),
		PreSharedKey:  firstNonEmpty(q.Get("presharedkey"), q.Get("pre_shared_key"), q.Get("psk")),
		LocalAddress:  splitList(firstNonEmpty(q.Get("address"), q.Get("ip"), q.Get("local_address"))),
		MTU:           atoiOr(q.Get("mtu"), 0),
		KeepAlive:     atoiOr(firstNonEmpty(q.Get("keepalive"), q.Get("persistent_keepalive")), 0),
	}
	for _, v := range splitList(q.Get("reserved")) {
		wg.Reserved = append(wg.Reserved, atoiOr(v, 0))
	}

	n := &model.Node{
		Name:      name,
		Protocol:  model.ProtoWireGuard,
		Server:    host,
		Port:      port,
		WireGuard: wg,
	}
	n.Transport.Type = model.TransportTCP
	return n, nil
}

// decodeProxyUserInfo extracts credentials from a URL userinfo section,
// transparently handling the base64-encoded form that v2rayN emits for SOCKS.
func decodeProxyUserInfo(info *url.Userinfo) (username, password string) {
	if info == nil {
		return "", ""
	}
	username = info.Username()
	password, hasPassword := info.Password()

	// A userinfo with no colon may be base64 of "user:password".
	if !hasPassword && username != "" && !strings.Contains(username, ":") {
		if decoded, err := decodeBase64(username); err == nil {
			if u, p, found := strings.Cut(string(decoded), ":"); found {
				return u, p
			}
		}
	}
	return username, password
}
