// Package singbox renders Obelisk's normalized nodes into sing-box
// configuration. sing-box is Obelisk's front core: it owns the system inbound
// (TUN, TPROXY or REDIRECT), the routing tree and the DNS layer, and it reaches
// Xray-only nodes through a loopback SOCKS hop. Nothing here patches sing-box
// itself; it all goes through the stock binary's configuration file.
package singbox

import (
	"fmt"
	"strings"

	"github.com/obelisk-project/obelisk/internal/model"
)

// Rendered is one node expressed in sing-box's schema.
type Rendered struct {
	// Object is the outbound (or endpoint) definition.
	Object map[string]any

	// Endpoint reports that the object belongs in the configuration's
	// "endpoints" array rather than "outbounds". sing-box 1.11 moved WireGuard
	// there, because a WireGuard interface both sends and receives and so is not
	// an outbound in the ordinary sense.
	Endpoint bool
}

// Outbound renders one node as a sing-box outbound carrying the given tag.
func Outbound(n *model.Node, tag string) (*Rendered, error) {
	if ok, reason := model.Supports(model.CoreSingBox, n); !ok {
		return nil, &model.UnsupportedError{Core: model.CoreSingBox, Node: n.DisplayName(), Reason: reason}
	}

	if n.Protocol == model.ProtoWireGuard {
		obj, err := wireGuardEndpoint(n, tag)
		if err != nil {
			return nil, err
		}
		return &Rendered{Object: obj, Endpoint: true}, nil
	}

	obj := map[string]any{
		"type":        singboxTypeName(n.Protocol),
		"tag":         tag,
		"server":      n.Server,
		"server_port": n.Port,
	}

	if err := applyIdentity(obj, n); err != nil {
		return nil, err
	}
	if tls := tlsBlock(n); tls != nil {
		obj["tls"] = tls
	}
	if tr := transportBlock(n); tr != nil {
		obj["transport"] = tr
	}
	if mux := multiplexBlock(n); mux != nil {
		obj["multiplex"] = mux
	}
	return &Rendered{Object: obj}, nil
}

// singboxTypeName maps Obelisk's protocol names onto sing-box's spelling.
func singboxTypeName(p model.Protocol) string {
	switch p {
	case model.ProtoDirect:
		return "direct"
	default:
		return string(p)
	}
}

// applyIdentity fills in the credential fields for the node's protocol.
func applyIdentity(obj map[string]any, n *model.Node) error {
	switch n.Protocol {
	case model.ProtoVLESS:
		obj["uuid"] = n.UUID
		if n.Flow != "" {
			obj["flow"] = n.Flow
		}
		if n.PacketEncoding != "" {
			obj["packet_encoding"] = n.PacketEncoding
		}

	case model.ProtoVMess:
		obj["uuid"] = n.UUID
		obj["security"] = orDefault(n.VMessSecurity, "auto")
		if n.AlterID > 0 {
			obj["alter_id"] = n.AlterID
		}

	case model.ProtoTrojan:
		obj["password"] = n.Password

	case model.ProtoShadowsocks:
		obj["method"] = n.Method
		obj["password"] = n.Password
		if n.Plugin != "" {
			obj["plugin"] = n.Plugin
			obj["plugin_opts"] = n.PluginOpts
		}
		if n.UDPOverTCP {
			obj["udp_over_tcp"] = true
		}

	case model.ProtoHysteria2:
		obj["password"] = n.Password
		if h := n.Hysteria; h != nil {
			if h.Ports != "" {
				ports := strings.Split(h.Ports, ",")
				for i := range ports {
					ports[i] = strings.ReplaceAll(strings.TrimSpace(ports[i]), "-", ":")
				}
				obj["server_ports"] = ports
				delete(obj, "server_port")
			}
			if h.HopInterval > 0 {
				obj["hop_interval"] = fmt.Sprintf("%ds", h.HopInterval)
			}

			setPositive(obj, "up_mbps", h.UpMbps)
			setPositive(obj, "down_mbps", h.DownMbps)
			if h.Obfs != "" {
				obj["obfs"] = map[string]any{
					"type":     h.Obfs,
					"password": h.ObfsPassword,
				}
			}
		}

	case model.ProtoHysteria:
		if h := n.Hysteria; h != nil {
			setPositive(obj, "up_mbps", h.UpMbps)
			setPositive(obj, "down_mbps", h.DownMbps)
			if h.Auth != "" {
				obj["auth_str"] = h.Auth
			}
			if h.AuthBase64 != "" {
				obj["auth"] = h.AuthBase64
			}
			if h.ObfsPassword != "" {
				obj["obfs"] = h.ObfsPassword
			}
			setPositive(obj, "recv_window", h.RecvWindow)
			setPositive(obj, "recv_window_conn", h.RecvWindowConn)
			if h.DisableMTUDiscovery {
				obj["disable_mtu_discovery"] = true
			}
		}

	case model.ProtoTUIC:
		obj["uuid"] = n.UUID
		obj["password"] = n.Password
		if t := n.TUIC; t != nil {
			obj["congestion_control"] = orDefault(t.CongestionControl, "bbr")
			obj["udp_relay_mode"] = orDefault(t.UDPRelayMode, "native")
			if t.ZeroRTTHandshake {
				obj["zero_rtt_handshake"] = true
			}
			if t.HeartbeatSeconds > 0 {
				obj["heartbeat"] = fmt.Sprintf("%ds", t.HeartbeatSeconds)
			}
		}

	case model.ProtoAnyTLS:
		obj["password"] = n.Password
		if a := n.AnyTLS; a != nil {
			setNonEmpty(obj, "idle_session_check_interval", a.IdleSessionCheckInterval)
			setNonEmpty(obj, "idle_session_timeout", a.IdleSessionTimeout)
			setPositive(obj, "min_idle_session", a.MinIdleSession)
		}

	case model.ProtoShadowTLS:
		obj["password"] = n.Password
		if s := n.ShadowTLS; s != nil && s.Version > 0 {
			obj["version"] = s.Version
		}

	case model.ProtoSOCKS:
		obj["version"] = "5"
		setNonEmpty(obj, "username", n.Username)
		setNonEmpty(obj, "password", n.Password)
		if n.UDPOverTCP {
			obj["udp_over_tcp"] = true
		}

	case model.ProtoHTTP:
		setNonEmpty(obj, "username", n.Username)
		setNonEmpty(obj, "password", n.Password)

	case model.ProtoSSH:
		setNonEmpty(obj, "user", n.Username)
		setNonEmpty(obj, "password", n.Password)
		if s := n.SSH; s != nil {
			setNonEmpty(obj, "private_key", s.PrivateKey)
			setNonEmpty(obj, "private_key_passphrase", s.PrivateKeyPassphrase)
			setNonEmpty(obj, "client_version", s.ClientVersion)
			if len(s.HostKeyAlgorithms) > 0 {
				obj["host_key_algorithms"] = s.HostKeyAlgorithms
			}
		}

	case model.ProtoDirect:
		// A direct outbound takes no server or credentials.
		delete(obj, "server")
		delete(obj, "server_port")

	default:
		return fmt.Errorf("sing-box: no outbound mapping for %q", n.Protocol)
	}
	return nil
}

// wireGuardEndpoint renders the WireGuard endpoint object.
func wireGuardEndpoint(n *model.Node, tag string) (map[string]any, error) {
	wg := n.WireGuard
	if wg == nil {
		return nil, fmt.Errorf("sing-box: wireguard node has no peer configuration")
	}

	peer := map[string]any{
		"address":    n.Server,
		"port":       n.Port,
		"public_key": wg.PeerPublicKey,
		// A client peer tunnels everything it is given; the routing decision was
		// already made by the time traffic reaches this endpoint.
		"allowed_ips": []any{"0.0.0.0/0", "::/0"},
	}
	setNonEmpty(peer, "pre_shared_key", wg.PreSharedKey)
	setPositive(peer, "persistent_keepalive_interval", wg.KeepAlive)
	if len(wg.Reserved) > 0 {
		peer["reserved"] = wg.Reserved
	}

	obj := map[string]any{
		"type":        "wireguard",
		"tag":         tag,
		"private_key": wg.PrivateKey,
		"address":     wg.LocalAddress,
		"peers":       []any{peer},
	}
	setPositive(obj, "mtu", wg.MTU)
	return obj, nil
}

// tlsBlock renders the shared TLS object, returning nil when the node is
// plaintext.
func tlsBlock(n *model.Node) map[string]any {
	if n.TLS.Security == model.SecurityNone {
		return nil
	}

	tls := map[string]any{"enabled": true}
	setNonEmpty(tls, "server_name", n.TLS.SNI)
	if n.TLS.AllowInsecure {
		tls["insecure"] = true
	}
	if len(n.TLS.ALPN) > 0 {
		tls["alpn"] = n.TLS.ALPN
	}
	if n.TLS.Certificate != "" {
		tls["certificate"] = []any{n.TLS.Certificate}
	}

	if n.TLS.Security == model.SecurityReality {
		tls["reality"] = map[string]any{
			"enabled":    true,
			"public_key": n.TLS.PublicKey,
			"short_id":   n.TLS.ShortID,
		}
		// REALITY is a ClientHello forgery: without uTLS there is nothing to
		// forge, so a fingerprint is supplied even when the link omitted one.
		tls["utls"] = map[string]any{
			"enabled":     true,
			"fingerprint": orDefault(n.TLS.Fingerprint, "chrome"),
		}
	} else if n.TLS.Fingerprint != "" && n.Protocol != model.ProtoHysteria2 &&
		n.Protocol != model.ProtoHysteria && n.Protocol != model.ProtoTUIC {
		// uTLS cannot be used by QUIC, even when a panel supplies a fingerprint.
		tls["utls"] = map[string]any{
			"enabled":     true,
			"fingerprint": n.TLS.Fingerprint,
		}
	}

	if n.TLS.ECHEnabled {
		ech := map[string]any{"enabled": true}
		if n.TLS.ECHConfig != "" {
			ech["config"] = strings.Split(n.TLS.ECHConfig, "\n")
		}
		tls["ech"] = ech
	}
	return tls
}

// transportBlock renders the shared transport object. sing-box treats plain TCP
// as the absence of a transport rather than as a transport named "tcp".
func transportBlock(n *model.Node) map[string]any {
	tr := n.Transport

	switch tr.Type {
	case model.TransportWebSocket:
		ws := map[string]any{
			"type": "ws",
			"path": orDefault(tr.Path, "/"),
		}
		headers := map[string]any{}
		for k, v := range tr.Headers {
			headers[k] = v
		}
		if h := firstHost(tr.Host); h != "" {
			headers["Host"] = h
		}
		if len(headers) > 0 {
			ws["headers"] = headers
		}
		if tr.MaxEarlyData > 0 {
			ws["max_early_data"] = tr.MaxEarlyData
			ws["early_data_header_name"] = orDefault(tr.EarlyDataHeaderName, "Sec-WebSocket-Protocol")
		}
		return ws

	case model.TransportGRPC:
		return map[string]any{
			"type":         "grpc",
			"service_name": tr.ServiceName,
		}

	case model.TransportHTTP:
		h := map[string]any{
			"type": "http",
			"path": orDefault(tr.Path, "/"),
		}
		if len(tr.Host) > 0 {
			h["host"] = tr.Host
		}
		setNonEmpty(h, "method", tr.Method)
		return h

	case model.TransportHTTPUpgrade:
		hu := map[string]any{
			"type": "httpupgrade",
			"path": orDefault(tr.Path, "/"),
		}
		setNonEmpty(hu, "host", firstHost(tr.Host))
		return hu

	default:
		// TCP and the QUIC-based protocols carry no transport object.
		return nil
	}
}

// multiplexBlock renders the shared multiplex object.
//
// It is skipped for the QUIC-based protocols, which already multiplex streams
// inside a single connection, and for XTLS Vision, whose whole point is a
// connection per stream so the kernel can splice them.
func multiplexBlock(n *model.Node) map[string]any {
	if n.Mux == nil || !n.Mux.Enabled {
		return nil
	}
	switch n.Protocol {
	case model.ProtoHysteria, model.ProtoHysteria2, model.ProtoTUIC:
		return nil
	}
	if n.Flow == "xtls-rprx-vision" {
		return nil
	}

	mux := map[string]any{
		"enabled":  true,
		"protocol": orDefault(n.Mux.Protocol, "h2mux"),
	}
	setPositive(mux, "max_connections", n.Mux.MaxConns)
	setPositive(mux, "min_streams", n.Mux.MinStreams)
	setPositive(mux, "max_streams", n.Mux.MaxStreams)
	if n.Mux.Padding {
		mux["padding"] = true
	}
	return mux
}

func setNonEmpty(m map[string]any, key, value string) {
	if value != "" {
		m[key] = value
	}
}

func setPositive(m map[string]any, key string, value int) {
	if value > 0 {
		m[key] = value
	}
}

func orDefault(v, def string) string {
	if v == "" {
		return def
	}
	return v
}

func firstHost(hosts []string) string {
	if len(hosts) == 0 {
		return ""
	}
	return hosts[0]
}
