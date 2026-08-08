package subs

import (
	"fmt"

	"github.com/obelisk-project/obelisk/internal/model"
	"gopkg.in/yaml.v3"
)

// ParseClash reads a Clash / Clash.Meta (mihomo) configuration: the nodes from
// its "proxies" list, and the routing decisions from its "rules" list.
//
// Proxy groups are still ignored — Obelisk builds its own — but the rules are
// not. A provider's curated list of what should bypass the tunnel is real
// knowledge about their network, and it does not fight the user's own rules
// because it is kept as a separate layer that compiles underneath them.
func ParseClash(data []byte) ([]*model.Node, []SkipReason, *ProviderRules, error) {
	var doc map[string]any
	if err := yaml.Unmarshal(data, &doc); err != nil {
		return nil, nil, nil, fmt.Errorf("clash: %w", err)
	}

	proxies := mList(doc, "proxies")
	if proxies == nil {
		return nil, nil, nil, fmt.Errorf("clash: document has no proxies list")
	}

	var (
		nodes   []*model.Node
		skipped []SkipReason
	)
	for i, p := range proxies {
		n, err := clashProxyToNode(p)
		if err != nil {
			skipped = append(skipped, SkipReason{
				Line: fmt.Sprintf("proxies[%d] %s", i, mStr(p, "name")),
				Err:  err.Error(),
			})
			continue
		}
		n.AssignID()
		nodes = append(nodes, n)
	}
	return nodes, skipped, extractClashRules(doc), nil
}

// clashProxyToNode converts one entry of the proxies list.
func clashProxyToNode(p map[string]any) (*model.Node, error) {
	protoRaw := mStr(p, "type")
	proto, ok := model.ParseProtocol(protoRaw)
	if !ok {
		return nil, fmt.Errorf("unsupported proxy type %q", protoRaw)
	}

	n := &model.Node{
		Name:     mStr(p, "name"),
		Protocol: proto,
		Server:   mStr(p, "server"),
		Port:     mInt(p, "port"),
	}
	if n.Port == 0 {
		n.Port = mInt(p, "server-port", "server_port")
	}

	if err := clashApplyIdentity(n, p); err != nil {
		return nil, err
	}
	clashApplyTransport(n, p)
	clashApplyTLS(n, p)
	clashApplyMux(n, p)

	if err := n.Validate(); err != nil {
		return nil, err
	}
	return n, nil
}

// clashApplyIdentity fills the credential fields for the node's protocol.
func clashApplyIdentity(n *model.Node, p map[string]any) error {
	switch n.Protocol {
	case model.ProtoVLESS:
		n.UUID = mStr(p, "uuid")
		n.Flow = mStr(p, "flow")
	case model.ProtoVMess:
		n.UUID = mStr(p, "uuid")
		n.AlterID = mInt(p, "alterId", "alterid", "alter-id")
		n.VMessSecurity = mStr(p, "cipher")
		if n.VMessSecurity == "" {
			n.VMessSecurity = "auto"
		}
	case model.ProtoTrojan:
		n.Password = mStr(p, "password")
	case model.ProtoShadowsocks:
		n.Method = mStr(p, "cipher", "method")
		n.Password = mStr(p, "password")
		n.Plugin = normalizeSSPlugin(mStr(p, "plugin"))
		if opts := mMap(p, "plugin-opts", "plugin_opts"); len(opts) > 0 {
			n.PluginOpts = clashPluginOpts(opts)
		}
	case model.ProtoShadowsocksR:
		n.Method = mStr(p, "cipher", "method")
		n.Password = mStr(p, "password")
		n.SSR = &model.SSROpts{
			Protocol:      mStr(p, "protocol"),
			ProtocolParam: mStr(p, "protocol-param", "protocolparam"),
			Obfs:          mStr(p, "obfs"),
			ObfsParam:     mStr(p, "obfs-param", "obfsparam"),
		}
	case model.ProtoHysteria2:
		n.Password = mStr(p, "password", "auth")
		n.Hysteria = &model.HysteriaOpts{
			UpMbps:       parseBandwidth(mStr(p, "up")),
			DownMbps:     parseBandwidth(mStr(p, "down")),
			Obfs:         mStr(p, "obfs"),
			ObfsPassword: mStr(p, "obfs-password", "obfs_password"),
			Ports:        mStr(p, "ports"),
		}
	case model.ProtoHysteria:
		n.Hysteria = &model.HysteriaOpts{
			UpMbps:      parseBandwidth(mStr(p, "up", "up-speed")),
			DownMbps:    parseBandwidth(mStr(p, "down", "down-speed")),
			Auth:        mStr(p, "auth-str", "auth_str", "auth"),
			AuthBase64:  mStr(p, "auth"),
			Obfs:        mStr(p, "obfs"),
			RecvWindow:  mInt(p, "recv-window"),
			Ports:       mStr(p, "ports"),
			HopInterval: mInt(p, "hop-interval"),
		}
	case model.ProtoTUIC:
		n.UUID = mStr(p, "uuid")
		n.Password = mStr(p, "password")
		n.TUIC = &model.TUICOpts{
			CongestionControl: mStr(p, "congestion-controller", "congestion_control"),
			UDPRelayMode:      mStr(p, "udp-relay-mode", "udp_relay_mode"),
			ZeroRTTHandshake:  mBool(p, "reduce-rtt", "zero-rtt-handshake"),
			HeartbeatSeconds:  mInt(p, "heartbeat-interval"),
		}
	case model.ProtoAnyTLS:
		n.Password = mStr(p, "password")
		n.AnyTLS = &model.AnyTLSOpts{
			IdleSessionCheckInterval: mStr(p, "idle-session-check-interval"),
			IdleSessionTimeout:       mStr(p, "idle-session-timeout"),
			MinIdleSession:           mInt(p, "min-idle-session"),
		}
	case model.ProtoSOCKS, model.ProtoHTTP:
		n.Username = mStr(p, "username")
		n.Password = mStr(p, "password")
	case model.ProtoSSH:
		n.Username = mStr(p, "username")
		n.Password = mStr(p, "password")
		n.SSH = &model.SSHOpts{
			PrivateKey:           mStr(p, "private-key"),
			PrivateKeyPassphrase: mStr(p, "private-key-passphrase"),
			HostKeyAlgorithms:    mStrSlice(p, "host-key-algorithms"),
		}
	case model.ProtoWireGuard:
		addrs := mStrSlice(p, "ip", "address", "local-address")
		if v6 := mStr(p, "ipv6"); v6 != "" {
			addrs = append(addrs, v6)
		}
		n.WireGuard = &model.WireGuardOpts{
			PrivateKey:    mStr(p, "private-key"),
			PeerPublicKey: mStr(p, "public-key"),
			PreSharedKey:  mStr(p, "pre-shared-key"),
			LocalAddress:  addrs,
			MTU:           mInt(p, "mtu"),
			Reserved:      mIntSlice(p, "reserved"),
		}
	default:
		return fmt.Errorf("no identity mapping for %q", n.Protocol)
	}
	return nil
}

// clashApplyTransport maps the per-transport option blocks. Clash keeps each
// transport's settings in its own nested mapping rather than in a shared one.
func clashApplyTransport(n *model.Node, p map[string]any) {
	network := mStr(p, "network")
	t, ok := model.ParseTransport(network)
	if !ok {
		t = model.TransportTCP
	}
	n.Transport.Type = t

	switch t {
	case model.TransportWebSocket:
		opts := mMap(p, "ws-opts", "ws_opts")
		n.Transport.Path = mStr(opts, "path")
		n.Transport.Headers = mStrMap(opts, "headers")
		n.Transport.MaxEarlyData = mInt(opts, "max-early-data")
		n.Transport.EarlyDataHeaderName = mStr(opts, "early-data-header-name")
		if host := n.Transport.Headers["Host"]; host != "" {
			n.Transport.Host = []string{host}
		} else if host := n.Transport.Headers["host"]; host != "" {
			n.Transport.Host = []string{host}
		}
	case model.TransportGRPC:
		opts := mMap(p, "grpc-opts", "grpc_opts")
		n.Transport.ServiceName = mStr(opts, "grpc-service-name", "service-name")
	case model.TransportHTTP:
		// Clash uses "h2-opts" for real HTTP/2 and "http-opts" for the HTTP
		// camouflage that rides on plain TCP; only the former is a transport.
		opts := mMap(p, "h2-opts", "h2_opts")
		n.Transport.Path = mStr(opts, "path")
		n.Transport.Host = mStrSlice(opts, "host")
	case model.TransportTCP:
		if opts := mMap(p, "http-opts", "http_opts"); len(opts) > 0 {
			n.Transport.HeaderType = "http"
			n.Transport.Method = mStr(opts, "method")
			n.Transport.Host = mStrSlice(mMap(opts, "headers"), "Host", "host")
			if paths := mStrSlice(opts, "path"); len(paths) > 0 {
				n.Transport.Path = paths[0]
			}
		}
	}

	if mBool(p, "udp") {
		n.PacketEncoding = mStr(p, "packet-encoding")
	}
	if mBool(p, "udp-over-tcp") {
		n.UDPOverTCP = true
	}
}

// clashApplyTLS maps the TLS and REALITY blocks.
func clashApplyTLS(n *model.Node, p map[string]any) {
	// Trojan and the QUIC-based protocols are TLS by construction, so Clash
	// documents routinely omit the flag for them; reading its absence as
	// plaintext would silently produce nodes that cannot connect.
	switch n.Protocol {
	case model.ProtoTrojan, model.ProtoHysteria, model.ProtoHysteria2,
		model.ProtoTUIC, model.ProtoAnyTLS:
		n.TLS.Security = model.SecurityTLS
	default:
		if mBool(p, "tls") {
			n.TLS.Security = model.SecurityTLS
		} else {
			n.TLS.Security = model.SecurityNone
		}
	}

	n.TLS.SNI = mStr(p, "servername", "sni", "server-name", "peer")
	n.TLS.AllowInsecure = mBool(p, "skip-cert-verify", "allow-insecure", "insecure")
	n.TLS.Fingerprint = mStr(p, "client-fingerprint")
	n.TLS.ALPN = mStrSlice(p, "alpn")
	n.TLS.Certificate = mStr(p, "ca-str", "certificate")

	if reality := mMap(p, "reality-opts", "reality_opts"); len(reality) > 0 {
		n.TLS.Security = model.SecurityReality
		n.TLS.PublicKey = mStr(reality, "public-key", "publicKey")
		n.TLS.ShortID = mStr(reality, "short-id", "shortId")
	}

	if n.TLS.Security != model.SecurityNone && n.TLS.SNI == "" {
		if len(n.Transport.Host) > 0 {
			n.TLS.SNI = n.Transport.Host[0]
		} else {
			n.TLS.SNI = n.Server
		}
	}
}

// clashApplyMux maps the smux block used by Clash.Meta.
func clashApplyMux(n *model.Node, p map[string]any) {
	smux := mMap(p, "smux")
	if len(smux) == 0 || !mBool(smux, "enabled") {
		return
	}
	n.Mux = &model.MuxOpts{
		Enabled:    true,
		Protocol:   mStr(smux, "protocol"),
		MaxConns:   mInt(smux, "max-connections"),
		MinStreams: mInt(smux, "min-streams"),
		MaxStreams: mInt(smux, "max-streams"),
		Padding:    mBool(smux, "padding"),
	}
}

// clashPluginOpts re-serializes a Clash plugin-opts mapping back into the SIP003
// semicolon string that both the links and sing-box use.
func clashPluginOpts(opts map[string]any) string {
	// The key order is fixed rather than map-random so that a node's fingerprint
	// stays stable across re-imports of the same subscription.
	order := []string{"mode", "host", "path", "tls", "obfs", "obfs-host", "mux"}
	var parts []string
	for _, k := range order {
		if v, ok := opts[k]; ok && v != nil {
			parts = append(parts, fmt.Sprintf("%s=%v", k, v))
		}
	}
	out := ""
	for i, p := range parts {
		if i > 0 {
			out += ";"
		}
		out += p
	}
	return out
}
