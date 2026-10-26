package subs

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/obelisk-project/obelisk/internal/model"
)

// singboxSyntheticTypes are outbound types that describe policy rather than a
// server. They are Obelisk's own job, so they are skipped on import without
// being reported as errors.
var singboxSyntheticTypes = map[string]bool{
	"selector": true, "urltest": true, "direct": true, "block": true,
	"dns": true, "reject": true,
}

// ParseSingBox reads a sing-box configuration and returns the server outbounds
// it defines. Both the modern "endpoints" array and the legacy WireGuard
// outbound are recognized.
func ParseSingBox(data []byte) ([]*model.Node, []SkipReason, *ProviderRules, error) {
	var doc map[string]any
	if err := json.Unmarshal(data, &doc); err != nil {
		return nil, nil, nil, fmt.Errorf("sing-box: %w", err)
	}

	entries := mList(doc, "outbounds")
	entries = append(entries, mList(doc, "endpoints")...)
	if len(entries) == 0 {
		return nil, nil, nil, fmt.Errorf("sing-box: document has no outbounds")
	}

	var (
		nodes   []*model.Node
		skipped []SkipReason
	)
	for i, o := range entries {
		typ := mStr(o, "type")
		if singboxSyntheticTypes[typ] {
			continue
		}
		n, err := singboxOutboundToNode(o)
		if err != nil {
			skipped = append(skipped, SkipReason{
				Line: fmt.Sprintf("outbounds[%d] %s", i, mStr(o, "tag")),
				Err:  err.Error(),
			})
			continue
		}
		n.AssignID()
		nodes = append(nodes, n)
	}
	return nodes, skipped, extractSingBoxRules(doc), nil
}

// singboxOutboundToNode converts one sing-box outbound into a normalized node.
func singboxOutboundToNode(o map[string]any) (*model.Node, error) {
	protoRaw := mStr(o, "type")
	proto, ok := model.ParseProtocol(protoRaw)
	if !ok {
		return nil, fmt.Errorf("unsupported outbound type %q", protoRaw)
	}

	n := &model.Node{
		Name:     mStr(o, "tag"),
		Protocol: proto,
		Server:   mStr(o, "server"),
		Port:     mInt(o, "server_port"),
	}

	switch proto {
	case model.ProtoVLESS:
		n.UUID = mStr(o, "uuid")
		n.Flow = mStr(o, "flow")
		n.PacketEncoding = mStr(o, "packet_encoding")
	case model.ProtoVMess:
		n.UUID = mStr(o, "uuid")
		n.AlterID = mInt(o, "alter_id")
		n.VMessSecurity = mStr(o, "security")
		if n.VMessSecurity == "" {
			n.VMessSecurity = "auto"
		}
	case model.ProtoTrojan:
		n.Password = mStr(o, "password")
	case model.ProtoShadowsocks:
		n.Method = mStr(o, "method")
		n.Password = mStr(o, "password")
		n.Plugin = normalizeSSPlugin(mStr(o, "plugin"))
		n.PluginOpts = mStr(o, "plugin_opts")
	case model.ProtoHysteria2:
		n.Password = mStr(o, "password")
		obfs := mMap(o, "obfs")
		n.Hysteria = &model.HysteriaOpts{
			Ports:        strings.Join(mStrSlice(o, "server_ports"), ","),
			UpMbps:       mInt(o, "up_mbps"),
			DownMbps:     mInt(o, "down_mbps"),
			Obfs:         mStr(obfs, "type"),
			ObfsPassword: mStr(obfs, "password"),
		}
		if d, err := time.ParseDuration(mStr(o, "hop_interval")); err == nil {
			n.Hysteria.HopInterval = int(d / time.Second)
		}
		if n.Port == 0 && n.Hysteria.Ports != "" {
			n.Port = 443
		}

	case model.ProtoHysteria:
		n.Hysteria = &model.HysteriaOpts{
			UpMbps:              mInt(o, "up_mbps"),
			DownMbps:            mInt(o, "down_mbps"),
			Auth:                mStr(o, "auth_str"),
			AuthBase64:          mStr(o, "auth"),
			ObfsPassword:        mStr(o, "obfs"),
			RecvWindow:          mInt(o, "recv_window"),
			RecvWindowConn:      mInt(o, "recv_window_conn"),
			DisableMTUDiscovery: mBool(o, "disable_mtu_discovery"),
		}
	case model.ProtoTUIC:
		n.UUID = mStr(o, "uuid")
		n.Password = mStr(o, "password")
		n.TUIC = &model.TUICOpts{
			CongestionControl: mStr(o, "congestion_control"),
			UDPRelayMode:      mStr(o, "udp_relay_mode"),
			ZeroRTTHandshake:  mBool(o, "zero_rtt_handshake"),
		}
	case model.ProtoAnyTLS:
		n.Password = mStr(o, "password")
		n.AnyTLS = &model.AnyTLSOpts{
			IdleSessionCheckInterval: mStr(o, "idle_session_check_interval"),
			IdleSessionTimeout:       mStr(o, "idle_session_timeout"),
			MinIdleSession:           mInt(o, "min_idle_session"),
		}
	case model.ProtoShadowTLS:
		n.Password = mStr(o, "password")
		n.ShadowTLS = &model.ShadowTLSOpts{
			Version:  mInt(o, "version"),
			Password: mStr(o, "password"),
		}
	case model.ProtoSOCKS, model.ProtoHTTP:
		n.Username = mStr(o, "username")
		n.Password = mStr(o, "password")
	case model.ProtoSSH:
		n.Username = mStr(o, "user")
		n.Password = mStr(o, "password")
		n.SSH = &model.SSHOpts{
			PrivateKey:           mStr(o, "private_key"),
			PrivateKeyPassphrase: mStr(o, "private_key_passphrase"),
			HostKeyAlgorithms:    mStrSlice(o, "host_key_algorithms"),
			ClientVersion:        mStr(o, "client_version"),
		}
	case model.ProtoWireGuard:
		singboxWireGuard(n, o)
	default:
		return nil, fmt.Errorf("no import mapping for %q", proto)
	}

	singboxApplyTransport(n, o)
	singboxApplyTLS(n, o)
	singboxApplyMux(n, o)

	if err := n.Validate(); err != nil {
		return nil, err
	}
	return n, nil
}

// singboxWireGuard handles both WireGuard shapes: the 1.11+ endpoint with a
// peers array, and the older flat outbound.
func singboxWireGuard(n *model.Node, o map[string]any) {
	wg := &model.WireGuardOpts{
		PrivateKey:   mStr(o, "private_key"),
		LocalAddress: mStrSlice(o, "address", "local_address"),
		MTU:          mInt(o, "mtu"),
	}

	if peers := mList(o, "peers"); len(peers) > 0 {
		// Obelisk's node model carries a single peer; a multi-peer endpoint is
		// imported as its first peer, which is what these configs always mean in
		// a client context.
		peer := peers[0]
		wg.PeerPublicKey = mStr(peer, "public_key")
		wg.PreSharedKey = mStr(peer, "pre_shared_key")
		wg.Reserved = mIntSlice(peer, "reserved")
		wg.KeepAlive = mInt(peer, "persistent_keepalive_interval")
		n.Server = mStr(peer, "address", "server")
		n.Port = mInt(peer, "port", "server_port")
	} else {
		wg.PeerPublicKey = mStr(o, "peer_public_key")
		wg.PreSharedKey = mStr(o, "pre_shared_key")
		wg.Reserved = mIntSlice(o, "reserved")
	}
	n.WireGuard = wg
}

// singboxApplyTransport maps the shared "transport" object.
func singboxApplyTransport(n *model.Node, o map[string]any) {
	tr := mMap(o, "transport")
	if len(tr) == 0 {
		if n.Transport.Type == "" {
			n.Transport.Type = model.TransportTCP
		}
		return
	}

	t, ok := model.ParseTransport(mStr(tr, "type"))
	if !ok {
		t = model.TransportTCP
	}
	n.Transport.Type = t
	n.Transport.Path = mStr(tr, "path")
	n.Transport.ServiceName = mStr(tr, "service_name")
	n.Transport.Method = mStr(tr, "method")
	n.Transport.Headers = mStrMap(tr, "headers")
	n.Transport.MaxEarlyData = mInt(tr, "max_early_data")
	n.Transport.EarlyDataHeaderName = mStr(tr, "early_data_header_name")

	if hosts := mStrSlice(tr, "host"); len(hosts) > 0 {
		n.Transport.Host = hosts
	} else if h := n.Transport.Headers["Host"]; h != "" {
		n.Transport.Host = []string{h}
	}
}

// singboxApplyTLS maps the shared "tls" object, including its utls and reality
// sub-objects.
func singboxApplyTLS(n *model.Node, o map[string]any) {
	tls := mMap(o, "tls")
	if len(tls) == 0 || !mBool(tls, "enabled") {
		n.TLS.Security = model.SecurityNone
		return
	}

	n.TLS.Security = model.SecurityTLS
	n.TLS.SNI = mStr(tls, "server_name")
	n.TLS.AllowInsecure = mBool(tls, "insecure")
	n.TLS.ALPN = mStrSlice(tls, "alpn")

	if utls := mMap(tls, "utls"); mBool(utls, "enabled") {
		n.TLS.Fingerprint = mStr(utls, "fingerprint")
	}
	if reality := mMap(tls, "reality"); mBool(reality, "enabled") {
		n.TLS.Security = model.SecurityReality
		n.TLS.PublicKey = mStr(reality, "public_key")
		n.TLS.ShortID = mStr(reality, "short_id")
	}
	if ech := mMap(tls, "ech"); mBool(ech, "enabled") {
		n.TLS.ECHEnabled = true
		if cfg := mStrSlice(ech, "config"); len(cfg) > 0 {
			n.TLS.ECHConfig = cfg[0]
		}
	}
	if certs := mStrSlice(tls, "certificate"); len(certs) > 0 {
		n.TLS.Certificate = certs[0]
	}

	if n.TLS.SNI == "" {
		n.TLS.SNI = n.Server
	}
}

// singboxApplyMux maps the shared "multiplex" object.
func singboxApplyMux(n *model.Node, o map[string]any) {
	mux := mMap(o, "multiplex")
	if len(mux) == 0 || !mBool(mux, "enabled") {
		return
	}
	n.Mux = &model.MuxOpts{
		Enabled:    true,
		Protocol:   mStr(mux, "protocol"),
		MaxConns:   mInt(mux, "max_connections"),
		MinStreams: mInt(mux, "min_streams"),
		MaxStreams: mInt(mux, "max_streams"),
		Padding:    mBool(mux, "padding"),
	}
}
