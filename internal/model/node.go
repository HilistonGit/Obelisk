package model

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net"
	"strconv"
	"strings"
)

// Node is Obelisk's normalized, core-agnostic representation of a single
// outbound server. Every subscription format and share link is parsed into this
// shape, and every core config is generated from it. Nothing outside
// internal/subs should need to know what a "vmess://" link looks like, and
// nothing outside internal/core should need to know what Xray's JSON looks like.
type Node struct {
	ID       string   `json:"id"`
	Name     string   `json:"name"`
	Protocol Protocol `json:"protocol"`
	Server   string   `json:"server"`
	Port     int      `json:"port"`

	// Identity. Which fields are meaningful depends on Protocol; parsers fill
	// only what the protocol defines and generators read only what they need.
	UUID          string `json:"uuid,omitempty"`           // vless, vmess, tuic
	Password      string `json:"password,omitempty"`       // trojan, ss, hysteria2, tuic, anytls, socks, http, ssh
	Username      string `json:"username,omitempty"`       // socks, http, ssh
	Method        string `json:"method,omitempty"`         // shadowsocks cipher
	Plugin        string `json:"plugin,omitempty"`         // shadowsocks SIP003 plugin: obfs-local, v2ray-plugin
	PluginOpts    string `json:"plugin_opts,omitempty"`    // raw SIP003 plugin option string
	AlterID       int    `json:"alter_id,omitempty"`       // vmess legacy (0 for AEAD)
	VMessSecurity string `json:"vmess_security,omitempty"` // auto, aes-128-gcm, chacha20-poly1305, none, zero
	Flow          string `json:"flow,omitempty"`           // vless: xtls-rprx-vision

	Transport TransportOpts `json:"transport"`
	TLS       TLSOpts       `json:"tls"`
	Mux       *MuxOpts      `json:"mux,omitempty"`

	// Protocol-specific extensions, set only for their own protocol.
	Hysteria  *HysteriaOpts  `json:"hysteria,omitempty"`
	TUIC      *TUICOpts      `json:"tuic,omitempty"`
	WireGuard *WireGuardOpts `json:"wireguard,omitempty"`
	SSR       *SSROpts       `json:"ssr,omitempty"`
	SSH       *SSHOpts       `json:"ssh,omitempty"`
	AnyTLS    *AnyTLSOpts    `json:"anytls,omitempty"`
	ShadowTLS *ShadowTLSOpts `json:"shadowtls,omitempty"`

	// UDP behaviour.
	UDPOverTCP     bool   `json:"udp_over_tcp,omitempty"`
	PacketEncoding string `json:"packet_encoding,omitempty"` // "", packetaddr, xudp

	// Provenance and policy.
	Source     string         `json:"source,omitempty"` // subscription ID; empty for manual nodes
	SourceName string         `json:"source_name,omitempty"`
	CorePref   CorePreference `json:"core_pref,omitempty"` // auto unless pinned by the user
	Raw        string         `json:"raw,omitempty"`       // original link/JSON, kept for debugging and round-trip

	// Free-form leftovers a parser understood syntactically but Obelisk has no
	// first-class field for. Generators may pass selected keys through.
	Extra map[string]string `json:"extra,omitempty"`
}

// TransportOpts describes the stream transport beneath the protocol.
type TransportOpts struct {
	Type Transport `json:"type"`

	// Host header(s). Multiple values are legal for ws/http and are load
	// balanced by the cores that support it.
	Host    []string          `json:"host,omitempty"`
	Path    string            `json:"path,omitempty"`
	Headers map[string]string `json:"headers,omitempty"`

	ServiceName   string `json:"service_name,omitempty"` // grpc
	GRPCMultiMode bool   `json:"grpc_multi_mode,omitempty"`

	Method string `json:"method,omitempty"` // http transport request method

	// xhttp / splithttp
	XHTTPMode  string `json:"xhttp_mode,omitempty"` // auto, packet-up, stream-up, stream-one
	XHTTPExtra string `json:"xhttp_extra,omitempty"`

	// mKCP
	Seed       string `json:"seed,omitempty"`
	HeaderType string `json:"header_type,omitempty"` // none, srtp, utp, wechat-video, dtls, wireguard

	// WebSocket early data
	MaxEarlyData        int    `json:"max_early_data,omitempty"`
	EarlyDataHeaderName string `json:"early_data_header_name,omitempty"`
}

// TLSOpts describes transport-layer security, including REALITY.
type TLSOpts struct {
	Security      Security `json:"security"`
	SNI           string   `json:"sni,omitempty"`
	ALPN          []string `json:"alpn,omitempty"`
	Fingerprint   string   `json:"fingerprint,omitempty"` // uTLS profile: chrome, firefox, safari, random...
	AllowInsecure bool     `json:"allow_insecure,omitempty"`

	// REALITY
	PublicKey string `json:"public_key,omitempty"`
	ShortID   string `json:"short_id,omitempty"`
	SpiderX   string `json:"spider_x,omitempty"`

	// Encrypted Client Hello
	ECHEnabled bool   `json:"ech_enabled,omitempty"`
	ECHConfig  string `json:"ech_config,omitempty"`

	// Pinned certificate / CA, PEM encoded.
	Certificate string `json:"certificate,omitempty"`

	// VLESS post-quantum encryption parameter (Xray-only).
	Encryption string `json:"encryption,omitempty"`
}

// MuxOpts describes connection multiplexing.
type MuxOpts struct {
	Enabled         bool   `json:"enabled"`
	Protocol        string `json:"protocol,omitempty"` // smux, yamux, h2mux (sing-box); "" for Xray's native mux
	MaxConns        int    `json:"max_connections,omitempty"`
	MinStreams      int    `json:"min_streams,omitempty"`
	MaxStreams      int    `json:"max_streams,omitempty"`
	Padding         bool   `json:"padding,omitempty"`
	Concurrency     int    `json:"concurrency,omitempty"` // Xray mux concurrency
	XUDPConcurrency int    `json:"xudp_concurrency,omitempty"`
}

// HysteriaOpts covers both Hysteria v1 and v2 knobs.
type HysteriaOpts struct {
	UpMbps              int    `json:"up_mbps,omitempty"`
	DownMbps            int    `json:"down_mbps,omitempty"`
	Obfs                string `json:"obfs,omitempty"`          // v2: "salamander"
	ObfsPassword        string `json:"obfs_password,omitempty"` // v2 obfs password / v1 obfs string
	Auth                string `json:"auth,omitempty"`          // v1 auth string
	AuthBase64          string `json:"auth_base64,omitempty"`   // v1 base64 auth
	Ports               string `json:"ports,omitempty"`         // port hopping range, e.g. "20000-30000"
	HopInterval         int    `json:"hop_interval,omitempty"`  // seconds
	RecvWindow          int    `json:"recv_window,omitempty"`
	RecvWindowConn      int    `json:"recv_window_conn,omitempty"`
	DisableMTUDiscovery bool   `json:"disable_mtu_discovery,omitempty"`
}

// TUICOpts covers TUIC v5 knobs.
type TUICOpts struct {
	CongestionControl string `json:"congestion_control,omitempty"` // cubic, new_reno, bbr
	UDPRelayMode      string `json:"udp_relay_mode,omitempty"`     // native, quic
	ZeroRTTHandshake  bool   `json:"zero_rtt_handshake,omitempty"`
	HeartbeatSeconds  int    `json:"heartbeat,omitempty"`
}

// WireGuardOpts describes a WireGuard peer used as an outbound.
type WireGuardOpts struct {
	PrivateKey    string   `json:"private_key"`
	PeerPublicKey string   `json:"peer_public_key"`
	PreSharedKey  string   `json:"pre_shared_key,omitempty"`
	LocalAddress  []string `json:"local_address"` // CIDRs assigned to the local interface
	MTU           int      `json:"mtu,omitempty"`
	Reserved      []int    `json:"reserved,omitempty"`
	KeepAlive     int      `json:"keepalive,omitempty"`
}

// SSROpts describes the ShadowsocksR obfuscation layer.
type SSROpts struct {
	Protocol      string `json:"protocol"`
	ProtocolParam string `json:"protocol_param,omitempty"`
	Obfs          string `json:"obfs"`
	ObfsParam     string `json:"obfs_param,omitempty"`
}

// SSHOpts describes an SSH tunnel outbound.
type SSHOpts struct {
	PrivateKey           string   `json:"private_key,omitempty"`
	PrivateKeyPassphrase string   `json:"private_key_passphrase,omitempty"`
	HostKeyAlgorithms    []string `json:"host_key_algorithms,omitempty"`
	ClientVersion        string   `json:"client_version,omitempty"`
}

// AnyTLSOpts describes AnyTLS session pooling.
type AnyTLSOpts struct {
	IdleSessionCheckInterval string `json:"idle_session_check_interval,omitempty"`
	IdleSessionTimeout       string `json:"idle_session_timeout,omitempty"`
	MinIdleSession           int    `json:"min_idle_session,omitempty"`
}

// ShadowTLSOpts describes a ShadowTLS v3 wrapper.
type ShadowTLSOpts struct {
	Version  int    `json:"version,omitempty"` // 1, 2 or 3
	Password string `json:"password,omitempty"`
}

// Address returns the "host:port" form of the node endpoint.
func (n *Node) Address() string {
	return net.JoinHostPort(n.Server, strconv.Itoa(n.Port))
}

// Fingerprint returns a stable identity for the node: the tuple that actually
// determines where and how traffic is sent. Renaming a node in a subscription
// must not change it, so the display name is deliberately excluded. This is what
// lets Obelisk preserve per-node latency history and user pins across
// subscription updates.
func (n *Node) Fingerprint() string {
	var b strings.Builder
	fmt.Fprintf(&b, "%s|%s|%d|", n.Protocol, strings.ToLower(n.Server), n.Port)

	switch n.Protocol {
	case ProtoVLESS, ProtoVMess:
		b.WriteString(n.UUID)
	case ProtoTUIC:
		b.WriteString(n.UUID + ":" + n.Password)
	case ProtoShadowsocks, ProtoShadowsocksR:
		b.WriteString(n.Method + ":" + n.Password)
	case ProtoWireGuard:
		if n.WireGuard != nil {
			b.WriteString(n.WireGuard.PeerPublicKey)
		}
	default:
		b.WriteString(n.Username + ":" + n.Password)
	}

	// The transport and TLS parameters are part of the identity: the same
	// server/port pair can legitimately host several distinct configurations.
	fmt.Fprintf(&b, "|%s|%s|%s|%s|%s",
		n.Transport.Type, n.Transport.Path, n.Transport.ServiceName,
		n.TLS.Security, n.TLS.SNI)
	if len(n.Transport.Host) > 0 {
		b.WriteString("|" + strings.Join(n.Transport.Host, ","))
	}
	if n.TLS.PublicKey != "" {
		b.WriteString("|" + n.TLS.PublicKey + "|" + n.TLS.ShortID)
	}
	return b.String()
}

// AssignID derives and stores the node's stable ID from its fingerprint.
func (n *Node) AssignID() {
	sum := sha256.Sum256([]byte(n.Fingerprint()))
	n.ID = hex.EncodeToString(sum[:8])
}

// Validate reports whether the node carries the minimum information its
// protocol requires to be usable. Parsers call it before emitting a node so a
// malformed line in a subscription is dropped rather than breaking a core.
func (n *Node) Validate() error {
	if n.Protocol == "" {
		return fmt.Errorf("protocol is empty")
	}
	if n.Protocol != ProtoWireGuard && n.Protocol != ProtoDirect {
		if n.Server == "" {
			return fmt.Errorf("%s: server address is empty", n.Protocol)
		}
		if n.Port <= 0 || n.Port > 65535 {
			return fmt.Errorf("%s: port %d out of range", n.Protocol, n.Port)
		}
	}

	switch n.Protocol {
	case ProtoVLESS, ProtoVMess:
		if n.UUID == "" {
			return fmt.Errorf("%s: uuid is empty", n.Protocol)
		}
	case ProtoTrojan, ProtoHysteria2, ProtoAnyTLS:
		if n.Password == "" {
			return fmt.Errorf("%s: password is empty", n.Protocol)
		}
	case ProtoShadowsocks:
		if n.Method == "" {
			return fmt.Errorf("shadowsocks: method is empty")
		}
		if n.Password == "" {
			return fmt.Errorf("shadowsocks: password is empty")
		}
	case ProtoShadowsocksR:
		if n.SSR == nil {
			return fmt.Errorf("shadowsocksr: obfuscation parameters are missing")
		}
	case ProtoTUIC:
		if n.UUID == "" {
			return fmt.Errorf("tuic: uuid is empty")
		}
	case ProtoWireGuard:
		if n.WireGuard == nil || n.WireGuard.PrivateKey == "" {
			return fmt.Errorf("wireguard: private key is missing")
		}
		if len(n.WireGuard.LocalAddress) == 0 {
			return fmt.Errorf("wireguard: local address is missing")
		}
	}
	return nil
}

// DisplayName returns a non-empty human label, synthesizing one from the
// endpoint when the subscription supplied no tag.
func (n *Node) DisplayName() string {
	if strings.TrimSpace(n.Name) != "" {
		return n.Name
	}
	return fmt.Sprintf("%s %s", n.Protocol, n.Address())
}

// SetExtra records a free-form key that has no first-class field.
func (n *Node) SetExtra(key, value string) {
	if value == "" {
		return
	}
	if n.Extra == nil {
		n.Extra = make(map[string]string)
	}
	n.Extra[key] = value
}

// Clone returns a deep copy, so that callers can mutate a node (for example to
// pin it to a core or rewrite its tag) without disturbing the stored original.
func (n *Node) Clone() *Node {
	c := *n

	c.Transport.Host = append([]string(nil), n.Transport.Host...)
	c.Transport.Headers = cloneStringMap(n.Transport.Headers)
	c.TLS.ALPN = append([]string(nil), n.TLS.ALPN...)
	c.Extra = cloneStringMap(n.Extra)

	if n.Mux != nil {
		v := *n.Mux
		c.Mux = &v
	}
	if n.Hysteria != nil {
		v := *n.Hysteria
		c.Hysteria = &v
	}
	if n.TUIC != nil {
		v := *n.TUIC
		c.TUIC = &v
	}
	if n.WireGuard != nil {
		v := *n.WireGuard
		v.LocalAddress = append([]string(nil), n.WireGuard.LocalAddress...)
		v.Reserved = append([]int(nil), n.WireGuard.Reserved...)
		c.WireGuard = &v
	}
	if n.SSR != nil {
		v := *n.SSR
		c.SSR = &v
	}
	if n.SSH != nil {
		v := *n.SSH
		v.HostKeyAlgorithms = append([]string(nil), n.SSH.HostKeyAlgorithms...)
		c.SSH = &v
	}
	if n.AnyTLS != nil {
		v := *n.AnyTLS
		c.AnyTLS = &v
	}
	if n.ShadowTLS != nil {
		v := *n.ShadowTLS
		c.ShadowTLS = &v
	}
	return &c
}

func cloneStringMap(m map[string]string) map[string]string {
	if m == nil {
		return nil
	}
	c := make(map[string]string, len(m))
	for k, v := range m {
		c[k] = v
	}
	return c
}
