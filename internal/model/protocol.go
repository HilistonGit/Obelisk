package model

import "strings"

// Protocol is the normalized outbound protocol identifier used across Obelisk.
// It is deliberately core-agnostic: the same value may be rendered into an Xray
// outbound, a sing-box outbound, or both, depending on the capability matrix.
type Protocol string

const (
	ProtoVLESS        Protocol = "vless"
	ProtoVMess        Protocol = "vmess"
	ProtoTrojan       Protocol = "trojan"
	ProtoShadowsocks  Protocol = "shadowsocks"
	ProtoShadowsocksR Protocol = "shadowsocksr"
	ProtoHysteria     Protocol = "hysteria"
	ProtoHysteria2    Protocol = "hysteria2"
	ProtoTUIC         Protocol = "tuic"
	ProtoAnyTLS       Protocol = "anytls"
	ProtoShadowTLS    Protocol = "shadowtls"
	ProtoWireGuard    Protocol = "wireguard"
	ProtoSOCKS        Protocol = "socks"
	ProtoHTTP         Protocol = "http"
	ProtoSSH          Protocol = "ssh"
	ProtoDirect       Protocol = "direct"
)

// protocolAliases maps the many spellings found in subscriptions, Clash configs
// and share links onto the canonical Protocol values.
var protocolAliases = map[string]Protocol{
	"vless":        ProtoVLESS,
	"vmess":        ProtoVMess,
	"trojan":       ProtoTrojan,
	"trojan-go":    ProtoTrojan,
	"ss":           ProtoShadowsocks,
	"shadowsocks":  ProtoShadowsocks,
	"ssr":          ProtoShadowsocksR,
	"shadowsocksr": ProtoShadowsocksR,
	"hysteria":     ProtoHysteria,
	"hy":           ProtoHysteria,
	"hysteria2":    ProtoHysteria2,
	"hy2":          ProtoHysteria2,
	"tuic":         ProtoTUIC,
	"anytls":       ProtoAnyTLS,
	"shadowtls":    ProtoShadowTLS,
	"wireguard":    ProtoWireGuard,
	"wg":           ProtoWireGuard,
	"socks":        ProtoSOCKS,
	"socks5":       ProtoSOCKS,
	"socks5-tls":   ProtoSOCKS,
	"http":         ProtoHTTP,
	"https":        ProtoHTTP,
	"ssh":          ProtoSSH,
	"direct":       ProtoDirect,
	"freedom":      ProtoDirect,
}

// ParseProtocol normalizes an arbitrary protocol spelling. The second return
// value reports whether the spelling was recognized.
func ParseProtocol(s string) (Protocol, bool) {
	p, ok := protocolAliases[strings.ToLower(strings.TrimSpace(s))]
	return p, ok
}

// String implements fmt.Stringer.
func (p Protocol) String() string { return string(p) }

// Transport is the normalized stream transport carrying the protocol.
type Transport string

const (
	TransportTCP         Transport = "tcp"
	TransportWebSocket   Transport = "ws"
	TransportGRPC        Transport = "grpc"
	TransportHTTP        Transport = "http" // HTTP/2 ("h2" in Xray)
	TransportHTTPUpgrade Transport = "httpupgrade"
	TransportXHTTP       Transport = "xhttp" // Xray-only, supersedes splithttp
	TransportQUIC        Transport = "quic"
	TransportKCP         Transport = "kcp" // mKCP, Xray-only
)

var transportAliases = map[string]Transport{
	"":            TransportTCP,
	"tcp":         TransportTCP,
	"raw":         TransportTCP, // Xray >=1.8.16 renamed "tcp" to "raw"
	"none":        TransportTCP,
	"ws":          TransportWebSocket,
	"websocket":   TransportWebSocket,
	"grpc":        TransportGRPC,
	"gun":         TransportGRPC,
	"h2":          TransportHTTP,
	"http":        TransportHTTP,
	"h2mux":       TransportHTTP,
	"httpupgrade": TransportHTTPUpgrade,
	"xhttp":       TransportXHTTP,
	"splithttp":   TransportXHTTP, // legacy name for the same transport
	"quic":        TransportQUIC,
	"kcp":         TransportKCP,
	"mkcp":        TransportKCP,
}

// ParseTransport normalizes an arbitrary transport spelling.
func ParseTransport(s string) (Transport, bool) {
	t, ok := transportAliases[strings.ToLower(strings.TrimSpace(s))]
	return t, ok
}

// String implements fmt.Stringer.
func (t Transport) String() string { return string(t) }

// Security is the transport-layer security applied on top of the transport.
type Security string

const (
	SecurityNone    Security = "none"
	SecurityTLS     Security = "tls"
	SecurityReality Security = "reality"
)

var securityAliases = map[string]Security{
	"":        SecurityNone,
	"none":    SecurityNone,
	"tls":     SecurityTLS,
	"xtls":    SecurityTLS, // legacy XTLS is folded into TLS + flow
	"reality": SecurityReality,
}

// ParseSecurity normalizes an arbitrary security spelling.
func ParseSecurity(s string) (Security, bool) {
	sec, ok := securityAliases[strings.ToLower(strings.TrimSpace(s))]
	return sec, ok
}

// String implements fmt.Stringer.
func (s Security) String() string { return string(s) }
