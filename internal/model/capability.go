package model

import "fmt"

// CoreID identifies one of the two proxy cores Obelisk drives. Obelisk never
// patches the cores themselves; it only decides which one is competent to carry
// a given node and generates that core's native configuration.
type CoreID string

const (
	CoreXray    CoreID = "xray"
	CoreSingBox CoreID = "sing-box"
)

// AllCores lists every core Obelisk can drive, in stable order.
var AllCores = []CoreID{CoreSingBox, CoreXray}

// CorePreference is a user-facing override recorded on a node or a group.
// PreferAuto defers to the capability matrix and the active Policy.
type CorePreference string

const (
	PreferAuto    CorePreference = "auto"
	PreferXray    CorePreference = "xray"
	PreferSingBox CorePreference = "sing-box"
)

// coreID maps a hard preference onto a CoreID. Returns false for PreferAuto.
func (p CorePreference) coreID() (CoreID, bool) {
	switch p {
	case PreferXray:
		return CoreXray, true
	case PreferSingBox:
		return CoreSingBox, true
	default:
		return "", false
	}
}

// UnsupportedError explains why a core cannot carry a node. It is surfaced
// verbatim in the UI and CLI, because "this node does not work" is useless to a
// user compared with "Xray has no Hysteria2 implementation".
type UnsupportedError struct {
	Core   CoreID
	Node   string
	Reason string
}

func (e *UnsupportedError) Error() string {
	return fmt.Sprintf("%s cannot carry %q: %s", e.Core, e.Node, e.Reason)
}

// Supports reports whether the given core can carry the node, and if not, why.
//
// The matrix below reflects Xray-core 25.x and sing-box 1.13.x. It is the single
// place in Obelisk that encodes core-specific knowledge about what exists; when
// a core gains a protocol, only this file changes.
func Supports(core CoreID, n *Node) (bool, string) {
	switch core {
	case CoreXray:
		return xraySupports(n)
	case CoreSingBox:
		return singboxSupports(n)
	default:
		return false, "unknown core"
	}
}

func xraySupports(n *Node) (bool, string) {
	switch n.Protocol {
	case ProtoVLESS, ProtoVMess, ProtoTrojan, ProtoShadowsocks,
		ProtoSOCKS, ProtoHTTP, ProtoWireGuard, ProtoDirect:
		// supported, continue to transport checks
	case ProtoHysteria, ProtoHysteria2, ProtoTUIC, ProtoAnyTLS, ProtoShadowTLS, ProtoSSH:
		return false, fmt.Sprintf("Xray has no %s implementation", n.Protocol)
	case ProtoShadowsocksR:
		return false, "ShadowsocksR was removed from Xray and is not supported by either core"
	default:
		return false, fmt.Sprintf("unknown protocol %q", n.Protocol)
	}

	switch n.Transport.Type {
	case TransportTCP, TransportWebSocket, TransportGRPC, TransportHTTP,
		TransportHTTPUpgrade, TransportXHTTP, TransportKCP, "":
		// supported
	case TransportQUIC:
		return false, "Xray removed the standalone QUIC transport"
	default:
		return false, fmt.Sprintf("Xray has no %q transport", n.Transport.Type)
	}

	// SIP003 Shadowsocks plugins (simple-obfs, v2ray-plugin) are implemented by
	// sing-box but have never existed in Xray.
	if n.Plugin != "" {
		return false, fmt.Sprintf("Xray has no Shadowsocks plugin support (%s); this node requires sing-box", n.Plugin)
	}

	// WireGuard in Xray is an outbound only; it has no endpoint semantics, which
	// is fine for our use, but it does not accept a peer keepalive list.
	return true, ""
}

func singboxSupports(n *Node) (bool, string) {
	switch n.Protocol {
	case ProtoVLESS, ProtoVMess, ProtoTrojan, ProtoShadowsocks, ProtoSOCKS,
		ProtoHTTP, ProtoWireGuard, ProtoHysteria, ProtoHysteria2, ProtoTUIC,
		ProtoAnyTLS, ProtoShadowTLS, ProtoSSH, ProtoDirect:
		// supported, continue to transport checks
	case ProtoShadowsocksR:
		return false, "ShadowsocksR is not implemented by sing-box and is not supported by either core"
	default:
		return false, fmt.Sprintf("unknown protocol %q", n.Protocol)
	}

	switch n.Transport.Type {
	case TransportTCP, TransportWebSocket, TransportGRPC, TransportHTTP,
		TransportHTTPUpgrade, TransportQUIC, "":
		// supported
	case TransportXHTTP:
		return false, "sing-box has no XHTTP transport; this node requires Xray"
	case TransportKCP:
		return false, "sing-box has no mKCP transport; this node requires Xray"
	default:
		return false, fmt.Sprintf("sing-box has no %q transport", n.Transport.Type)
	}

	// HTTP camouflage over the raw TCP transport is a V2Ray/Xray feature that
	// sing-box never implemented.
	if n.Transport.Type == TransportTCP && n.Transport.HeaderType == "http" {
		return false, "sing-box has no HTTP camouflage on the raw TCP transport; this node requires Xray"
	}

	// VLESS post-quantum encryption is an Xray extension with no sing-box
	// counterpart; a node carrying it must not be handed to sing-box.
	if n.TLS.Encryption != "" && n.TLS.Encryption != "none" {
		return false, "VLESS encryption is an Xray-only extension; this node requires Xray"
	}
	return true, ""
}

// CapableCores returns every core that can carry the node, in AllCores order.
func CapableCores(n *Node) []CoreID {
	var out []CoreID
	for _, c := range AllCores {
		if ok, _ := Supports(c, n); ok {
			out = append(out, c)
		}
	}
	return out
}

// Policy resolves the remaining freedom once capability has been established:
// which core to use when *both* of them can carry a node.
//
// The default is sing-box, and that is a deliberate performance decision rather
// than a preference. sing-box is Obelisk's front core: it owns the TUN/TPROXY
// inbound and the routing tree. A node carried by sing-box is served directly
// from that process, whereas a node carried by Xray costs an extra local SOCKS
// hop between the two cores. On a Raspberry Pi 4 that hop is one more userspace
// copy per packet and a second process's worth of buffers, so Obelisk keeps
// traffic inside the front core unless there is a concrete reason not to.
type Policy struct {
	// Default is the tie-break when both cores are capable and no more specific
	// rule applies.
	Default CoreID `json:"default"`

	// ByProtocol overrides Default for whole protocols.
	ByProtocol map[Protocol]CoreID `json:"by_protocol,omitempty"`

	// PreferXrayForVision routes VLESS nodes using xtls-rprx-vision to Xray,
	// whose Vision implementation is the reference one and can splice TCP
	// connections to avoid a userspace copy. Worth the extra hop on the nodes
	// that carry the most traffic; off by default on very small routers.
	PreferXrayForVision bool `json:"prefer_xray_for_vision"`
}

// DefaultPolicy returns Obelisk's out-of-the-box core selection policy.
func DefaultPolicy() Policy {
	return Policy{
		Default:             CoreSingBox,
		ByProtocol:          map[Protocol]CoreID{},
		PreferXrayForVision: true,
	}
}

// SelectCore decides which core will carry the node.
//
// Resolution order, most specific first:
//  1. an explicit per-node pin set by the user;
//  2. capability — if exactly one core can carry it, that settles it;
//  3. the policy's per-protocol override;
//  4. the Vision heuristic;
//  5. the policy default.
//
// A pin that names a core which cannot carry the node is an error rather than a
// silent fallback: the user asked for something specific and deserves to be told
// it is impossible.
func SelectCore(n *Node, p Policy) (CoreID, error) {
	if pinned, ok := n.CorePref.coreID(); ok {
		if ok, reason := Supports(pinned, n); !ok {
			return "", &UnsupportedError{Core: pinned, Node: n.DisplayName(), Reason: reason}
		}
		return pinned, nil
	}

	capable := CapableCores(n)
	switch len(capable) {
	case 0:
		_, reason := Supports(CoreSingBox, n)
		return "", &UnsupportedError{Core: "", Node: n.DisplayName(), Reason: reason}
	case 1:
		return capable[0], nil
	}

	if c, ok := p.ByProtocol[n.Protocol]; ok {
		if ok, _ := Supports(c, n); ok {
			return c, nil
		}
	}

	if p.PreferXrayForVision && n.Protocol == ProtoVLESS && n.Flow == "xtls-rprx-vision" {
		return CoreXray, nil
	}

	if p.Default != "" {
		if ok, _ := Supports(p.Default, n); ok {
			return p.Default, nil
		}
	}
	return capable[0], nil
}
