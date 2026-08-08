package xray

import (
	"encoding/json"
	"fmt"

	"github.com/obelisk-project/obelisk/internal/model"
)

// Bridge is one node that Xray carries on behalf of the front core.
//
// Xray runs as Obelisk's backend core: it owns no system inbound and never sees
// LAN traffic directly. For each node it carries, it opens a dedicated SOCKS
// listener on the loopback interface, and sing-box dials that listener as an
// ordinary outbound. One listener per node is what makes the hand-off
// unambiguous — Xray routes purely on which port the connection arrived at, so
// no sniffing or metadata has to survive the hop.
type Bridge struct {
	Node        *model.Node
	InboundTag  string
	OutboundTag string
	ListenAddr  string
	ListenPort  int
}

// Options configures the generated Xray instance.
type Options struct {
	// LogLevel is Xray's loglevel: debug, info, warning, error or none.
	LogLevel string

	// MetricsListen is the "host:port" that exposes Xray's expvar metrics for
	// traffic accounting. Empty disables metrics. Requires Xray 1.8.20 or newer,
	// which accepts a listen address directly on the metrics object instead of
	// demanding a hand-wired dokodemo-door inbound.
	MetricsListen string

	// RouteMark is stamped on every node outbound's sockets via SO_MARK.
	//
	// This is what keeps the two cores from eating each other. The front core's
	// transparent capture takes everything leaving the router, including the
	// connection Xray opens to a remote server — which would send that
	// connection straight back into the tunnel it is meant to be establishing.
	// Marking Xray's own sockets gives the firewall layer something to match on
	// so it can let them past. Zero disables the option.
	RouteMark int
}

// DefaultOptions returns the settings Obelisk runs Xray with out of the box.
func DefaultOptions() Options {
	return Options{
		LogLevel:      "warning",
		MetricsListen: "127.0.0.1:24099",
	}
}

// BuildConfig renders a complete Xray configuration for the given bridges.
//
// The returned bytes are indented JSON: Xray does not care, but a human reading
// /etc/obelisk/xray.json while diagnosing a problem very much does.
func BuildConfig(bridges []Bridge, opts Options) ([]byte, error) {
	if len(bridges) == 0 {
		return nil, fmt.Errorf("xray: refusing to build a config with no nodes")
	}

	inbounds := make([]any, 0, len(bridges))
	outbounds := make([]any, 0, len(bridges)+2)
	rules := make([]any, 0, len(bridges)+1)

	for _, b := range bridges {
		if b.Node == nil {
			return nil, fmt.Errorf("xray: bridge %q has no node", b.InboundTag)
		}

		out, err := Outbound(b.Node, b.OutboundTag)
		if err != nil {
			return nil, err
		}
		applyRouteMark(out, opts.RouteMark)
		outbounds = append(outbounds, out)

		inbounds = append(inbounds, map[string]any{
			"tag":      b.InboundTag,
			"listen":   orDefault(b.ListenAddr, "127.0.0.1"),
			"port":     b.ListenPort,
			"protocol": "socks",
			"settings": map[string]any{
				"auth": "noauth",
				"udp":  true,
				// UDP associations are answered from the loopback address the
				// front core dialed, so no external IP has to be guessed.
				"ip": orDefault(b.ListenAddr, "127.0.0.1"),
			},
			// The front core has already sniffed and routed this connection.
			// Sniffing again would cost a copy of every first packet and could
			// only ever reach the same conclusion.
			"sniffing": map[string]any{"enabled": false},
		})

		rules = append(rules, map[string]any{
			"type":        "field",
			"inboundTag":  []any{b.InboundTag},
			"outboundTag": b.OutboundTag,
		})
	}

	// Anything that did not match a bridge rule is discarded rather than sent
	// out of the first outbound, which is what Xray would otherwise do. A
	// misrouted connection must fail closed, not silently take another node.
	outbounds = append(outbounds,
		map[string]any{"tag": tagBlock, "protocol": "blackhole"},
		map[string]any{"tag": tagDirect, "protocol": "freedom", "settings": map[string]any{"domainStrategy": "UseIP"}},
	)
	rules = append(rules, map[string]any{
		"type":        "field",
		"network":     "tcp,udp",
		"outboundTag": tagBlock,
	})

	cfg := map[string]any{
		"log": map[string]any{
			"loglevel": orDefault(opts.LogLevel, "warning"),
		},
		"inbounds":  inbounds,
		"outbounds": outbounds,
		"routing": map[string]any{
			// The front core resolved names already; resolving again here would
			// double every lookup and can disagree with the routing decision that
			// was already made.
			"domainStrategy": "AsIs",
			"rules":          rules,
		},
		"stats": map[string]any{},
		"policy": map[string]any{
			"system": map[string]any{
				"statsOutboundUplink":   true,
				"statsOutboundDownlink": true,
			},
		},
	}

	if opts.MetricsListen != "" {
		cfg["metrics"] = map[string]any{
			"tag":    "metrics",
			"listen": opts.MetricsListen,
		}
	}

	return json.MarshalIndent(cfg, "", "  ")
}

const (
	tagDirect = "direct"
	tagBlock  = "block"
)

// applyRouteMark stamps SO_MARK onto an outbound's sockets, creating the stream
// settings and sockopt objects if the protocol did not already need them.
func applyRouteMark(outbound map[string]any, mark int) {
	if mark <= 0 {
		return
	}

	stream, ok := outbound["streamSettings"].(map[string]any)
	if !ok {
		stream = map[string]any{}
		outbound["streamSettings"] = stream
	}
	sockopt, ok := stream["sockopt"].(map[string]any)
	if !ok {
		sockopt = map[string]any{}
		stream["sockopt"] = sockopt
	}
	sockopt["mark"] = mark
}

// CanCarry reports whether Xray is able to run the node, mirroring the shared
// capability matrix so callers need not import both packages.
func CanCarry(n *model.Node) (bool, string) {
	return model.Supports(model.CoreXray, n)
}
