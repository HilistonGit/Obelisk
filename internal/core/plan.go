package core

import (
	"fmt"

	"github.com/obelisk-project/obelisk/internal/core/singbox"
	"github.com/obelisk-project/obelisk/internal/core/xray"
	"github.com/obelisk-project/obelisk/internal/model"
)

// PlanOptions configures how nodes are distributed across the two cores.
type PlanOptions struct {
	// Policy resolves which core carries a node when both are capable.
	Policy model.Policy

	// BridgeListen is the address Xray's per-node SOCKS listeners bind to. It
	// must stay on the loopback interface: these listeners are unauthenticated,
	// and binding them anywhere else would hand the whole LAN an open proxy.
	BridgeListen string

	// BridgePortBase is the first loopback port allocated to a bridge.
	BridgePortBase int

	// RouteMark is the fwmark Xray stamps on its own outbound sockets so that
	// the firewall layer can let them past the transparent capture. Without it,
	// Xray's connection to a remote server is itself captured by the front core
	// and loops back into the tunnel it is supposed to be leaving.
	RouteMark int
}

// DefaultPlanOptions returns Obelisk's out-of-the-box topology settings.
func DefaultPlanOptions() PlanOptions {
	return PlanOptions{
		Policy:         model.DefaultPolicy(),
		BridgeListen:   "127.0.0.1",
		BridgePortBase: 24100,
		RouteMark:      0x4f42, // "OB"
	}
}

// Assignment records the core chosen for one node and how it is wired up.
type Assignment struct {
	Node *model.Node  `json:"node"`
	Core model.CoreID `json:"core"`
	Tag  string       `json:"tag"`

	// BridgePort is the loopback port the front core dials, set only when the
	// node is carried by Xray.
	BridgePort int `json:"bridge_port,omitempty"`

	// Reason explains why no core could carry the node; when it is non-empty the
	// assignment is a rejection rather than a placement.
	Reason string `json:"reason,omitempty"`
}

// Carried reports whether the node was successfully placed on a core.
func (a Assignment) Carried() bool { return a.Reason == "" }

// Plan is the resolved topology: every node placed on a core, every Xray node
// given a loopback bridge, and both cores' configurations ready to render.
type Plan struct {
	Options PlanOptions

	// Assignments covers every node handed to BuildPlan, in input order,
	// including the ones no core can run.
	Assignments []Assignment

	bridges          []xray.Bridge
	singboxOutbounds []map[string]any
	singboxEndpoints []map[string]any
}

// BuildPlan distributes nodes across the cores and wires the Xray-carried ones
// through loopback bridges.
//
// A node that neither core can run is recorded with its reason rather than
// aborting the plan: one dead node in a hundred-node subscription must not stop
// the other ninety-nine from working.
func BuildPlan(nodes []*model.Node, opts PlanOptions) (*Plan, error) {
	if opts.BridgeListen == "" {
		opts.BridgeListen = "127.0.0.1"
	}
	if opts.BridgePortBase <= 0 {
		opts.BridgePortBase = 24100
	}
	if opts.Policy.Default == "" {
		opts.Policy = model.DefaultPolicy()
	}

	p := &Plan{Options: opts}
	nextPort := opts.BridgePortBase
	seenTags := make(map[string]bool, len(nodes))

	for _, n := range nodes {
		if n.ID == "" {
			n.AssignID()
		}
		tag := "node-" + n.ID
		if seenTags[tag] {
			// Two entries with the same fingerprint are the same server; the
			// duplicate is dropped rather than generating a colliding tag.
			continue
		}
		seenTags[tag] = true

		core, err := model.SelectCore(n, opts.Policy)
		if err != nil {
			p.Assignments = append(p.Assignments, Assignment{
				Node:   n,
				Tag:    tag,
				Reason: err.Error(),
			})
			continue
		}

		a := Assignment{Node: n, Core: core, Tag: tag}

		switch core {
		case model.CoreSingBox:
			rendered, err := singbox.Outbound(n, tag)
			if err != nil {
				a.Reason = err.Error()
				a.Core = ""
				break
			}
			if rendered.Endpoint {
				p.singboxEndpoints = append(p.singboxEndpoints, rendered.Object)
			} else {
				p.singboxOutbounds = append(p.singboxOutbounds, rendered.Object)
			}

		case model.CoreXray:
			if nextPort > 65535 {
				a.Reason = "no loopback ports left for an Xray bridge"
				a.Core = ""
				break
			}
			// Validate the Xray rendering now so a bad node surfaces here rather
			// than as an opaque parse error from the core at startup.
			if _, err := xray.Outbound(n, tag); err != nil {
				a.Reason = err.Error()
				a.Core = ""
				break
			}

			a.BridgePort = nextPort
			nextPort++

			p.bridges = append(p.bridges, xray.Bridge{
				Node:        n,
				InboundTag:  "bridge-" + n.ID,
				OutboundTag: tag,
				ListenAddr:  opts.BridgeListen,
				ListenPort:  a.BridgePort,
			})
			// From the front core's point of view an Xray node is an ordinary
			// SOCKS server that happens to live on the loopback interface.
			p.singboxOutbounds = append(p.singboxOutbounds, map[string]any{
				"type":        "socks",
				"tag":         tag,
				"server":      opts.BridgeListen,
				"server_port": a.BridgePort,
				"version":     "5",
			})
		}

		p.Assignments = append(p.Assignments, a)
	}

	return p, nil
}

// CarriedTags returns the outbound tags of every node that was placed, in plan
// order. These are the tags routing rules and groups may reference.
func (p *Plan) CarriedTags() []string {
	tags := make([]string, 0, len(p.Assignments))
	for _, a := range p.Assignments {
		if a.Carried() {
			tags = append(tags, a.Tag)
		}
	}
	return tags
}

// Rejected returns the assignments no core could carry.
func (p *Plan) Rejected() []Assignment {
	var out []Assignment
	for _, a := range p.Assignments {
		if !a.Carried() {
			out = append(out, a)
		}
	}
	return out
}

// CountByCore returns how many nodes each core ended up carrying.
func (p *Plan) CountByCore() map[model.CoreID]int {
	counts := map[model.CoreID]int{}
	for _, a := range p.Assignments {
		if a.Carried() {
			counts[a.Core]++
		}
	}
	return counts
}

// NeedsXray reports whether the plan requires the Xray process to run at all.
// When every node is carried by the front core, Obelisk does not start Xray, and
// a router saves an entire process's worth of memory.
func (p *Plan) NeedsXray() bool { return len(p.bridges) > 0 }

// XrayConfig renders the backend core's configuration, or nil when no node needs
// Xray.
func (p *Plan) XrayConfig(opts xray.Options) ([]byte, error) {
	if !p.NeedsXray() {
		return nil, nil
	}
	if opts.RouteMark == 0 {
		opts.RouteMark = p.Options.RouteMark
	}
	return xray.BuildConfig(p.bridges, opts)
}

// SingBoxConfig renders the front core's configuration. The caller supplies the
// inbound, DNS and routing halves; the plan supplies the outbounds.
func (p *Plan) SingBoxConfig(cfg singbox.Config) ([]byte, error) {
	if len(p.singboxOutbounds) == 0 && len(p.singboxEndpoints) == 0 {
		return nil, fmt.Errorf("plan carries no usable nodes")
	}
	cfg.Outbounds = append(append([]map[string]any(nil), p.singboxOutbounds...), cfg.Outbounds...)
	cfg.Endpoints = append(append([]map[string]any(nil), p.singboxEndpoints...), cfg.Endpoints...)
	return singbox.BuildConfig(cfg)
}
