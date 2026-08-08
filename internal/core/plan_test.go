package core

import (
	"encoding/json"
	"testing"

	"github.com/obelisk-project/obelisk/internal/core/singbox"
	"github.com/obelisk-project/obelisk/internal/core/xray"
	"github.com/obelisk-project/obelisk/internal/model"
	"github.com/obelisk-project/obelisk/internal/subs"
)

// parseAll is a test helper that turns share links into nodes, failing the test
// on the first link that does not parse.
func parseAll(t *testing.T, links ...string) []*model.Node {
	t.Helper()
	nodes := make([]*model.Node, 0, len(links))
	for _, l := range links {
		n, err := subs.ParseURI(l)
		if err != nil {
			t.Fatalf("ParseURI(%q): %v", l, err)
		}
		nodes = append(nodes, n)
	}
	return nodes
}

const (
	linkVisionVLESS = "vless://d342d11e-d424-4583-b36e-524ab1f0afa4@a.example.com:443" +
		"?security=reality&pbk=PUBKEY&sid=abcd&sni=www.microsoft.com&flow=xtls-rprx-vision#Vision"
	linkPlainVLESS = "vless://d342d11e-d424-4583-b36e-524ab1f0afa4@b.example.com:443" +
		"?security=tls&type=ws&path=/ws#Plain"
	linkXHTTP = "vless://d342d11e-d424-4583-b36e-524ab1f0afa4@c.example.com:443" +
		"?security=tls&type=xhttp&path=/x#XHTTP"
	linkHysteria2 = "hy2://pw@d.example.com:443?sni=d.example.com#HY2"
)

func TestPlanRoutesNodesToTheOnlyCapableCore(t *testing.T) {
	nodes := parseAll(t, linkXHTTP, linkHysteria2)

	plan, err := BuildPlan(nodes, DefaultPlanOptions())
	if err != nil {
		t.Fatalf("BuildPlan: %v", err)
	}

	if got := plan.Assignments[0].Core; got != model.CoreXray {
		t.Errorf("XHTTP node went to %q; only Xray implements that transport", got)
	}
	if got := plan.Assignments[1].Core; got != model.CoreSingBox {
		t.Errorf("Hysteria2 node went to %q; only sing-box implements that protocol", got)
	}
}

func TestPlanKeepsTrafficInTheFrontCoreByDefault(t *testing.T) {
	// Both cores can carry a plain VLESS-over-WebSocket node. The default policy
	// keeps it in sing-box so that it costs no loopback hop.
	plan, err := BuildPlan(parseAll(t, linkPlainVLESS), DefaultPlanOptions())
	if err != nil {
		t.Fatalf("BuildPlan: %v", err)
	}
	if got := plan.Assignments[0].Core; got != model.CoreSingBox {
		t.Errorf("Core = %q, want sing-box when both cores are capable", got)
	}
	if plan.NeedsXray() {
		t.Error("Xray must not be started when no node requires it")
	}
}

func TestPlanSendsVisionToXrayWhenPolicyAsks(t *testing.T) {
	opts := DefaultPlanOptions()
	if !opts.Policy.PreferXrayForVision {
		t.Fatal("the default policy is expected to prefer Xray for Vision")
	}

	plan, err := BuildPlan(parseAll(t, linkVisionVLESS), opts)
	if err != nil {
		t.Fatalf("BuildPlan: %v", err)
	}
	if got := plan.Assignments[0].Core; got != model.CoreXray {
		t.Errorf("Core = %q, want xray for an XTLS Vision node", got)
	}

	// With the preference off, the same node stays in the front core.
	opts.Policy.PreferXrayForVision = false
	plan, err = BuildPlan(parseAll(t, linkVisionVLESS), opts)
	if err != nil {
		t.Fatalf("BuildPlan: %v", err)
	}
	if got := plan.Assignments[0].Core; got != model.CoreSingBox {
		t.Errorf("Core = %q, want sing-box once the Vision preference is off", got)
	}
}

func TestPlanAllocatesOneBridgePortPerXrayNode(t *testing.T) {
	opts := DefaultPlanOptions()
	plan, err := BuildPlan(parseAll(t, linkXHTTP, linkVisionVLESS, linkPlainVLESS), opts)
	if err != nil {
		t.Fatalf("BuildPlan: %v", err)
	}

	seen := map[int]bool{}
	for _, a := range plan.Assignments {
		if a.Core != model.CoreXray {
			if a.BridgePort != 0 {
				t.Errorf("%s: a sing-box node must not hold a bridge port", a.Node.DisplayName())
			}
			continue
		}
		if a.BridgePort < opts.BridgePortBase {
			t.Errorf("%s: bridge port %d is below the base", a.Node.DisplayName(), a.BridgePort)
		}
		if seen[a.BridgePort] {
			t.Errorf("bridge port %d was allocated twice", a.BridgePort)
		}
		seen[a.BridgePort] = true
	}
	if len(seen) != 2 {
		t.Errorf("allocated %d bridge ports, want 2", len(seen))
	}
}

func TestPlanRecordsUnsupportedNodesInsteadOfFailing(t *testing.T) {
	// ShadowsocksR is implemented by neither core. It must not take the whole
	// plan down with it.
	ssr := &model.Node{
		Name:     "Legacy SSR",
		Protocol: model.ProtoShadowsocksR,
		Server:   "ssr.example.com",
		Port:     8388,
		Method:   "aes-256-cfb",
		Password: "pw",
		SSR:      &model.SSROpts{Protocol: "origin", Obfs: "plain"},
	}
	ssr.AssignID()

	nodes := append([]*model.Node{ssr}, parseAll(t, linkPlainVLESS)...)
	plan, err := BuildPlan(nodes, DefaultPlanOptions())
	if err != nil {
		t.Fatalf("BuildPlan: %v", err)
	}

	rejected := plan.Rejected()
	if len(rejected) != 1 {
		t.Fatalf("got %d rejected nodes, want 1", len(rejected))
	}
	if rejected[0].Reason == "" {
		t.Error("a rejected node must carry a human-readable reason")
	}
	if len(plan.CarriedTags()) != 1 {
		t.Errorf("the usable node must still be carried, got %v", plan.CarriedTags())
	}
}

func TestPlanDropsDuplicateNodes(t *testing.T) {
	// The same server listed twice under different names is one server.
	nodes := parseAll(t, linkPlainVLESS, linkPlainVLESS+"-renamed")
	plan, err := BuildPlan(nodes, DefaultPlanOptions())
	if err != nil {
		t.Fatalf("BuildPlan: %v", err)
	}
	if len(plan.Assignments) != 1 {
		t.Errorf("got %d assignments, want 1 after deduplication", len(plan.Assignments))
	}
}

func TestPlanRendersBothCoreConfigs(t *testing.T) {
	plan, err := BuildPlan(parseAll(t, linkXHTTP, linkHysteria2), DefaultPlanOptions())
	if err != nil {
		t.Fatalf("BuildPlan: %v", err)
	}
	tags := plan.CarriedTags()

	sbJSON, err := plan.SingBoxConfig(singbox.Config{
		Options:  singbox.DefaultOptions(),
		Groups:   []singbox.Group{{Tag: "proxy", Type: "selector", Outbounds: tags}},
		FinalTag: "proxy",
	})
	if err != nil {
		t.Fatalf("SingBoxConfig: %v", err)
	}

	var sb map[string]any
	if err := json.Unmarshal(sbJSON, &sb); err != nil {
		t.Fatalf("generated sing-box config is not valid JSON: %v", err)
	}
	for _, key := range []string{"inbounds", "outbounds", "route", "dns"} {
		if _, ok := sb[key]; !ok {
			t.Errorf("sing-box config is missing %q", key)
		}
	}

	xrayJSON, err := plan.XrayConfig(xray.DefaultOptions())
	if err != nil {
		t.Fatalf("XrayConfig: %v", err)
	}
	var xr map[string]any
	if err := json.Unmarshal(xrayJSON, &xr); err != nil {
		t.Fatalf("generated Xray config is not valid JSON: %v", err)
	}

	// The Xray-carried node must appear on both sides of the bridge: as a SOCKS
	// listener in Xray and as a SOCKS outbound in sing-box.
	inbounds, _ := xr["inbounds"].([]any)
	if len(inbounds) != 1 {
		t.Fatalf("got %d Xray inbounds, want 1 bridge", len(inbounds))
	}
	bridge := inbounds[0].(map[string]any)
	bridgePort := int(bridge["port"].(float64))

	outbounds, _ := sb["outbounds"].([]any)
	found := false
	for _, o := range outbounds {
		out := o.(map[string]any)
		if out["type"] == "socks" && int(out["server_port"].(float64)) == bridgePort {
			found = true
		}
	}
	if !found {
		t.Errorf("sing-box has no SOCKS outbound pointing at the Xray bridge on port %d", bridgePort)
	}
}

func TestXrayConfigMarksItsOwnSockets(t *testing.T) {
	// Without SO_MARK, Xray's connection to the remote server is captured by the
	// front core and loops back into the tunnel it is trying to establish.
	plan, err := BuildPlan(parseAll(t, linkXHTTP), DefaultPlanOptions())
	if err != nil {
		t.Fatalf("BuildPlan: %v", err)
	}
	raw, err := plan.XrayConfig(xray.DefaultOptions())
	if err != nil {
		t.Fatalf("XrayConfig: %v", err)
	}

	var cfg map[string]any
	if err := json.Unmarshal(raw, &cfg); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}

	for _, o := range cfg["outbounds"].([]any) {
		out := o.(map[string]any)
		if out["protocol"] == "blackhole" || out["protocol"] == "freedom" {
			continue
		}
		stream, ok := out["streamSettings"].(map[string]any)
		if !ok {
			t.Fatalf("outbound %v has no streamSettings", out["tag"])
		}
		sockopt, ok := stream["sockopt"].(map[string]any)
		if !ok {
			t.Fatalf("outbound %v has no sockopt", out["tag"])
		}
		if int(sockopt["mark"].(float64)) != DefaultPlanOptions().RouteMark {
			t.Errorf("outbound %v carries mark %v, want the plan's route mark", out["tag"], sockopt["mark"])
		}
	}
}

func TestPlanWithNoNodesProducesNoConfig(t *testing.T) {
	plan, err := BuildPlan(nil, DefaultPlanOptions())
	if err != nil {
		t.Fatalf("BuildPlan: %v", err)
	}
	if _, err := plan.SingBoxConfig(singbox.Config{Options: singbox.DefaultOptions()}); err == nil {
		t.Error("expected an error when the plan carries no nodes")
	}
	if cfg, err := plan.XrayConfig(xray.DefaultOptions()); err != nil || cfg != nil {
		t.Errorf("XrayConfig = %v, %v; want nil, nil when Xray is not needed", cfg, err)
	}
}
