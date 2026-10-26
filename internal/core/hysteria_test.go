package core

import (
	"github.com/obelisk-project/obelisk/internal/core/singbox"
	"github.com/obelisk-project/obelisk/internal/model"
	"github.com/obelisk-project/obelisk/internal/subs"
	"testing"
)

func TestHysteriaJSONAndPortHopping(t *testing.T) {
	payloads := []string{
		`{"outbounds":[{"protocol":"hysteria","settings":{"version":2,"address":"example.com","port":443},"streamSettings":{"network":"hysteria","security":"tls","tlsSettings":{"serverName":"example.com"},"hysteriaSettings":{"version":2,"auth":"secret"}}}]}`,
		`{"outbounds":[{"type":"hysteria2","server":"example.com","server_ports":["20000:30000"],"hop_interval":"30s","password":"secret","tls":{"enabled":true}}]}`,
		`hy2://secret@example.com:20000-30000/?hop-interval=30`,
		`{"outbounds":[{"protocol":"hysteria","settings":{"version":2,"address":"example.com","port":443},"streamSettings":{"network":"hysteria","security":"tls","hysteriaSettings":{"version":2,"auth":"secret"},"finalmask":{"udp":[{"type":"salamander","settings":{"password":"obfs-secret"}}],"quicParams":{"udpHop":{"ports":"20000-30000","interval":30}}}}}]}`,
		`hysteria2://secret@[2001:db8::1]:20000-30000/?hop-interval=30`,
	}
	for i, payload := range payloads {
		result, err := subs.Parse([]byte(payload))
		if err != nil {
			t.Fatalf("case %d: %v", i, err)
		}
		if len(result.Nodes) != 1 {
			t.Fatalf("case %d: missing node: %+v", i, result.Skipped)
		}
		n := result.Nodes[0]
		if n.Protocol != model.ProtoHysteria2 || n.Password != "secret" {
			t.Fatalf("case %d: wrong credentials/protocol", i)
		}
		plan, err := BuildPlan(result.Nodes, DefaultPlanOptions())
		if err != nil || plan.NeedsXray() {
			t.Fatalf("case %d: should use sing-box: %v", i, err)
		}
		n.TLS.Fingerprint = "chrome"
		rendered, err := singbox.Outbound(n, "test")
		if err != nil {
			t.Fatal(err)
		}
		if tls, ok := rendered.Object["tls"].(map[string]any); ok && tls["utls"] != nil {
			t.Fatal("QUIC must not use uTLS")
		}
		if rendered.Object["tls"] == nil {
			t.Fatal("TLS missing")
		}
		if i == 3 {
			obfs, ok := rendered.Object["obfs"].(map[string]any)
			if !ok || obfs["password"] != "obfs-secret" {
				t.Fatal("lost salamander obfuscation")
			}
		}
		if i > 0 {
			ports, ok := rendered.Object["server_ports"].([]string)
			if !ok || len(ports) != 1 || ports[0] != "20000:30000" {
				t.Fatalf("lost port hopping: %+v", rendered.Object)
			}
			if rendered.Object["hop_interval"] != "30s" {
				t.Fatal("lost hop interval")
			}
		}
	}
}
