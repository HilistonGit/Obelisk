package app

import (
	"context"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"sync/atomic"
	"testing"

	"github.com/obelisk-project/obelisk/internal/config"
)

func TestSubscriptionSurvivesOfflineRestart(t *testing.T) {
	var offline atomic.Bool
	var hwid string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if offline.Load() {
			w.WriteHeader(503)
			return
		}
		hwid = r.Header.Get("X-Hwid")
		w.Write([]byte(`{"outbounds":[{"type":"hysteria2","tag":"test","server":"example.com","server_port":443,"password":"secret","tls":{"enabled":true}}],"route":{"rules":[{"domain_suffix":["example.org"],"outbound":"direct"}]}}`))
	}))
	defer server.Close()
	dir := t.TempDir()
	opts := Options{ConfigPath: filepath.Join(dir, "config.json"), ConfigDir: dir, CoreDir: dir}
	a, err := New(opts)
	if err != nil {
		t.Fatal(err)
	}
	a.cfg.Subscriptions = []config.Subscription{{ID: "test", URL: server.URL, Enabled: true, UserAgent: "Happ/1.0", ImportRules: true}}
	if err := a.save(); err != nil {
		t.Fatal(err)
	}
	if err := a.Refresh(context.Background()); err != nil {
		t.Fatal(err)
	}
	if hwid == "" {
		t.Fatal("Happ fetch omitted HWID")
	}
	id := a.nodes[0].ID
	a.cfg.Settings.SelectedNode = "node-" + id
	if err := a.save(); err != nil {
		t.Fatal(err)
	}
	offline.Store(true)
	if err := a.Refresh(context.Background()); err == nil {
		t.Fatal("expected offline error")
	}
	if len(a.nodes) != 1 || a.nodes[0].ID != id {
		t.Fatal("failed refresh discarded nodes")
	}
	b, err := New(opts)
	if err != nil {
		t.Fatal(err)
	}
	if len(b.nodes) != 1 || b.nodes[0].ID != id || b.plan == nil {
		t.Fatal("offline restart lost nodes or plan")
	}
	if b.providerRules["test"].Count() != 1 {
		t.Fatal("offline restart lost provider routing")
	}
	if b.cfg.Settings.SelectedNode != "node-"+id || b.plan.Assignments[0].Tag != b.cfg.Settings.SelectedNode {
		t.Fatal("last selected server no longer resolves after restart")
	}
	if b.cfg.DeviceID != hwid {
		t.Fatal("HWID changed on restart")
	}
	if b.fetchOptions("sing-box").HWID != "" {
		t.Fatal("HWID sent without Happ identity")
	}
	if err := b.SetSubscriptionEnabled(context.Background(), "test", false); err != nil {
		t.Fatal(err)
	}
	c, err := New(opts)
	if err != nil {
		t.Fatal(err)
	}
	if len(c.nodes) != 0 {
		t.Fatal("disabled subscription restored")
	}
}

func TestEmptyPlanTriggersSubscriptionRetry(t *testing.T) {
	var requests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		w.WriteHeader(503)
	}))
	defer server.Close()
	dir := t.TempDir()
	a, err := New(Options{ConfigPath: filepath.Join(dir, "config.json"), ConfigDir: dir, CoreDir: dir})
	if err != nil {
		t.Fatal(err)
	}
	a.cfg.Subscriptions = []config.Subscription{{ID: "test", URL: server.URL, Enabled: true}}
	_ = a.Refresh(context.Background())
	_ = a.Connect(context.Background())
	if requests.Load() != 2 {
		t.Fatalf("empty plan prevented retry: %d requests", requests.Load())
	}
}
