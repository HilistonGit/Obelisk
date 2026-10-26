package app

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"

	"github.com/obelisk-project/obelisk/internal/core"
	"github.com/obelisk-project/obelisk/internal/model"
	"github.com/obelisk-project/obelisk/internal/subs"
)

type subscriptionCache struct {
	Nodes   []*model.Node                  `json:"nodes"`
	Rules   map[string]*subs.ProviderRules `json:"rules"`
	Skipped map[string][]subs.SkipReason   `json:"skipped"`
}

// The cache lives beside the persistent config, never in the runtime directory.
func (a *App) loadSubscriptions() {
	data, err := os.ReadFile(a.opts.ConfigPath + ".subscriptions.json")
	if os.IsNotExist(err) {
		return
	}
	var cache subscriptionCache
	if err == nil {
		err = json.Unmarshal(data, &cache)
	}
	if err != nil {
		log.Printf("subscription cache: %v", err)
		return
	}
	for _, s := range a.cfg.EnabledSubscriptions() {
		for _, n := range cache.Nodes {
			if n != nil && n.Source == s.ID && n.Validate() == nil {
				a.nodes = append(a.nodes, n)
			}
		}
		a.providerRules[s.ID] = cache.Rules[s.ID]
		a.skipped[s.ID] = cache.Skipped[s.ID]
	}
	opts := core.DefaultPlanOptions()
	opts.Policy = a.cfg.Settings.Core.Policy
	a.plan, _ = core.BuildPlan(a.nodes, opts)
}

// Caller holds mu. Credentials require the same permissions as the config.
func (a *App) saveSubscriptions() error {
	path := a.opts.ConfigPath + ".subscriptions.json"
	data, err := json.Marshal(subscriptionCache{a.nodes, a.providerRules, a.skipped})
	if err != nil {
		return err
	}
	if err = os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return err
	}
	f, err := os.CreateTemp(filepath.Dir(path), ".subscriptions-*")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	if _, err = f.Write(data); err == nil {
		err = f.Sync()
	}
	closeErr := f.Close()
	if err == nil {
		err = closeErr
	}
	if err == nil {
		err = os.Rename(f.Name(), path)
	}
	if err != nil {
		return fmt.Errorf("saving subscription cache: %w", err)
	}
	return nil
}

// Happ-compatible subscriptions require an installation identity, stable across boots.
func (a *App) fetchOptions(userAgent string) subs.FetchOptions {
	opts := subs.FetchOptions{UserAgent: userAgent}
	if strings.HasPrefix(strings.ToLower(strings.TrimSpace(userAgent)), "happ/") || strings.EqualFold(strings.TrimSpace(userAgent), "happ") {
		a.mu.RLock()
		opts.HWID = a.cfg.DeviceID
		a.mu.RUnlock()
	}
	return opts
}
