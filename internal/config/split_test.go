package config

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/obelisk-project/obelisk/internal/routing"
)

func TestSplitModeMeanings(t *testing.T) {
	cases := []struct {
		mode     SplitMode
		fallback routing.Action
		uses     bool
		add      routing.Action
	}{
		// Only what the list names goes through the tunnel, so everything else
		// is direct and a new entry is there to be proxied.
		{SplitProxyList, routing.ActionDirect, true, routing.ActionProxy},
		// The reverse: the list is what stays out, so a new entry is an exception
		// to a tunnel that otherwise carries everything.
		{SplitBypassList, routing.ActionProxy, true, routing.ActionDirect},
		// Split tunnelling off: everything goes in and no list is consulted.
		{SplitOff, routing.ActionProxy, false, routing.ActionDirect},
	}
	for _, c := range cases {
		if got := c.mode.Fallback(); got != c.fallback {
			t.Errorf("%s: unmatched traffic goes %s, want %s", c.mode, got, c.fallback)
		}
		if got := c.mode.UsesRules(); got != c.uses {
			t.Errorf("%s: UsesRules = %v, want %v", c.mode, got, c.uses)
		}
		if got := c.mode.AddAction(); got != c.add {
			t.Errorf("%s: a new entry defaults to %s, want %s", c.mode, got, c.add)
		}
		// An entry that agrees with the fallback cannot change any outcome, so
		// the default for a new one is never the fallback.
		if c.mode.AddAction() == c.mode.Fallback() {
			t.Errorf("%s: new entries default to the fallback, which does nothing", c.mode)
		}
	}
}

// A configuration written before split modes existed says only what happened to
// unmatched traffic. Reading it must not silently change where traffic goes.
func TestSplitModeMigratesFromTheOldSetting(t *testing.T) {
	cases := []struct {
		name  string
		saved string
		want  SplitMode
	}{
		{"proxy fallback becomes the bypass list", `{"settings":{"default_action":"proxy"}}`, SplitBypassList},
		{"direct fallback becomes the proxy list", `{"settings":{"default_action":"direct"}}`, SplitProxyList},
		{"a file with neither gets the safe default", `{"settings":{}}`, SplitProxyList},
		{"an explicit split wins over the old field", `{"settings":{"split":"off","default_action":"direct"}}`, SplitOff},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "config.json")
			if err := os.WriteFile(path, []byte(c.saved), 0o600); err != nil {
				t.Fatal(err)
			}
			cfg, err := Load(path)
			if err != nil {
				t.Fatalf("Load: %v", err)
			}
			if cfg.Settings.Split != c.want {
				t.Errorf("Split = %q, want %q", cfg.Settings.Split, c.want)
			}
			// The old field is not carried forward, so it cannot drift out of
			// step with the one that now decides.
			if cfg.Settings.DefaultAction != "" {
				t.Errorf("DefaultAction survived migration as %q", cfg.Settings.DefaultAction)
			}
		})
	}
}

// A fresh install must not put a household's whole connection through a server
// it has not chosen yet.
func TestFreshInstallProxiesOnlyWhatItIsAsked(t *testing.T) {
	cfg := Default()
	if cfg.Settings.Split != SplitProxyList {
		t.Errorf("default split is %q, want %q", cfg.Settings.Split, SplitProxyList)
	}
	if cfg.Settings.Split.Fallback() != routing.ActionDirect {
		t.Error("a fresh install would send unmatched traffic through the tunnel")
	}
}

// A boolean added in a later schema needs the version number to be given its
// default, because JSON cannot distinguish a field that was absent from one
// written as false. Without this every existing installation would read the new
// setting as off and the feature would appear not to work.
func TestAutoConnectIsGrantedToOlderConfigs(t *testing.T) {
	dir := t.TempDir()
	path := dir + "/obelisk.json"

	// A file as written by a build that predates the setting.
	older := `{"version":1,"settings":{"mode":"tun","split":"proxy-list"}}`
	if err := os.WriteFile(path, []byte(older), 0o600); err != nil {
		t.Fatal(err)
	}

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if !cfg.Settings.AutoConnect {
		t.Error("upgrading left auto-connect off; the setting would look broken to every existing user")
	}
	if cfg.Version != CurrentVersion {
		t.Errorf("version stayed at %d after migration", cfg.Version)
	}
}

// Someone who switched it off must keep it off. Re-granting the default on
// every load would make the switch impossible to use.
func TestAutoConnectStaysOffOnceChosen(t *testing.T) {
	dir := t.TempDir()
	path := dir + "/obelisk.json"

	current := `{"version":2,"settings":{"mode":"tun","split":"proxy-list","auto_connect":false}}`
	if err := os.WriteFile(path, []byte(current), 0o600); err != nil {
		t.Fatal(err)
	}

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Settings.AutoConnect {
		t.Error("a deliberate off was overwritten by the default")
	}
}
