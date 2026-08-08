package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/obelisk-project/obelisk/internal/config"
	"github.com/obelisk-project/obelisk/internal/core"
	"github.com/obelisk-project/obelisk/internal/core/singbox"
	"github.com/obelisk-project/obelisk/internal/cores"
	"github.com/obelisk-project/obelisk/internal/model"
	"github.com/obelisk-project/obelisk/internal/routing"
)

// cmdRun is the daemon: it keeps a subscription, a plan and two core processes
// in agreement until it is asked to stop.
func cmdRun(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("run", flag.ContinueOnError)
	configDir := fs.String("dir", defaultConfigDir, "directory for generated configuration and state")
	coreDir := fs.String("core-dir", defaultCoreDir, "directory holding the managed core binaries")
	mode := fs.String("mode", "tun", "traffic capture mode: tun, tproxy, redirect or proxy")
	userAgent := fs.String("ua", "", "User-Agent to request the subscription with")
	interval := fs.Duration("interval", time.Hour, "how often to refresh the subscription; 0 disables refreshing")
	autoInstall := fs.Bool("auto-install", true, "download a missing core instead of failing")
	token := fs.String("token", os.Getenv("GITHUB_TOKEN"), "GitHub token, to raise the API rate limit")

	cfgPath := configPathFlag(fs)

	positional, err := parseArgs(fs, args)
	if err != nil {
		return err
	}
	source, err := singleSource("run", positional)
	if err != nil {
		return err
	}

	cfg, err := config.Load(*cfgPath)
	if err != nil {
		return err
	}
	// An explicit -mode overrides what the configuration file says; anything the
	// flag does not cover comes from the file.
	if isFlagSet(fs, "mode") {
		cfg.Settings.Mode = *mode
	}

	fmt.Printf("Split tunnelling: %s\n", describeSplit(cfg.Settings.Split))
	if summary := routing.Summarize(cfg.Rules); summary.Enabled > 0 {
		fmt.Printf("%d routing rule(s): %d proxied, %d direct, %d blocked\n",
			summary.Enabled, summary.Proxied, summary.Direct, summary.Blocked)
	} else if cfg.Settings.Split.UsesRules() {
		fmt.Println("No routing rules configured.")
		fmt.Println("Add some with: obelisk route add <domain or address>")
	}

	manager := newManager(*coreDir, *token)

	// The front core is always required; the backend is only fetched once a plan
	// turns out to need it, so a subscription of pure sing-box nodes never pays
	// for an Xray download.
	singboxPath, err := ensureCore(ctx, manager, cores.KindSingBox, *autoInstall)
	if err != nil {
		return err
	}

	sbOpts := singbox.DefaultOptions()
	sbOpts.Mode = singbox.InboundMode(cfg.Settings.Mode)
	sbOpts.CacheFile = filepath.Join(*configDir, "cache.db")
	sbOpts.DNSProxy = cfg.Settings.DNS.Proxy
	sbOpts.DNSDirect = cfg.Settings.DNS.Direct
	sbOpts.FakeIP = cfg.Settings.DNS.FakeIP
	sbOpts.DNSPort = cfg.Settings.DNS.Listen
	sbOpts.DNSStrategy = cfg.Settings.DNS.Strategy

	runtime := core.NewRuntime(core.RuntimeOptions{
		ConfigDir:     *configDir,
		SingBoxBinary: singboxPath,
		SingBox:       sbOpts,
	})

	// The cores keep running while a refresh is prepared, so a failed refresh
	// costs nothing: the previous plan simply stays in force.
	apply := func() error {
		res, _, err := load(ctx, source, *userAgent)
		if err != nil {
			return err
		}

		planOpts := core.DefaultPlanOptions()
		planOpts.Policy = cfg.Settings.Core.Policy

		plan, err := core.BuildPlan(res.Nodes, planOpts)
		if err != nil {
			return err
		}
		tags := plan.CarriedTags()
		if len(tags) == 0 {
			return errors.New("no node in this subscription can be carried by either core")
		}

		routingConfig, err := buildRoutingConfig(cfg, tags)
		if err != nil {
			return err
		}

		if plan.NeedsXray() && runtime.XrayBinary() == "" {
			xrayPath, err := ensureCore(ctx, manager, cores.KindXray, *autoInstall)
			if err != nil {
				return err
			}
			runtime.SetXrayBinary(xrayPath)
		}

		if err := runtime.Apply(ctx, plan, routingConfig); err != nil {
			return err
		}

		counts := plan.CountByCore()
		fmt.Printf("[%s] %d node(s) on sing-box, %d on Xray",
			time.Now().Format(time.TimeOnly), counts[model.CoreSingBox], counts[model.CoreXray])
		if rejected := plan.Rejected(); len(rejected) > 0 {
			fmt.Printf(", %d unusable", len(rejected))
		}
		fmt.Println()
		return nil
	}

	if err := apply(); err != nil {
		return err
	}
	for _, st := range runtime.Status() {
		fmt.Printf("  %-9s %s (pid %d)\n", st.Name, st.State, st.PID)
	}
	fmt.Println("running; press Ctrl+C to stop")

	var refresh <-chan time.Time
	if *interval > 0 {
		ticker := time.NewTicker(*interval)
		defer ticker.Stop()
		refresh = ticker.C
	}

	for {
		select {
		case <-ctx.Done():
			fmt.Println("\nstopping cores…")
			// The parent context is already cancelled, so shutdown gets a fresh
			// one; otherwise every stop would time out instantly.
			stopCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 15*time.Second)
			defer cancel()
			return runtime.Stop(stopCtx)

		case <-refresh:
			if err := apply(); err != nil {
				fmt.Fprintf(os.Stderr, "refresh failed, keeping the previous plan: %v\n", err)
			}
		}
	}
}

// ensureCore resolves a core binary, installing it when it is missing and the
// caller allows it.
func ensureCore(ctx context.Context, m *cores.Manager, kind cores.Kind, autoInstall bool) (string, error) {
	path, _, err := m.Resolve(kind)
	if err == nil {
		return path, nil
	}
	if !autoInstall {
		return "", fmt.Errorf("%s is not installed; run \"obelisk core install %s\"", kind, kind)
	}

	fmt.Printf("%s is not installed; fetching the latest release…\n", kind)
	rel, err := m.Source.Latest(ctx, kind, cores.CurrentTarget())
	if err != nil {
		return "", err
	}
	installed, err := m.Install(ctx, rel)
	if err != nil {
		return "", err
	}
	fmt.Printf("%s %s installed at %s\n", kind, installed.Version, installed.Path)
	return installed.Path, nil
}

// buildRoutingConfig assembles the routing half of the sing-box configuration
// from the user's rules.
//
// Two rules are supplied by Obelisk rather than by the user and always come
// first. Private destinations go direct, because sending the LAN into the tunnel
// would cut the router off from the devices it serves. Everything else falls
// through to the configured default, which starts as "direct" so that a freshly
// configured Obelisk proxies only what it was explicitly told to.
func buildRoutingConfig(cfg *config.Config, tags []string) (singbox.Config, error) {
	proxyGroup := cfg.Settings.ProxyGroup
	if proxyGroup == "" {
		proxyGroup = "proxy"
	}

	userRules, err := routing.Compile(cfg.Rules, routing.CompileOptions{
		ProxyTag:  proxyGroup,
		DirectTag: singbox.TagDirect,
	})
	if err != nil {
		return singbox.Config{}, err
	}

	rules := []singbox.Rule{{IPIsPrivate: true, Outbound: singbox.TagDirect}}
	if cfg.Settings.Split.UsesRules() {
		rules = append(rules, userRules...)
	}

	final := singbox.TagDirect
	if cfg.Settings.Split.Fallback() == routing.ActionProxy {
		final = proxyGroup
	}

	return singbox.Config{
		Groups: []singbox.Group{
			{Tag: "auto", Type: "urltest", Outbounds: tags, Interval: "3m", Tolerance: 50},
			{Tag: proxyGroup, Type: "selector", Outbounds: append([]string{"auto"}, tags...), Default: "auto"},
		},
		Rules:    rules,
		FinalTag: final,
		ProxyTag: proxyGroup,
	}, nil
}
