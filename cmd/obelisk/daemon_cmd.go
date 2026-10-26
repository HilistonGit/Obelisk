package main

import (
	"context"
	"flag"
	"fmt"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"github.com/obelisk-project/obelisk/internal/api"
	"github.com/obelisk-project/obelisk/internal/app"
	"github.com/obelisk-project/obelisk/web"
)

// cmdDaemon runs Obelisk as a service: the web interface, the API, and the cores.
//
// This is the entry point the container and the init script use. Unlike "run",
// it takes no subscription on the command line — everything comes from the
// stored configuration, which is what the browser and the CLI both edit.
func cmdDaemon(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("daemon", flag.ContinueOnError)
	cfgPath := configPathFlag(fs)
	configDir := fs.String("dir", defaultConfigDir, "directory for generated configuration and state")
	coreDir := fs.String("core-dir", defaultCoreDir, "directory holding the managed core binaries")
	listen := fs.String("listen", "0.0.0.0:24080", "address for the web interface")
	token := fs.String("token", os.Getenv("OBELISK_TOKEN"), "access token; one is generated when empty")
	ghToken := fs.String("github-token", os.Getenv("GITHUB_TOKEN"), "GitHub token, to raise the API rate limit")
	autoConnect := fs.Bool("connect", true, "override the auto-connect setting for this run")
	refresh := fs.Duration("refresh", time.Hour, "how often to refresh subscriptions; 0 disables")

	if _, err := parseArgs(fs, args); err != nil {
		return err
	}

	parentCtx := ctx
	ctx, stopDaemon := context.WithCancel(parentCtx)
	defer stopDaemon()
	var restarting atomic.Bool
	app.Version = version

	service, err := app.New(app.Options{
		ConfigPath:  *cfgPath,
		ConfigDir:   *configDir,
		CoreDir:     *coreDir,
		GitHubToken: *ghToken,
	})
	if err != nil {
		return err
	}

	server, accessToken, err := api.New(service, api.Options{
		Listen:  *listen,
		Token:   *token,
		Static:  web.FS(),
		Restart: func() { restarting.Store(true); stopDaemon() },
	})
	if err != nil {
		return err
	}

	service.OpenHistory(ctx)
	defer service.CloseHistory()

	printBanner(*listen, accessToken, *token == "")

	// Subscriptions are fetched before the interface is useful, but a failure
	// here must not stop the daemon: the browser is the place to see and fix a
	// broken subscription, and it cannot be reached if startup aborted.
	if err := service.Refresh(ctx); err != nil {
		fmt.Fprintf(os.Stderr, "warning: %v\n", err)
	}

	// Before anything else: clear routing a previous run may have left behind.
	//
	// A core that was killed rather than asked to stop never removes its own
	// policy routing, and what remains points every LAN client at a routing
	// table with nothing in it. The router itself keeps working, so nothing
	// looks wrong from here while the whole house is offline. Startup is the one
	// moment such remnants are certainly dead, so it is where they get cleared.
	if removed, err := service.SweepStaleRouting(ctx); err != nil {
		fmt.Fprintf(os.Stderr, "warning: could not check for stale routing: %v\n", err)
	} else if removed > 0 {
		fmt.Printf("cleared %d routing rule(s) left behind by a previous run\n", removed)
	}

	// Whether to come up on its own is a setting, not a command-line argument:
	// it has to survive a reboot, and the person who changes it does so in the
	// interface. The flag stays as a deliberate override for one run — useful
	// when the saved configuration is what you are trying to debug.
	shouldConnect := service.AutoConnectEnabled()
	fs.Visit(func(f *flag.Flag) {
		if f.Name == "connect" {
			shouldConnect = *autoConnect
		}
	})

	var workers sync.WaitGroup
	if shouldConnect {
		// In the background, with retries: at boot the WAN may still be dialling
		// and the first attempt would fail on a link that is seconds away from
		// working. Doing it here rather than inline also means the interface is
		// reachable while it happens, so a failure can be seen and fixed.
		workers.Go(func() { service.AutoConnect(ctx) })
	}

	if *refresh > 0 {
		workers.Go(func() { refreshLoop(ctx, service, *refresh) })
	}

	err = server.ListenAndServe(ctx)
	stopDaemon()
	workers.Wait()

	// The parent context is already cancelled by the time we get here, so the
	// shutdown path needs one of its own or every stop would time out at once.
	// Long enough for both cores to shut down properly. sing-box removes its
	// interface and its policy routing on the way out, and killing it partway
	// through that leaves the LAN routed into a table with nothing in it.
	stopCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 45*time.Second)
	defer cancel()
	fmt.Println("\nstopping cores…")
	if stopErr := service.Disconnect(stopCtx); stopErr != nil {
		fmt.Fprintf(os.Stderr, "warning: %v\n", stopErr)
	}
	if restarting.Load() && parentCtx.Err() == nil {
		service.CloseHistory()
		if err != nil {
			return err
		}
		return restartProcess(accessToken)
	}
	return err
}

// refreshLoop re-fetches subscriptions on a timer.
func refreshLoop(ctx context.Context, service *app.App, every time.Duration) {
	ticker := time.NewTicker(every)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if err := service.Refresh(ctx); err != nil {
				fmt.Fprintf(os.Stderr, "subscription refresh failed, keeping the previous list: %v\n", err)
			}
		}
	}
}

// printBanner tells the operator where the interface is and how to get in.
func printBanner(listen, token string, generated bool) {
	fmt.Printf("\n  Obelisk %s\n\n", version)
	for _, url := range interfaceURLs(listen) {
		fmt.Printf("  interface   %s\n", url)
	}
	fmt.Printf("  token       %s\n", token)
	if generated {
		fmt.Println("\n  This token was generated for this run and is not stored. Set one with")
		fmt.Println("  -token or OBELISK_TOKEN to keep it stable across restarts.")
	}
	fmt.Println()
}

// interfaceURLs turns a listen address into addresses a person can actually
// open, because "0.0.0.0:24080" is not one of them.
func interfaceURLs(listen string) []string {
	host, port, err := net.SplitHostPort(listen)
	if err != nil {
		return []string{"http://" + listen}
	}
	if host != "" && host != "0.0.0.0" && host != "::" {
		return []string{fmt.Sprintf("http://%s", net.JoinHostPort(host, port))}
	}

	urls := []string{fmt.Sprintf("http://127.0.0.1:%s", port)}
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return urls
	}
	for _, addr := range addrs {
		ipNet, ok := addr.(*net.IPNet)
		if !ok || ipNet.IP.IsLoopback() || ipNet.IP.To4() == nil {
			continue
		}
		urls = append(urls, fmt.Sprintf("http://%s", net.JoinHostPort(ipNet.IP.String(), port)))
	}
	return urls
}
