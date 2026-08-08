// Command obelisk is the Obelisk VPN client: a single static binary that drives
// stock Xray-core and sing-box processes on OpenWrt, choosing between them per
// node according to what each core can actually carry.
//
// This build exposes the pipeline that everything else will be assembled on:
// fetch and parse a subscription, resolve which core carries each node, render
// both cores' configurations, and hand them to the cores for validation.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
	"text/tabwriter"
	"time"

	"github.com/obelisk-project/obelisk/internal/core"
	"github.com/obelisk-project/obelisk/internal/core/singbox"
	"github.com/obelisk-project/obelisk/internal/core/xray"
	"github.com/obelisk-project/obelisk/internal/model"
	"github.com/obelisk-project/obelisk/internal/subs"
)

// version is stamped at build time with -ldflags "-X main.version=...".
var version = "dev"

// Default locations. Both are overridable per command, and the container image
// mounts them as a single volume so that cores, configuration and state survive
// a rebuild.
const (
	defaultConfigDir = "/etc/obelisk"
	defaultCoreDir   = "/etc/obelisk/bin"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	if err := run(ctx, os.Args[1:]); err != nil {
		fmt.Fprintf(os.Stderr, "obelisk: %v\n", err)
		os.Exit(1)
	}
}

func run(ctx context.Context, args []string) error {
	if len(args) == 0 {
		usage()
		return fmt.Errorf("no command given")
	}

	switch args[0] {
	case "parse":
		return cmdParse(ctx, args[1:])
	case "plan":
		return cmdPlan(ctx, args[1:])
	case "generate", "gen":
		return cmdGenerate(ctx, args[1:])
	case "core", "cores":
		return cmdCore(ctx, args[1:])
	case "route", "routes":
		return cmdRoute(ctx, args[1:])
	case "run":
		return cmdRun(ctx, args[1:])
	case "daemon", "serve", "web":
		return cmdDaemon(ctx, args[1:])
	case "version", "-v", "--version":
		fmt.Printf("obelisk %s\n", version)
		return nil
	case "help", "-h", "--help":
		usage()
		return nil
	default:
		usage()
		return fmt.Errorf("unknown command %q", args[0])
	}
}

func usage() {
	fmt.Fprint(os.Stderr, `obelisk — dual-core VPN client for OpenWrt

Usage:
  obelisk parse    <source>          Parse a subscription and list its nodes
  obelisk plan     <source>          Show which core would carry each node
  obelisk generate <source> -o <dir> Render both cores' configuration files
  obelisk daemon                     Run the service: web interface, API, cores
  obelisk run      <source>          Run the cores against one subscription
  obelisk version                    Print the version

Split tunnelling — what goes through the VPN and what does not:
  obelisk route add <entry...>       Route a domain, address, subnet or URL
  obelisk route list                 Show the rules in evaluation order
  obelisk route rm <id|value>        Remove a rule
  obelisk route test <destination>   Show what would happen to a destination
  obelisk route import <file>        Load a list, one entry per line

Core management (the cores stay independent binaries and are never linked in):
  obelisk core status  [core]        Show installed and available versions
  obelisk core install [core]        Download a core, optionally -version <tag>
  obelisk core update  [core]        Install the latest release if it differs
  obelisk core rollback <core>       Restore the binary the last install replaced

A <source> is a subscription URL, a file path, or "-" for standard input.
A [core] is "xray", "sing-box", or "all" (the default).
Most commands accept -json for machine-readable output.
`)
}

// parseArgs parses flags that may appear before, after or between positional
// arguments. The standard flag package stops at the first non-flag argument,
// which would make the natural "obelisk generate sub.txt -o out" fail; parsing
// in a loop and peeling off one positional at a time restores the ordering every
// other command-line tool allows.
func parseArgs(fs *flag.FlagSet, args []string) ([]string, error) {
	var positional []string
	for {
		if err := fs.Parse(args); err != nil {
			return nil, err
		}
		rest := fs.Args()
		if len(rest) == 0 {
			return positional, nil
		}
		positional = append(positional, rest[0])
		args = rest[1:]
	}
}

// isFlagSet reports whether a flag was actually typed on the command line.
//
// A flag's default is indistinguishable from a value the user chose, so without
// this a "-mode tun" default would silently overwrite whatever the configuration
// file says every time the command runs.
func isFlagSet(fs *flag.FlagSet, name string) bool {
	found := false
	fs.Visit(func(f *flag.Flag) {
		if f.Name == name {
			found = true
		}
	})
	return found
}

// singleSource returns the one source argument a command expects.
func singleSource(command string, positional []string) (string, error) {
	switch len(positional) {
	case 1:
		return positional[0], nil
	case 0:
		return "", fmt.Errorf("%s needs a source: a subscription URL, a file path, or \"-\"", command)
	default:
		return "", fmt.Errorf("%s takes one source, got %d", command, len(positional))
	}
}

// cmdParse parses a subscription and lists what it contains.
func cmdParse(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("parse", flag.ContinueOnError)
	asJSON := fs.Bool("json", false, "emit JSON instead of a table")
	userAgent := fs.String("ua", subs.DefaultUserAgent, "User-Agent to request the subscription with")
	positional, err := parseArgs(fs, args)
	if err != nil {
		return err
	}
	source, err := singleSource("parse", positional)
	if err != nil {
		return err
	}

	res, meta, err := load(ctx, source, *userAgent)
	if err != nil {
		return err
	}

	if *asJSON {
		return emitJSON(map[string]any{"meta": meta, "result": res})
	}

	printSubscriptionMeta(meta, res)
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "ID\tPROTOCOL\tTRANSPORT\tSECURITY\tADDRESS\tNAME")
	for _, n := range res.Nodes {
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t%s\n",
			n.ID, n.Protocol, n.Transport.Type, n.TLS.Security, n.Address(), n.DisplayName())
	}
	if err := w.Flush(); err != nil {
		return err
	}
	printSkipped(res)
	return nil
}

// cmdPlan resolves the topology and shows the core assignment per node.
func cmdPlan(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("plan", flag.ContinueOnError)
	asJSON := fs.Bool("json", false, "emit JSON instead of a table")
	userAgent := fs.String("ua", subs.DefaultUserAgent, "User-Agent to request the subscription with")
	preferVision := fs.Bool("prefer-xray-vision", true, "route XTLS Vision nodes to Xray")
	positional, err := parseArgs(fs, args)
	if err != nil {
		return err
	}
	source, err := singleSource("plan", positional)
	if err != nil {
		return err
	}

	res, meta, err := load(ctx, source, *userAgent)
	if err != nil {
		return err
	}

	opts := core.DefaultPlanOptions()
	opts.Policy.PreferXrayForVision = *preferVision

	plan, err := core.BuildPlan(res.Nodes, opts)
	if err != nil {
		return err
	}

	if *asJSON {
		return emitJSON(plan)
	}

	printSubscriptionMeta(meta, res)

	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "CORE\tBRIDGE\tPROTOCOL\tTRANSPORT\tNAME")
	for _, a := range plan.Assignments {
		coreName := string(a.Core)
		bridge := "-"
		if !a.Carried() {
			coreName = "none"
		} else if a.BridgePort > 0 {
			bridge = fmt.Sprintf("127.0.0.1:%d", a.BridgePort)
		}
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\n",
			coreName, bridge, a.Node.Protocol, a.Node.Transport.Type, a.Node.DisplayName())
	}
	if err := w.Flush(); err != nil {
		return err
	}

	counts := plan.CountByCore()
	fmt.Printf("\n%d node(s) on sing-box, %d on Xray", counts[model.CoreSingBox], counts[model.CoreXray])
	if plan.NeedsXray() {
		fmt.Print(" (Xray process required)")
	} else {
		fmt.Print(" (Xray not needed; it will not be started)")
	}
	fmt.Println()

	if rejected := plan.Rejected(); len(rejected) > 0 {
		fmt.Printf("\n%d node(s) cannot be carried by either core:\n", len(rejected))
		for _, a := range rejected {
			fmt.Printf("  %-40s %s\n", truncate(a.Node.DisplayName(), 40), a.Reason)
		}
	}
	return nil
}

// cmdGenerate renders both cores' configurations and, when the core binaries are
// available, asks them to validate what was produced.
func cmdGenerate(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("generate", flag.ContinueOnError)
	outDir := fs.String("o", ".", "directory to write the configuration files into")
	userAgent := fs.String("ua", subs.DefaultUserAgent, "User-Agent to request the subscription with")
	mode := fs.String("mode", "tun", "traffic capture mode: tun, tproxy, redirect or proxy")
	check := fs.Bool("check", true, "validate the output with the core binaries when they are installed")
	positional, err := parseArgs(fs, args)
	if err != nil {
		return err
	}
	source, err := singleSource("generate", positional)
	if err != nil {
		return err
	}

	res, _, err := load(ctx, source, *userAgent)
	if err != nil {
		return err
	}

	plan, err := core.BuildPlan(res.Nodes, core.DefaultPlanOptions())
	if err != nil {
		return err
	}
	tags := plan.CarriedTags()
	if len(tags) == 0 {
		return fmt.Errorf("no node in this subscription can be carried by either core")
	}

	if err := os.MkdirAll(*outDir, 0o755); err != nil {
		return err
	}

	sbOpts := singbox.DefaultOptions()
	sbOpts.Mode = singbox.InboundMode(*mode)
	sbOpts.CacheFile = filepath.Join(*outDir, "cache.db")

	// Until the routing engine lands, the generated config gives every node a
	// latency-tested group and sends everything through it, with private
	// destinations kept off the tunnel.
	sbCfg := singbox.Config{
		Options: sbOpts,
		Groups: []singbox.Group{
			{Tag: "auto", Type: "urltest", Outbounds: tags, Interval: "3m", Tolerance: 50},
			{Tag: "proxy", Type: "selector", Outbounds: append([]string{"auto"}, tags...), Default: "auto"},
		},
		Rules: []singbox.Rule{
			{IPIsPrivate: true, Outbound: singbox.TagDirect},
		},
		FinalTag: "proxy",
		ProxyTag: "proxy",
	}

	singboxPath := filepath.Join(*outDir, "sing-box.json")
	sbJSON, err := plan.SingBoxConfig(sbCfg)
	if err != nil {
		return err
	}
	if err := os.WriteFile(singboxPath, sbJSON, 0o600); err != nil {
		return err
	}
	fmt.Printf("wrote %s (%d bytes)\n", singboxPath, len(sbJSON))

	xrayPath := ""
	if plan.NeedsXray() {
		xrayJSON, err := plan.XrayConfig(xray.DefaultOptions())
		if err != nil {
			return err
		}
		xrayPath = filepath.Join(*outDir, "xray.json")
		if err := os.WriteFile(xrayPath, xrayJSON, 0o600); err != nil {
			return err
		}
		fmt.Printf("wrote %s (%d bytes)\n", xrayPath, len(xrayJSON))
	} else {
		fmt.Println("no Xray-only node in this subscription; xray.json not generated")
	}

	if *check {
		validate(ctx, singboxPath, xrayPath)
	}
	return nil
}

// validate asks each core binary to parse the config Obelisk generated for it.
//
// A config that Obelisk considers correct is still only a hypothesis until the
// core that has to read it agrees, and each core is the only authority on its
// own schema. When a binary is absent the check is reported as skipped rather
// than passed, because an unrun check proves nothing.
func validate(ctx context.Context, singboxPath, xrayPath string) {
	fmt.Println()

	if singboxPath != "" {
		if bin, err := exec.LookPath("sing-box"); err != nil {
			fmt.Println("sing-box: not installed, config left unvalidated")
		} else {
			report("sing-box", runCheck(ctx, bin, "check", "-c", singboxPath))
		}
	}
	if xrayPath != "" {
		if bin, err := exec.LookPath("xray"); err != nil {
			fmt.Println("xray: not installed, config left unvalidated")
		} else {
			report("xray", runCheck(ctx, bin, "run", "-test", "-c", xrayPath))
		}
	}
}

func runCheck(ctx context.Context, bin string, args ...string) error {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, bin, args...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("%w\n%s", err, strings.TrimSpace(string(out)))
	}
	return nil
}

func report(name string, err error) {
	if err != nil {
		fmt.Printf("%s: FAILED\n%s\n", name, err)
		return
	}
	fmt.Printf("%s: config accepted\n", name)
}

// load resolves a source into a parsed subscription. The source may be a URL, a
// file path, or "-" for standard input.
func load(ctx context.Context, source, userAgent string) (*subs.Result, *subs.FetchResult, error) {
	if strings.HasPrefix(source, "http://") || strings.HasPrefix(source, "https://") {
		fetched, err := subs.Fetch(ctx, source, subs.FetchOptions{UserAgent: userAgent})
		if err != nil {
			return nil, nil, err
		}
		if fetched.Result == nil {
			return nil, nil, fmt.Errorf("subscription reported no changes and no cached copy exists")
		}
		return fetched.Result, fetched, nil
	}

	var (
		data []byte
		err  error
	)
	if source == "-" {
		data, err = io.ReadAll(os.Stdin)
	} else {
		data, err = os.ReadFile(source)
	}
	if err != nil {
		return nil, nil, err
	}

	res, err := subs.Parse(data)
	if err != nil {
		return nil, nil, err
	}
	return res, nil, nil
}

func printSubscriptionMeta(meta *subs.FetchResult, res *subs.Result) {
	if meta != nil && meta.ProfileTitle != "" {
		fmt.Printf("Profile:  %s\n", meta.ProfileTitle)
	}
	fmt.Printf("Format:   %s\n", res.Format)
	fmt.Printf("Nodes:    %d parsed", len(res.Nodes))
	if len(res.Skipped) > 0 {
		fmt.Printf(", %d skipped", len(res.Skipped))
	}
	fmt.Println()

	if meta != nil && meta.UserInfo != nil {
		info := meta.UserInfo
		fmt.Printf("Traffic:  %s used", humanBytes(info.Used()))
		if info.Total > 0 {
			fmt.Printf(" of %s (%s left)", humanBytes(info.Total), humanBytes(info.Remaining()))
		}
		fmt.Println()
		if info.Expire != nil {
			fmt.Printf("Expires:  %s\n", info.Expire.Format(time.RFC3339))
		}
	}
	fmt.Println()
}

func printSkipped(res *subs.Result) {
	if len(res.Skipped) == 0 {
		return
	}
	fmt.Printf("\n%d entr(ies) could not be parsed:\n", len(res.Skipped))

	// Identical failures are collapsed: a panel emitting one malformed shape a
	// hundred times is one problem, not a hundred.
	byReason := map[string][]string{}
	for _, s := range res.Skipped {
		byReason[s.Err] = append(byReason[s.Err], s.Line)
	}
	reasons := make([]string, 0, len(byReason))
	for r := range byReason {
		reasons = append(reasons, r)
	}
	sort.Strings(reasons)

	for _, r := range reasons {
		lines := byReason[r]
		fmt.Printf("  %s (%d)\n    e.g. %s\n", r, len(lines), truncate(lines[0], 90))
	}
}

func emitJSON(v any) error {
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(v)
}

func humanBytes(n int64) string {
	if n < 0 {
		return "unlimited"
	}
	const unit = 1024
	if n < unit {
		return fmt.Sprintf("%d B", n)
	}
	div, exp := int64(unit), 0
	for v := n / unit; v >= unit; v /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %ciB", float64(n)/float64(div), "KMGTPE"[exp])
}

func truncate(s string, max int) string {
	if len([]rune(s)) <= max {
		return s
	}
	return string([]rune(s)[:max]) + "…"
}
