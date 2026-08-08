package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"text/tabwriter"
	"time"

	"github.com/obelisk-project/obelisk/internal/cores"
)

// cmdCore dispatches the core management subcommands.
func cmdCore(ctx context.Context, args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("core needs a subcommand: status, install, update or rollback")
	}

	switch args[0] {
	case "status", "ls", "list":
		return cmdCoreStatus(ctx, args[1:])
	case "install":
		return cmdCoreInstall(ctx, args[1:])
	case "update", "upgrade":
		return cmdCoreUpdate(ctx, args[1:])
	case "rollback":
		return cmdCoreRollback(ctx, args[1:])
	default:
		return fmt.Errorf("unknown core subcommand %q", args[0])
	}
}

// coreFlags registers the flags every core subcommand shares.
func coreFlags(fs *flag.FlagSet) (dir, token, target *string) {
	dir = fs.String("dir", defaultCoreDir, "directory holding the managed core binaries")
	token = fs.String("token", os.Getenv("GITHUB_TOKEN"), "GitHub token, to raise the API rate limit")
	target = fs.String("target", "", "platform to fetch for, e.g. linux/arm64 (default: this machine)")
	return dir, token, target
}

// resolveTarget interprets the -target flag, defaulting to the running platform.
//
// Fetching for another platform is what lets a workstation or a CI job stage
// cores for the router they are destined for; the binaries are then simply
// copied across, since Obelisk installs them as plain files.
func resolveTarget(s string) (cores.Target, error) {
	if s == "" {
		return cores.CurrentTarget(), nil
	}
	return cores.ParseTarget(s)
}

func newManager(dir, token string) *cores.Manager {
	return &cores.Manager{
		Dir:    dir,
		Source: &cores.Source{Token: token},
		// On OpenWrt the cores are frequently already installed by opkg; Obelisk
		// uses those rather than downloading a second copy onto scarce flash.
		ExtraLookupPaths: []string{"/usr/bin", "/usr/local/bin", "/opt/bin"},
	}
}

// resolveKinds turns the positional argument into the set of cores to act on.
func resolveKinds(args []string) ([]cores.Kind, error) {
	if len(args) == 0 || args[0] == "all" {
		return cores.AllKinds, nil
	}
	out := make([]cores.Kind, 0, len(args))
	for _, a := range args {
		k, err := cores.ParseKind(a)
		if err != nil {
			return nil, err
		}
		out = append(out, k)
	}
	return out, nil
}

// cmdCoreStatus reports the installed and available version of each core.
func cmdCoreStatus(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("core status", flag.ContinueOnError)
	dir, token, targetFlag := coreFlags(fs)
	asJSON := fs.Bool("json", false, "emit JSON instead of a table")
	offline := fs.Bool("offline", false, "report what is installed without querying for updates")
	positional, err := parseArgs(fs, args)
	if err != nil {
		return err
	}
	kinds, err := resolveKinds(positional)
	if err != nil {
		return err
	}
	target, err := resolveTarget(*targetFlag)
	if err != nil {
		return err
	}

	// Naming a core explicitly asserts that it should be there, so a missing one
	// is an error the exit code reports. Asking about "all" is a survey, and a
	// setup whose subscription needs only one core is not unhealthy for lacking
	// the other. This is also what makes the command usable as a healthcheck.
	strict := len(positional) > 0 && positional[0] != "all"

	m := newManager(*dir, *token)

	statuses := make([]cores.Status, 0, len(kinds))
	for _, k := range kinds {
		if *offline {
			st := cores.Status{Kind: k}
			if installed, err := m.Detect(ctx, k); err == nil {
				st.Installed = installed
			} else {
				st.Error = err.Error()
			}
			statuses = append(statuses, st)
			continue
		}
		statuses = append(statuses, m.Status(ctx, k, target))
	}

	if *asJSON {
		return emitJSON(map[string]any{"target": target.String(), "cores": statuses})
	}

	fmt.Printf("Target: %s\nDir:    %s\n\n", target, *dir)

	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "CORE\tINSTALLED\tLATEST\tSOURCE\tINTEGRITY")
	for _, st := range statuses {
		installed, latest, origin, integrity := "-", "-", "-", "-"

		if st.Installed != nil {
			installed = st.Installed.Version
			if st.Installed.Managed {
				origin = "obelisk"
			} else {
				origin = "system"
			}
			switch {
			case !st.Installed.Managed:
				integrity = "n/a"
			case st.Installed.Verified:
				integrity = "checksum verified"
			default:
				integrity = "unverified"
			}
		}
		if st.Available != nil {
			latest = st.Available.Version
			if st.UpdateAvailable {
				latest += " (update)"
			}
		}
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\n", st.Kind, installed, latest, origin, integrity)
	}
	if err := w.Flush(); err != nil {
		return err
	}

	for _, st := range statuses {
		// In strict mode a missing core is reported once, as the returned error.
		if st.Error != "" && !(strict && st.Installed == nil) {
			fmt.Printf("\n%s: %s\n", st.Kind, st.Error)
		}
	}

	// sing-box publishes no checksums, so saying "verified" for it would be a
	// lie. Explaining that once is better than an unexplained column.
	for _, st := range statuses {
		if st.Installed != nil && st.Installed.Managed && !st.Installed.Verified {
			fmt.Printf("\nNote: %s publishes no checksum file, so its download could only be\n"+
				"      trusted as far as the TLS connection it arrived over.\n", st.Kind)
			break
		}
	}

	if strict {
		for _, st := range statuses {
			if st.Installed == nil {
				return fmt.Errorf("%s is not installed", st.Kind)
			}
		}
	}
	return nil
}

// cmdCoreInstall downloads a core, optionally pinned to a specific release.
func cmdCoreInstall(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("core install", flag.ContinueOnError)
	dir, token, targetFlag := coreFlags(fs)
	tag := fs.String("version", "", "install this release tag instead of the latest")
	positional, err := parseArgs(fs, args)
	if err != nil {
		return err
	}
	kinds, err := resolveKinds(positional)
	if err != nil {
		return err
	}
	if *tag != "" && len(kinds) != 1 {
		return fmt.Errorf("-version applies to one core at a time")
	}
	target, err := resolveTarget(*targetFlag)
	if err != nil {
		return err
	}

	m := newManager(*dir, *token)
	if !target.Equal(cores.CurrentTarget()) {
		fmt.Printf("staging cores for %s; they will not be test-run here\n\n", target)
	}

	for _, k := range kinds {
		var (
			rel *cores.Release
			err error
		)
		if *tag != "" {
			rel, err = m.Source.ByTag(ctx, k, target, *tag)
		} else {
			rel, err = m.Source.Latest(ctx, k, target)
		}
		if err != nil {
			return err
		}

		fmt.Printf("%s %s: downloading %s (%s)\n", k, rel.Version, rel.AssetName, humanBytes(rel.Size))
		installed, err := m.Install(ctx, rel)
		if err != nil {
			return err
		}
		printInstalled(installed)
	}
	return nil
}

// cmdCoreUpdate installs the latest release when it differs from what is on disk.
func cmdCoreUpdate(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("core update", flag.ContinueOnError)
	dir, token, targetFlag := coreFlags(fs)
	asJSON := fs.Bool("json", false, "emit JSON instead of text")
	positional, err := parseArgs(fs, args)
	if err != nil {
		return err
	}
	kinds, err := resolveKinds(positional)
	if err != nil {
		return err
	}
	target, err := resolveTarget(*targetFlag)
	if err != nil {
		return err
	}

	m := newManager(*dir, *token)

	results := make([]*cores.UpdateResult, 0, len(kinds))
	for _, k := range kinds {
		res, err := m.Update(ctx, k, target)
		if err != nil {
			return err
		}
		results = append(results, res)
	}

	if *asJSON {
		return emitJSON(results)
	}

	for _, res := range results {
		switch {
		case res.AlreadyNew:
			fmt.Printf("%s %s is already the latest release\n", res.Kind, res.Current.Version)
		case res.Previous == nil:
			fmt.Printf("%s: installed %s\n", res.Kind, res.Current.Version)
			printInstalled(res.Current)
		default:
			fmt.Printf("%s: %s -> %s\n", res.Kind, res.Previous.Version, res.Current.Version)
			printInstalled(res.Current)
		}
	}

	for _, res := range results {
		if res.Shadows != "" && res.Changed {
			fmt.Printf("\nNote: %s now takes precedence over the system copy at %s,\n"+
				"      which is left in place and unchanged.\n", res.Current.Path, res.Shadows)
		}
	}
	for _, res := range results {
		if res.Changed {
			fmt.Println("\nRestart Obelisk for the new core to take effect;" +
				" a running process keeps the binary it started with.")
			break
		}
	}
	return nil
}

// cmdCoreRollback restores the binary replaced by the last install.
func cmdCoreRollback(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("core rollback", flag.ContinueOnError)
	dir, token, _ := coreFlags(fs)
	positional, err := parseArgs(fs, args)
	if err != nil {
		return err
	}
	if len(positional) != 1 {
		return fmt.Errorf("rollback takes exactly one core")
	}
	kind, err := cores.ParseKind(positional[0])
	if err != nil {
		return err
	}

	installed, err := newManager(*dir, *token).Rollback(ctx, kind)
	if err != nil {
		return err
	}
	fmt.Printf("%s rolled back to %s\n", kind, installed.Version)
	printInstalled(installed)
	return nil
}

func printInstalled(i *cores.Installed) {
	fmt.Printf("  path:      %s\n", i.Path)
	fmt.Printf("  version:   %s\n", i.Version)
	fmt.Printf("  size:      %s\n", humanBytes(i.Size))
	if i.SHA256 != "" {
		fmt.Printf("  sha256:    %s\n", i.SHA256)
	}
	if i.Verified {
		fmt.Printf("  integrity: publisher checksum verified\n")
	} else if i.Managed {
		fmt.Printf("  integrity: unverified (no publisher checksum available)\n")
	}
	if !i.InstalledAt.IsZero() {
		fmt.Printf("  installed: %s\n", i.InstalledAt.Format(time.RFC3339))
	}
}
