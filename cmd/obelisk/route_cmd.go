package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"text/tabwriter"

	"github.com/obelisk-project/obelisk/internal/config"
	"github.com/obelisk-project/obelisk/internal/routing"
)

// cmdRoute dispatches the routing rule subcommands.
func cmdRoute(ctx context.Context, args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("route needs a subcommand: add, list, rm, test or import")
	}

	switch args[0] {
	case "add":
		return cmdRouteAdd(args[1:])
	case "list", "ls":
		return cmdRouteList(args[1:])
	case "rm", "remove", "del":
		return cmdRouteRemove(args[1:])
	case "test", "check":
		return cmdRouteTest(args[1:])
	case "import":
		return cmdRouteImport(args[1:])
	default:
		return fmt.Errorf("unknown route subcommand %q", args[0])
	}
}

// configPathFlag registers the shared -config flag.
func configPathFlag(fs *flag.FlagSet) *string {
	return fs.String("config", filepath.Join(defaultConfigDir, "obelisk.json"),
		"path to the Obelisk configuration file")
}

// cmdRouteAdd stores one or more entries.
func cmdRouteAdd(args []string) error {
	fs := flag.NewFlagSet("route add", flag.ContinueOnError)
	cfgPath := configPathFlag(fs)
	actionFlag := fs.String("action", "proxy", "what to do with matching traffic: proxy, direct or block")
	target := fs.String("target", "", "send matching traffic to a specific group or node instead of the default")
	source := fs.String("source", "", "limit the rule to these client addresses or subnets, comma separated")
	comment := fs.String("comment", "", "a note for your own benefit")

	positional, err := parseArgs(fs, args)
	if err != nil {
		return err
	}
	if len(positional) == 0 {
		return fmt.Errorf("route add needs at least one domain, address or URL")
	}

	action, err := routing.ParseAction(*actionFlag)
	if err != nil {
		return err
	}

	cfg, err := config.Load(*cfgPath)
	if err != nil {
		return err
	}

	for _, raw := range positional {
		entry, err := routing.ParseEntry(raw)
		if err != nil {
			return err
		}
		entry.Action = action
		entry.Target = *target
		entry.Comment = *comment
		if *source != "" {
			entry.Sources = splitCommas(*source)
		}
		entry.Reindex()

		replaced := cfg.AddRule(*entry)
		verb := "added"
		if replaced {
			verb = "updated"
		}
		fmt.Printf("%s: %s\n", verb, entry.Describe())
		if entry.Note != "" {
			fmt.Printf("  note: %s\n", entry.Note)
		}
	}

	if err := cfg.Save(*cfgPath); err != nil {
		return err
	}
	fmt.Printf("\n%d rule(s) stored in %s\n", len(cfg.Rules), *cfgPath)

	reportConflicts(cfg.Rules)

	fmt.Println("\nRun \"obelisk run\" or restart it to apply.")
	return nil
}

// cmdRouteList prints the rules in evaluation order.
func cmdRouteList(args []string) error {
	fs := flag.NewFlagSet("route list", flag.ContinueOnError)
	cfgPath := configPathFlag(fs)
	asJSON := fs.Bool("json", false, "emit JSON instead of a table")
	if _, err := parseArgs(fs, args); err != nil {
		return err
	}

	cfg, err := config.Load(*cfgPath)
	if err != nil {
		return err
	}
	if *asJSON {
		return emitJSON(cfg.Rules)
	}

	if len(cfg.Rules) == 0 {
		fmt.Printf("No routing rules yet.\n\nAdd one with:\n  obelisk route add youtube.com\n")
		return nil
	}

	// Order is not cosmetic here: the first rule that matches decides, so the
	// position number is part of the meaning.
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "#\tID\tMATCH\tVALUE\tACTION\tSCOPE\tCOMMENT")
	for i, r := range cfg.Rules {
		scope := "all clients"
		if len(r.Sources) > 0 {
			scope = strings.Join(r.Sources, ",")
		}
		action := string(r.Action)
		if r.Target != "" {
			action += " → " + r.Target
		}
		if !r.Enabled {
			action = "(disabled) " + action
		}
		fmt.Fprintf(w, "%d\t%s\t%s\t%s\t%s\t%s\t%s\n",
			i+1, r.ID, r.Kind, r.Value, action, scope, r.Comment)
	}
	if err := w.Flush(); err != nil {
		return err
	}

	s := routing.Summarize(cfg.Rules)
	fmt.Printf("\n%d rule(s): %d proxied, %d direct, %d blocked (%d domain, %d network)\n",
		s.Enabled, s.Proxied, s.Direct, s.Blocked, s.Domains, s.Networks)
	fmt.Printf("Split tunnelling: %s.\n", describeSplit(cfg.Settings.Split))

	reportConflicts(cfg.Rules)
	return nil
}

// reportConflicts prints rules that can never take effect.
//
// The first rule that matches decides, so a broad rule written above a narrow
// one makes the narrow one dead code. Nothing about the configuration looks
// wrong when this happens — the rule is right there in the list — so it has to
// be pointed out explicitly, along with the fix.
func reportConflicts(rules []routing.Entry) {
	conflicts := routing.FindShadowed(rules)
	if len(conflicts) == 0 {
		return
	}

	harmful := 0
	for _, c := range conflicts {
		if c.Harmful {
			harmful++
		}
	}

	fmt.Printf("\n%d rule(s) can never match:\n", len(conflicts))
	for _, c := range conflicts {
		label := "redundant"
		if c.Harmful {
			label = "changes behaviour"
		}
		fmt.Printf("  #%d %s — %s\n    %s\n", c.Index+1, c.Entry.Value, label, c.Reason)
		if c.Harmful {
			fmt.Printf("    fix: move #%d above #%d\n", c.Index+1, c.ShadowedBy+1)
		}
	}
	if harmful > 0 {
		fmt.Println("\nRules are evaluated top to bottom and the first match wins,")
		fmt.Println("so a specific rule has to sit above the general one it carves out of.")
	}
}

// cmdRouteRemove deletes rules by identifier or by what they match.
func cmdRouteRemove(args []string) error {
	fs := flag.NewFlagSet("route rm", flag.ContinueOnError)
	cfgPath := configPathFlag(fs)
	positional, err := parseArgs(fs, args)
	if err != nil {
		return err
	}
	if len(positional) == 0 {
		return fmt.Errorf("route rm needs an id or a value to remove")
	}

	cfg, err := config.Load(*cfgPath)
	if err != nil {
		return err
	}

	total := 0
	for _, needle := range positional {
		removed := cfg.RemoveRule(needle)
		if len(removed) == 0 {
			fmt.Printf("no rule matches %q\n", needle)
			continue
		}
		for _, r := range removed {
			fmt.Printf("removed: %s\n", r.Describe())
			total++
		}
	}
	if total == 0 {
		return nil
	}
	return cfg.Save(*cfgPath)
}

// cmdRouteTest reports what would happen to a destination.
func cmdRouteTest(args []string) error {
	fs := flag.NewFlagSet("route test", flag.ContinueOnError)
	cfgPath := configPathFlag(fs)
	from := fs.String("from", "", "test as if the connection came from this client address")
	asJSON := fs.Bool("json", false, "emit JSON instead of text")

	positional, err := parseArgs(fs, args)
	if err != nil {
		return err
	}
	if len(positional) == 0 {
		return fmt.Errorf("route test needs a domain, address or URL")
	}

	cfg, err := config.Load(*cfgPath)
	if err != nil {
		return err
	}

	results := make([]map[string]any, 0, len(positional))
	for _, destination := range positional {
		decision, err := routing.Test(cfg.Rules, destination, *from)
		if err != nil {
			return err
		}

		action := decision.Action
		if decision.Matched == nil || !cfg.Settings.Split.UsesRules() {
			action = cfg.Settings.Split.Fallback()
		}

		if *asJSON {
			results = append(results, map[string]any{
				"destination": destination,
				"decision":    decision,
				"effective":   action,
			})
			continue
		}

		fmt.Printf("%s\n", destination)
		fmt.Printf("  result: %s\n", action)
		fmt.Printf("  why:    %s\n", decision.Explanation)
		if decision.Matched != nil {
			fmt.Printf("  rule:   #%d %s (%s)\n", decision.Index+1, decision.Matched.Value, decision.Matched.ID)
		}
		fmt.Println()
	}

	if *asJSON {
		return emitJSON(results)
	}
	return nil
}

// cmdRouteImport reads a list of entries from a file or standard input.
func cmdRouteImport(args []string) error {
	fs := flag.NewFlagSet("route import", flag.ContinueOnError)
	cfgPath := configPathFlag(fs)
	actionFlag := fs.String("action", "proxy", "what to do with matching traffic: proxy, direct or block")
	replace := fs.Bool("replace", false, "discard the existing rules instead of appending")

	positional, err := parseArgs(fs, args)
	if err != nil {
		return err
	}
	source, err := singleSource("route import", positional)
	if err != nil {
		return err
	}

	action, err := routing.ParseAction(*actionFlag)
	if err != nil {
		return err
	}

	var data []byte
	if source == "-" {
		data, err = io.ReadAll(os.Stdin)
	} else {
		data, err = os.ReadFile(source)
	}
	if err != nil {
		return err
	}

	cfg, err := config.Load(*cfgPath)
	if err != nil {
		return err
	}
	if *replace {
		cfg.Rules = nil
	}

	entries, lineErrors := routing.ParseList(string(data), action)
	for _, e := range entries {
		cfg.AddRule(*e)
	}

	fmt.Printf("imported %d rule(s)\n", len(entries))
	// Unusable lines are listed rather than counted: a user who pasted a list
	// needs to know which lines were dropped, not how many.
	if len(lineErrors) > 0 {
		fmt.Printf("\n%d line(s) could not be read:\n", len(lineErrors))
		for _, le := range lineErrors {
			fmt.Printf("  line %d: %s\n    %s\n", le.Line, le.Text, le.Err)
		}
	}
	if len(entries) == 0 {
		return nil
	}
	return cfg.Save(*cfgPath)
}

func splitCommas(s string) []string {
	parts := strings.Split(s, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if trimmed := strings.TrimSpace(p); trimmed != "" {
			out = append(out, trimmed)
		}
	}
	return out
}

// describeSplit puts a split mode into the words a user would use, because
// "bypass-list" on its own says nothing about which way round it is.
func describeSplit(m config.SplitMode) string {
	switch m {
	case config.SplitBypassList:
		return "everything through the tunnel except what the rules name"
	case config.SplitOff:
		return "everything through the tunnel, rules ignored"
	default:
		return "only what the rules name goes through the tunnel"
	}
}
