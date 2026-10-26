// Package app is Obelisk's service layer: the single owner of the running
// state, sitting between the transports (CLI, HTTP API) and the machinery
// (subscriptions, planning, cores, routing).
//
// Everything that mutates state goes through here, which is what makes it
// possible for the web interface and the command line to be two views of the
// same daemon rather than two programs that happen to edit the same files.
package app

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"log"
	"sort"
	"sync"
	"time"

	"github.com/obelisk-project/obelisk/internal/config"
	"github.com/obelisk-project/obelisk/internal/core"
	"github.com/obelisk-project/obelisk/internal/core/singbox"
	"github.com/obelisk-project/obelisk/internal/cores"
	"github.com/obelisk-project/obelisk/internal/model"
	"github.com/obelisk-project/obelisk/internal/netfw"
	"github.com/obelisk-project/obelisk/internal/probe"
	"github.com/obelisk-project/obelisk/internal/routing"
	"github.com/obelisk-project/obelisk/internal/store"
	"github.com/obelisk-project/obelisk/internal/subs"
)

// Options configures the service.
type Options struct {
	ConfigPath  string
	ConfigDir   string
	CoreDir     string
	GitHubToken string
}

// App holds the whole of Obelisk's running state.
type App struct {
	opts Options

	// mu guards the in-memory state and is only ever held for as long as it
	// takes to read or write a field. Nothing slow may run under it: every
	// status request, every rule listing and every page load takes it, so a
	// single second spent here is a second the whole interface is frozen.
	mu      sync.RWMutex
	cfg     *config.Config
	nodes   []*model.Node
	plan    *core.Plan
	skipped map[string][]subs.SkipReason

	// applyMu serializes the slow half: starting and stopping cores,
	// resolving server names, installing firewall rules. It is held across
	// seconds by design, which is exactly why it has to be a different lock
	// from the one readers use.
	applyMu   sync.Mutex
	refreshMu sync.Mutex

	runtime  *core.Runtime
	coreMgr  *cores.Manager
	firewall *netfw.Manager
	monitor  *probe.Monitor

	// history has its own lock rather than sharing mu, because the sampling
	// goroutine writes to it once a second while calling back into App. Taking
	// mu on that path is what allowed a connect — which stops the sampler while
	// holding mu — to wait forever for a goroutine that was waiting for mu.
	histMu  sync.RWMutex
	history *store.Store

	// providerRules holds the routing each subscription shipped, keyed by
	// subscription. Cached alongside nodes to survive an offline reboot.
	providerRules map[string]*subs.ProviderRules

	// zapret is whether a DPI desynchroniser is intercepting traffic on this
	// router. Detected before each apply, because it can be installed or
	// stopped without Obelisk being involved.
	zapret bool

	connected bool
	lastError string

	// manualIntent records that the connection was driven by hand since start.
	// Automatic retries stand down once it is set: a client that reconnects
	// against a decision the user just made is worse than one that never
	// connects on its own.
	manualIntent bool
	startedAt    time.Time

	// events fans state changes out to whoever is watching, so the web
	// interface reflects a change made from the command line without polling.
	events *eventBus
}

// New loads the configuration and prepares the service. Nothing is started.
func New(opts Options) (*App, error) {
	cfg, err := config.Load(opts.ConfigPath)
	if err != nil {
		return nil, err
	}

	if cfg.DeviceID == "" {
		var id [16]byte
		if _, err := rand.Read(id[:]); err != nil {
			return nil, err
		}
		cfg.DeviceID = hex.EncodeToString(id[:])
		if err := cfg.Save(opts.ConfigPath); err != nil {
			return nil, err
		}
	}
	coreDir := opts.CoreDir
	if cfg.Settings.Core.Dir != "" {
		coreDir = cfg.Settings.Core.Dir
	}

	a := &App{
		opts:          opts,
		cfg:           cfg,
		skipped:       map[string][]subs.SkipReason{},
		providerRules: map[string]*subs.ProviderRules{},
		coreMgr: &cores.Manager{
			Dir:              coreDir,
			Source:           &cores.Source{Token: opts.GitHubToken},
			ExtraLookupPaths: []string{"/usr/bin", "/usr/local/bin", "/opt/bin"},
		},
		events: newEventBus(),
	}
	a.loadSubscriptions()
	return a, nil
}

// Config returns a copy of the current configuration.
func (a *App) Config() config.Config {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return *a.cfg
}

// Events returns a channel of state-change notifications and a cancel function.
func (a *App) Events() (<-chan Event, func()) { return a.events.subscribe() }

// save persists the configuration. The caller must hold the write lock.
func (a *App) save() error {
	if err := a.cfg.Save(a.opts.ConfigPath); err != nil {
		return err
	}
	return nil
}

// ---------------------------------------------------------------- status

// Status is the summary the interface shows at a glance.
type Status struct {
	Connected bool          `json:"connected"`
	Mode      string        `json:"mode"`
	Uptime    float64       `json:"uptime_seconds"`
	LastError string        `json:"last_error,omitempty"`
	Cores     []core.Status `json:"cores"`

	NodeCount     int            `json:"node_count"`
	UsableCount   int            `json:"usable_count"`
	CoreBreakdown map[string]int `json:"core_breakdown"`

	// RuleCount is the user's own rules, ProviderRuleCount the ones the
	// subscriptions contributed. Split says how both lists are read.
	RuleCount         int    `json:"rule_count"`
	ProviderRuleCount int    `json:"provider_rule_count"`
	Split             string `json:"split"`
	Subscriptions     int    `json:"subscription_count"`

	// AutoConnect mirrors the setting so the dashboard switch can show it
	// without a second request.
	AutoConnect bool `json:"auto_connect"`

	// Zapret reports that a DPI desynchroniser is active alongside Obelisk and
	// that the cores' own traffic is being kept out of its way.
	Zapret bool `json:"zapret,omitempty"`

	// SelectedNode is the tag the proxy group points at, and SelectedName its
	// display name. Empty means automatic.
	SelectedNode string `json:"selected_node,omitempty"`
	SelectedName string `json:"selected_name,omitempty"`

	Version string `json:"version"`
}

// Version is stamped by the binary at startup.
var Version = "dev"

// Status returns the current state.
func (a *App) Status() Status {
	a.mu.RLock()
	defer a.mu.RUnlock()

	st := Status{
		Connected:     a.connected,
		Mode:          a.cfg.Settings.Mode,
		LastError:     a.lastError,
		NodeCount:     len(a.nodes),
		RuleCount:     len(a.cfg.Rules),
		Split:         string(a.cfg.Settings.Split),
		AutoConnect:   a.cfg.Settings.AutoConnect,
		Zapret:        a.zapret,
		Subscriptions: len(a.cfg.Subscriptions),
		CoreBreakdown: map[string]int{},
		SelectedNode:  a.cfg.Settings.SelectedNode,
		Version:       Version,
	}
	if st.SelectedNode != "" && a.plan != nil {
		for _, as := range a.plan.Assignments {
			if as.Tag == st.SelectedNode && as.Node != nil {
				st.SelectedName = as.Node.DisplayName()
			}
		}
	}
	if provider, _ := a.providerRouting(); len(provider) > 0 {
		st.ProviderRuleCount = len(provider)
	}
	if !a.startedAt.IsZero() && a.connected {
		st.Uptime = time.Since(a.startedAt).Seconds()
	}
	if a.runtime != nil {
		st.Cores = a.runtime.Status()
	}
	if a.plan != nil {
		for id, n := range a.plan.CountByCore() {
			st.CoreBreakdown[string(id)] = n
			st.UsableCount += n
		}
	}
	return st
}

// ---------------------------------------------------------------- nodes

// NodeView is a node as the interface displays it.
type NodeView struct {
	ID         string `json:"id"`
	Tag        string `json:"tag"` // the outbound tag, which is how the core names it
	Name       string `json:"name"`
	Protocol   string `json:"protocol"`
	Transport  string `json:"transport"`
	Security   string `json:"security"`
	Server     string `json:"server"`
	Port       int    `json:"port"`
	Source     string `json:"source,omitempty"`
	SourceID   string `json:"source_id,omitempty"`
	Core       string `json:"core,omitempty"`
	BridgePort int    `json:"bridge_port,omitempty"`
	Usable     bool   `json:"usable"`
	Reason     string `json:"reason,omitempty"`

	// Delay is the last measured latency in milliseconds. Zero means either
	// never measured or unreachable; Measured tells the two apart, because
	// showing "0 ms" for a dead node would read as the best result in the list.
	Delay    int  `json:"delay,omitempty"`
	Measured bool `json:"measured"`
	Active   bool `json:"active,omitempty"`
}

// Nodes returns every known node with the core that would carry it.
func (a *App) Nodes() []NodeView {
	a.mu.RLock()
	defer a.mu.RUnlock()

	latencies := a.latencies()

	if a.plan == nil {
		out := make([]NodeView, 0, len(a.nodes))
		for _, n := range a.nodes {
			out = append(out, nodeView(n, core.Assignment{}, latencies))
		}
		return out
	}

	out := make([]NodeView, 0, len(a.plan.Assignments))
	for _, as := range a.plan.Assignments {
		out = append(out, nodeView(as.Node, as, latencies))
	}
	return a.markSelected(out)
}

func nodeView(n *model.Node, as core.Assignment, latencies map[string]probe.Latency) NodeView {
	v := NodeView{
		ID:        n.ID,
		Tag:       as.Tag,
		Name:      n.DisplayName(),
		Protocol:  string(n.Protocol),
		Transport: string(n.Transport.Type),
		Security:  string(n.TLS.Security),
		Server:    n.Server,
		Port:      n.Port,
		Source:    n.SourceName,
		SourceID:  n.Source,
		Usable:    true,
	}
	if as.Core != "" {
		v.Core = string(as.Core)
		v.BridgePort = as.BridgePort
	}
	if as.Reason != "" {
		v.Usable = false
		v.Reason = as.Reason
	}
	if latency, ok := latencies[as.Tag]; ok {
		v.Measured = true
		v.Delay = latency.Delay
	}
	return v
}

// markSelected flags the node the proxy group points at. The caller holds the
// lock.
func (a *App) markSelected(views []NodeView) []NodeView {
	chosen := a.cfg.Settings.SelectedNode
	if chosen == "" {
		return views
	}
	for i := range views {
		views[i].Active = views[i].Tag == chosen
	}
	return views
}

// ---------------------------------------------------------------- subscriptions

// AddSubscription stores a subscription and fetches it immediately, so that a
// mistyped URL is reported while the user is still looking at the form.
func (a *App) AddSubscription(ctx context.Context, name, url, userAgent string) (*config.Subscription, error) {
	if url == "" {
		return nil, fmt.Errorf("a subscription needs a URL")
	}

	a.mu.Lock()
	for _, s := range a.cfg.Subscriptions {
		if s.URL == url {
			a.mu.Unlock()
			return nil, fmt.Errorf("that subscription is already configured")
		}
	}
	sub := config.Subscription{
		ID:          newID(),
		Name:        name,
		URL:         url,
		UserAgent:   userAgent,
		Enabled:     true,
		ImportRules: true,
	}
	a.cfg.Subscriptions = append(a.cfg.Subscriptions, sub)
	err := a.save()
	a.mu.Unlock()

	if err != nil {
		return nil, err
	}

	if err := a.Refresh(ctx); err != nil {
		return &sub, err
	}
	return &sub, nil
}

// DeleteSubscription removes a subscription and the nodes it contributed.
func (a *App) DeleteSubscription(ctx context.Context, id string) error {
	a.mu.Lock()
	kept := a.cfg.Subscriptions[:0]
	found := false
	for _, s := range a.cfg.Subscriptions {
		if s.ID == id {
			found = true
			continue
		}
		kept = append(kept, s)
	}
	a.cfg.Subscriptions = kept
	if !found {
		a.mu.Unlock()
		return fmt.Errorf("no such subscription")
	}
	err := a.save()
	a.mu.Unlock()
	if err != nil {
		return err
	}
	return a.Refresh(ctx)
}

// SetSubscriptionEnabled turns a subscription on or off.
func (a *App) SetSubscriptionEnabled(ctx context.Context, id string, enabled bool) error {
	a.mu.Lock()
	found := false
	for i := range a.cfg.Subscriptions {
		if a.cfg.Subscriptions[i].ID == id {
			a.cfg.Subscriptions[i].Enabled = enabled
			found = true
		}
	}
	if !found {
		a.mu.Unlock()
		return fmt.Errorf("no such subscription")
	}
	err := a.save()
	a.mu.Unlock()
	if err != nil {
		return err
	}
	return a.Refresh(ctx)
}

// SetSubscriptionUserAgent changes the identity a subscription is fetched with
// and re-fetches it, since that is the only way to see what it changed.
func (a *App) SetSubscriptionUserAgent(ctx context.Context, id, userAgent string) error {
	a.mu.Lock()
	found := false
	for i := range a.cfg.Subscriptions {
		if a.cfg.Subscriptions[i].ID == id {
			a.cfg.Subscriptions[i].UserAgent = userAgent
			// The stored validators belong to the old identity's response and
			// would earn a 304 for a payload we no longer want.
			a.cfg.Subscriptions[i].ETag = ""
			a.cfg.Subscriptions[i].LastModified = ""
			found = true
		}
	}
	if !found {
		a.mu.Unlock()
		return fmt.Errorf("no such subscription")
	}
	err := a.save()
	a.mu.Unlock()
	if err != nil {
		return err
	}
	return a.RefreshOne(ctx, id)
}

// Refresh re-fetches every enabled subscription and rebuilds the plan.
//
// A subscription that fails keeps its previously known nodes rather than
// vanishing: a router that loses its node list because a panel was briefly down
// is a worse outcome than one running on slightly stale data.
func (a *App) Refresh(ctx context.Context) error {
	a.refreshMu.Lock()
	defer a.refreshMu.Unlock()
	a.mu.RLock()
	subscriptions := a.cfg.EnabledSubscriptions()
	a.mu.RUnlock()

	var (
		collected []*model.Node
		skipped   = map[string][]subs.SkipReason{}
		imported  = map[string]*subs.ProviderRules{}
		firstErr  error
	)

	for _, s := range subscriptions {
		res, err := subs.Fetch(ctx, s.URL, a.fetchOptions(s.UserAgent))
		if err != nil {
			a.recordSubscriptionError(s.ID, err)
			if firstErr == nil {
				firstErr = fmt.Errorf("%s: %w", displayName(s), err)
			}
			a.mu.RLock()
			for _, n := range a.nodes {
				if n.Source == s.ID {
					collected = append(collected, n)
				}
			}
			skipped[s.ID] = a.skipped[s.ID]
			imported[s.ID] = a.providerRules[s.ID]
			a.mu.RUnlock()
			continue
		}
		if res.Result == nil {
			continue
		}

		for _, n := range res.Result.Nodes {
			n.Source = s.ID
			n.SourceName = displayName(s)
			collected = append(collected, n)
		}
		skipped[s.ID] = res.Result.Skipped
		if res.Result.Rules != nil && res.Result.Rules.Count() > 0 {
			// Tag every imported rule with where it came from, so the interface
			// can show it as the provider's and never let it be edited as if it
			// were the user's own.
			name := displayName(s)
			for i := range res.Result.Rules.Entries {
				res.Result.Rules.Entries[i].Origin = name
			}
			imported[s.ID] = res.Result.Rules
		}
		a.recordSubscriptionSuccess(s.ID, res, len(res.Result.Nodes))
	}

	a.mu.Lock()
	a.nodes = collected
	a.skipped = skipped
	a.providerRules = imported
	cacheErr := a.saveSubscriptions()
	planOpts := core.DefaultPlanOptions()
	planOpts.Policy = a.cfg.Settings.Core.Policy
	plan, err := core.BuildPlan(collected, planOpts)
	if err == nil {
		a.plan = plan
	}
	a.mu.Unlock()

	a.events.publish(Event{Type: "nodes"})
	a.reloadAfterChange(ctx)

	if firstErr != nil {
		return firstErr
	}
	if cacheErr != nil {
		return cacheErr
	}
	return err
}

func (a *App) recordSubscriptionSuccess(id string, res *subs.FetchResult, nodeCount int) {
	format, ruleCount := "", 0
	if res.Result != nil {
		format = string(res.Result.Format)
		ruleCount = res.Result.Rules.Count()
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	for i := range a.cfg.Subscriptions {
		s := &a.cfg.Subscriptions[i]
		if s.ID != id {
			continue
		}
		s.LastUpdate = time.Now().UTC()
		s.LastError = ""
		s.NodeCount = nodeCount
		s.Format = format
		s.RuleCount = ruleCount
		s.ETag = res.ETag
		s.LastModified = res.LastModified
		if s.Name == "" && res.ProfileTitle != "" {
			s.Name = res.ProfileTitle
		}
	}
	_ = a.save()
}

func (a *App) recordSubscriptionError(id string, err error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	for i := range a.cfg.Subscriptions {
		if a.cfg.Subscriptions[i].ID == id {
			a.cfg.Subscriptions[i].LastError = err.Error()
		}
	}
	_ = a.save()
}

func displayName(s config.Subscription) string {
	if s.Name != "" {
		return s.Name
	}
	return s.URL
}

// ---------------------------------------------------------------- rules

// RefreshOne re-fetches a single subscription, leaving the others alone.
//
// Refreshing everything to update one is slow when a provider is unreachable —
// the failing one holds up the rest — and it is the wrong thing to offer next to
// a single subscription in the interface.
func (a *App) RefreshOne(ctx context.Context, id string) error {
	a.refreshMu.Lock()
	defer a.refreshMu.Unlock()
	a.mu.RLock()
	var target *config.Subscription
	for i := range a.cfg.Subscriptions {
		if a.cfg.Subscriptions[i].ID == id {
			s := a.cfg.Subscriptions[i]
			target = &s
		}
	}
	a.mu.RUnlock()

	if target == nil {
		return fmt.Errorf("no such subscription")
	}
	if !target.Enabled {
		return fmt.Errorf("subscription is disabled")
	}

	res, err := subs.Fetch(ctx, target.URL, a.fetchOptions(target.UserAgent))
	if err != nil {
		a.recordSubscriptionError(id, err)
		a.events.publish(Event{Type: "nodes"})
		return err
	}
	if res.Result == nil {
		return nil
	}

	name := displayName(*target)
	for _, n := range res.Result.Nodes {
		n.Source = id
		n.SourceName = name
	}
	if res.Result.Rules != nil {
		for i := range res.Result.Rules.Entries {
			res.Result.Rules.Entries[i].Origin = name
		}
	}

	a.mu.Lock()
	// Everything from this subscription is replaced; nodes from the others stay
	// exactly as they were.
	kept := a.nodes[:0:0]
	for _, n := range a.nodes {
		if n.Source != id {
			kept = append(kept, n)
		}
	}
	a.nodes = append(kept, res.Result.Nodes...)
	a.skipped[id] = res.Result.Skipped
	if res.Result.Rules != nil && res.Result.Rules.Count() > 0 {
		a.providerRules[id] = res.Result.Rules
	} else {
		delete(a.providerRules, id)
	}

	planOpts := core.DefaultPlanOptions()
	planOpts.Policy = a.cfg.Settings.Core.Policy
	if plan, err := core.BuildPlan(a.nodes, planOpts); err == nil {
		a.plan = plan
	}
	cacheErr := a.saveSubscriptions()
	a.mu.Unlock()

	a.recordSubscriptionSuccess(id, res, len(res.Result.Nodes))
	a.events.publish(Event{Type: "nodes"})
	a.reloadAfterChange(ctx)
	return cacheErr
}

// PreviewConfig renders the sing-box configuration the daemon would write,
// without writing or starting anything.
//
// It exists because a configuration is only a hypothesis until the core that
// has to read it agrees, and validating a config produced by some other code
// path proves nothing about this one — a lesson learned the hard way, when a
// setting differed between the command line and the daemon and only the daemon's
// version was rejected.
func (a *App) PreviewConfig() ([]byte, error) {
	a.mu.RLock()
	defer a.mu.RUnlock()

	if a.plan == nil || len(a.plan.CarriedTags()) == 0 {
		return nil, fmt.Errorf("no usable nodes yet")
	}
	cfg, err := a.routingConfig()
	if err != nil {
		return nil, err
	}
	cfg.Options = a.singboxOptions()
	return a.plan.SingBoxConfig(cfg)
}

// AddRules parses and stores routing entries, returning what was understood.
func (a *App) AddRules(raw []string, action routing.Action, target string, sources []string, comment string) ([]routing.Entry, []routing.LineError, error) {
	var (
		added []routing.Entry
		errs  []routing.LineError
	)

	for i, line := range raw {
		entry, err := routing.ParseEntry(line)
		if err != nil {
			errs = append(errs, routing.LineError{Line: i + 1, Text: line, Err: err.Error()})
			continue
		}
		entry.Action = action
		entry.Target = target
		entry.Sources = sources
		entry.Comment = comment
		entry.Reindex()
		added = append(added, *entry)
	}
	if len(added) == 0 {
		return nil, errs, nil
	}

	a.mu.Lock()
	for _, e := range added {
		a.cfg.AddRule(e)
	}
	err := a.save()
	a.mu.Unlock()
	if err != nil {
		return nil, errs, err
	}

	a.events.publish(Event{Type: "rules"})
	a.reloadAfterChange(context.Background())
	return added, errs, nil
}

// DeleteRule removes a rule by identifier or by the value it matches.
func (a *App) DeleteRule(idOrValue string) (int, error) {
	a.mu.Lock()
	removed := a.cfg.RemoveRule(idOrValue)
	err := a.save()
	a.mu.Unlock()
	if err != nil {
		return 0, err
	}
	if len(removed) > 0 {
		a.events.publish(Event{Type: "rules"})
		a.reloadAfterChange(context.Background())
	}
	return len(removed), nil
}

// SetRuleEnabled toggles one rule without deleting it.
func (a *App) SetRuleEnabled(id string, enabled bool) error {
	a.mu.Lock()
	found := false
	for i := range a.cfg.Rules {
		if a.cfg.Rules[i].ID == id {
			a.cfg.Rules[i].Enabled = enabled
			found = true
		}
	}
	if !found {
		a.mu.Unlock()
		return fmt.Errorf("no such rule")
	}
	err := a.save()
	a.mu.Unlock()
	if err != nil {
		return err
	}
	a.events.publish(Event{Type: "rules"})
	a.reloadAfterChange(context.Background())
	return nil
}

// MoveRule changes a rule's position. Order is meaning here — the first match
// wins — so this is how a user resolves a shadowed rule.
func (a *App) MoveRule(id string, to int) error {
	a.mu.Lock()

	from := -1
	for i := range a.cfg.Rules {
		if a.cfg.Rules[i].ID == id {
			from = i
			break
		}
	}
	if from < 0 {
		a.mu.Unlock()
		return fmt.Errorf("no such rule")
	}
	if to < 0 {
		to = 0
	}
	if to >= len(a.cfg.Rules) {
		to = len(a.cfg.Rules) - 1
	}
	if from == to {
		a.mu.Unlock()
		return nil
	}

	entry := a.cfg.Rules[from]
	rules := append(a.cfg.Rules[:from], a.cfg.Rules[from+1:]...)
	rules = append(rules, routing.Entry{})
	copy(rules[to+1:], rules[to:])
	rules[to] = entry
	a.cfg.Rules = rules

	err := a.save()
	a.mu.Unlock()
	if err != nil {
		return err
	}

	a.events.publish(Event{Type: "rules"})
	a.reloadAfterChange(context.Background())
	return nil
}

// Rules returns the rules in evaluation order together with any that can never
// match.
func (a *App) Rules() ([]routing.Entry, []routing.Conflict) {
	a.mu.RLock()
	defer a.mu.RUnlock()

	out := make([]routing.Entry, len(a.cfg.Rules))
	copy(out, a.cfg.Rules)
	return out, routing.FindShadowed(out)
}

// ProviderRules returns the rules imported from subscriptions, in the order
// they are applied — which is beneath everything in Rules.
func (a *App) ProviderRules() []routing.Entry {
	a.mu.RLock()
	defer a.mu.RUnlock()

	entries, _ := a.providerRouting()
	return entries
}

// TestRoute reports what would happen to a destination.
func (a *App) TestRoute(destination, source string) (*routing.Decision, routing.Action, error) {
	a.mu.RLock()
	// The check has to see the same list the router will: the user's rules
	// first, then whatever the subscriptions contributed underneath.
	provider, _ := a.providerRouting()
	rules := make([]routing.Entry, 0, len(a.cfg.Rules)+len(provider))
	rules = append(rules, a.cfg.Rules...)
	rules = append(rules, provider...)
	fallback := a.cfg.Settings.Split.Fallback()
	usesRules := a.cfg.Settings.Split.UsesRules()
	a.mu.RUnlock()

	// In the mode that ignores the lists, saying what a rule would have done is
	// worse than saying nothing: it would describe a route the core is not using.
	if !usesRules {
		return &routing.Decision{
			Index:       -1,
			Action:      fallback,
			Explanation: "split tunnelling is off, so every destination goes through the tunnel",
		}, fallback, nil
	}

	decision, err := routing.Test(rules, destination, source)
	if err != nil {
		return nil, "", err
	}
	effective := decision.Action
	if decision.Matched == nil {
		effective = fallback
	}
	return decision, effective, nil
}

// ---------------------------------------------------------------- settings

// UpdateSettings replaces the settings block and persists it.
func (a *App) UpdateSettings(s config.Settings) error {
	// An unrecognized split mode must be refused rather than quietly falling
	// back, because both of the values it could fall back to are a decision
	// about where a household's traffic goes.
	if !s.Split.Valid() {
		return fmt.Errorf("split must be %q, %q or %q, not %q",
			config.SplitProxyList, config.SplitBypassList, config.SplitOff, s.Split)
	}

	a.mu.Lock()
	a.cfg.Settings = s
	err := a.save()
	a.mu.Unlock()
	if err != nil {
		return err
	}

	a.events.publish(Event{Type: "settings"})
	// The save is what the caller asked for and it succeeded. A tunnel that
	// could not be brought in line is recorded as the last error and shown in
	// the interface, not reported as a failure to save.
	a.reloadAfterChange(context.Background())
	return nil
}

// ---------------------------------------------------------------- cores

// CoreStatus reports the installed and available core versions.
func (a *App) CoreStatus(ctx context.Context) []cores.Status {
	target := cores.CurrentTarget()
	out := make([]cores.Status, 0, len(cores.AllKinds))
	for _, k := range cores.AllKinds {
		out = append(out, a.coreMgr.Status(ctx, k, target))
	}
	return out
}

// UpdateCore installs the latest release of one core.
func (a *App) UpdateCore(ctx context.Context, kind cores.Kind) (*cores.UpdateResult, error) {
	res, err := a.coreMgr.Update(ctx, kind, cores.CurrentTarget())
	if err != nil {
		return nil, err
	}
	a.events.publish(Event{Type: "cores"})
	return res, nil
}

// ---------------------------------------------------------------- lifecycle

// Connect brings the cores up against the current nodes and rules.
func (a *App) Connect(ctx context.Context) error {
	a.mu.RLock()
	hasPlan := a.plan != nil && len(a.nodes) > 0
	a.mu.RUnlock()

	if !hasPlan {
		if err := a.Refresh(ctx); err != nil {
			return err
		}
	}

	a.applyMu.Lock()
	defer a.applyMu.Unlock()

	if err := a.bringUp(ctx); err != nil {
		a.setLastError(err.Error())
		a.events.publish(Event{Type: "status"})
		return err
	}

	a.mu.Lock()
	a.connected = true
	a.lastError = ""
	a.startedAt = time.Now()
	a.mu.Unlock()

	a.events.publish(Event{Type: "status"})
	return nil
}

// Reload brings a running tunnel in line with the current configuration.
//
// Every edit a user makes is written to disk the moment they make it, but the
// cores go on serving whatever they were started with until this runs. Without
// it the interface accepts a rule, reports success, and changes nothing about
// where traffic actually goes — the change appears to have worked and has not.
//
// It is cheap when nothing relevant moved: the runtime hashes each core's
// configuration and only restarts a core whose own file actually differs, so a
// setting that neither core cares about costs a render and no interruption.
func (a *App) Reload(ctx context.Context) error {
	if !a.Connected() {
		return nil
	}

	a.applyMu.Lock()
	defer a.applyMu.Unlock()

	// Re-checked under applyMu: a disconnect may have run while we queued, and
	// bringing the cores back up behind its back would leave a tunnel nobody
	// asked for.
	if !a.Connected() {
		return nil
	}

	if err := a.bringUp(ctx); err != nil {
		a.setLastError(err.Error())
		a.events.publish(Event{Type: "status"})
		return err
	}
	a.setLastError("")
	a.events.publish(Event{Type: "status"})
	return nil
}

// reloadAfterChange pushes a configuration change into a running tunnel and
// logs rather than returns a failure.
//
// It is called from the edit paths — adding a rule, changing a setting,
// refreshing a subscription — where the edit itself has already succeeded and
// been written to disk. Failing the edit because the cores could not be brought
// in line would leave the user with a rule they can see in the list, were told
// was rejected, and which will take effect the next time anything reconnects.
// Recording it as the last error and letting the interface show it is the
// honest version.
//
// The context is deliberately not the request's: a browser tab closed halfway
// through must not abort a core restart and leave the tunnel half-applied.
func (a *App) reloadAfterChange(ctx context.Context) error {
	if !a.Connected() {
		return nil
	}
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 90*time.Second)
	defer cancel()

	if err := a.Reload(ctx); err != nil {
		log.Printf("obelisk: the change is saved but the cores did not take it: %v", err)
		return err
	}
	return nil
}

// Connected reports whether the tunnel is meant to be up.
func (a *App) Connected() bool {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return a.connected
}

// setLastError records the most recent failure for the interface to show.
func (a *App) setLastError(msg string) {
	a.mu.Lock()
	a.lastError = msg
	a.mu.Unlock()
}

// bringUp renders the current configuration into the cores and installs the
// capture rules.
//
// The caller holds applyMu and no other lock. Everything read out of the state
// is read in one short critical section up front; what follows — resolving
// names, restarting processes, rewriting firewall rules — takes seconds, and
// none of it may run while holding a lock that every status request needs.
func (a *App) bringUp(ctx context.Context) error {
	// Detected outside the lock: it shells out to nft, and nothing that runs a
	// subprocess may hold the lock every status request needs.
	zapret := netfw.DetectZapret(ctx)

	a.mu.Lock()
	a.zapret = zapret
	if a.plan == nil || len(a.plan.CarriedTags()) == 0 {
		a.mu.Unlock()
		return fmt.Errorf("no node can be carried by either core")
	}
	plan := a.plan
	zapretMode := a.cfg.Settings.Firewall.Zapret
	sbOpts := a.singboxOptions()
	routingCfg, cfgErr := a.routingConfig()
	fwManage := a.cfg.Settings.Firewall.Manage
	fwCfg := a.firewallConfig()
	a.mu.Unlock()

	if cfgErr != nil {
		return cfgErr
	}

	singboxPath, _, err := a.coreMgr.Resolve(cores.KindSingBox)
	if err != nil {
		return err
	}
	xrayPath := ""
	if plan.NeedsXray() {
		xrayPath, _, err = a.coreMgr.Resolve(cores.KindXray)
		if err != nil {
			return fmt.Errorf("this subscription needs Xray: %w", err)
		}
	}

	a.mu.Lock()
	if a.runtime == nil {
		a.runtime = core.NewRuntime(core.RuntimeOptions{
			ConfigDir:     a.opts.ConfigDir,
			SingBoxBinary: singboxPath,
			SingBox:       sbOpts,
		})
	}
	rt := a.runtime
	a.mu.Unlock()

	// A settings change can move the capture mode or the resolvers, and those
	// live in the core options rather than in the routing config.
	rt.Configure(singboxPath, xrayPath, sbOpts)

	if err := rt.Apply(ctx, plan, routingCfg); err != nil {
		return err
	}

	// The capture rules go in only once the cores are listening. Installing them
	// first would divert the LAN's traffic to a port with nothing behind it.
	if fwManage {
		// The servers themselves must never be captured, and finding their
		// addresses means DNS — which is why it happens here and not while the
		// state was locked.
		v4, v6 := resolveServers(ctx, plan)
		fwCfg.BypassIPv4 = append(fwCfg.BypassIPv4, v4...)
		fwCfg.BypassIPv6 = append(fwCfg.BypassIPv6, v6...)

		a.mu.Lock()
		previous := a.firewall
		manager := netfw.New(fwCfg)
		a.firewall = manager
		a.mu.Unlock()

		// Out with the old rules before the new ones, so a mode change does not
		// leave the previous mode's rules behind to fight with.
		if previous != nil {
			_ = previous.Remove(ctx)
		}
		if err := manager.Apply(ctx); err != nil {
			// Leave nothing half-applied: without working rules the cores are
			// just idle listeners, but with half of them the LAN loses its route
			// out.
			_ = manager.Remove(ctx)
			a.mu.Lock()
			a.firewall = nil
			a.mu.Unlock()
			_ = rt.Stop(ctx)
			return err
		}
	}

	// zapret's injected packets are locally originated and would otherwise be
	// swallowed by the tunnel's own routing before reaching the provider.
	a.applyZapretRoute(ctx, zapret, zapretMode)

	a.startMonitor(ctx, sbOpts)
	return nil
}

// applyZapretRoute installs or removes the routing exemption for a DPI
// desynchroniser's own packets. Failure is logged, not fatal: the tunnel works
// either way, and only the bypass on the direct path depends on it.
func (a *App) applyZapretRoute(ctx context.Context, present bool, mode config.ZapretMode) {
	manager := netfw.New(netfw.DefaultConfig())
	if !present || mode != config.ZapretShare {
		_ = manager.RemoveZapretRoute(ctx, netfw.ZapretExemptBit)
		return
	}
	if err := manager.InstallZapretRoute(ctx, netfw.ZapretExemptBit); err != nil {
		log.Printf("obelisk: zapret is running but its packets could not be routed around the tunnel: %v", err)
	}
}

// Disconnect stops the cores and removes the capture rules.
//
// The rules come out first. Stopping the cores while traffic is still being
// diverted to them would black-hole the LAN for as long as the teardown takes.
func (a *App) Disconnect(ctx context.Context) error {
	a.applyMu.Lock()
	defer a.applyMu.Unlock()

	a.stopMonitor()

	a.mu.Lock()
	fw := a.firewall
	a.firewall = nil
	rt := a.runtime
	a.connected = false
	a.mu.Unlock()

	if fw != nil {
		if err := fw.Remove(ctx); err != nil {
			a.setLastError(err.Error())
		}
	}
	_ = netfw.New(netfw.DefaultConfig()).RemoveZapretRoute(ctx, netfw.ZapretExemptBit)

	if rt == nil {
		a.events.publish(Event{Type: "status"})
		return nil
	}
	err := rt.Stop(ctx)

	// A core that had to be killed rather than asked never removed its own
	// routing, so check regardless of whether the stop reported success.
	if removed, sweepErr := a.SweepStaleRouting(ctx); sweepErr == nil && removed > 0 {
		log.Printf("obelisk: cleaned up %d routing rule(s) the tunnel left behind", removed)
	}

	a.events.publish(Event{Type: "status"})
	return err
}

// Logs returns recent core output.
func (a *App) Logs(name string, n int) []core.LogLine {
	a.mu.RLock()
	rt := a.runtime
	a.mu.RUnlock()

	if rt == nil {
		return nil
	}
	lines := rt.Logs(name, n)
	sort.SliceStable(lines, func(i, j int) bool { return lines[i].Time.Before(lines[j].Time) })
	return lines
}

// singboxOptions builds the core options from settings. The caller holds the lock.
func (a *App) singboxOptions() singbox.Options {
	opts := singbox.DefaultOptions()
	opts.Mode = singbox.InboundMode(a.cfg.Settings.Mode)
	opts.CacheFile = a.opts.ConfigDir + "/cache.db"
	opts.DNSProxy = a.cfg.Settings.DNS.Proxy
	opts.FakeIP = a.cfg.Settings.DNS.FakeIP

	// The direct resolver has to be somewhere the core can actually reach. It
	// binds its outbound sockets to the default route's interface, so an address
	// on this machine or on the LAN behind it is delivered to the ISP and lost —
	// and a core that cannot resolve anything takes the whole network with it.
	opts.DNSDirect = a.cfg.Settings.DNS.Direct
	if !reachableFromCore(opts.DNSDirect) {
		log.Printf("obelisk: the direct resolver %q is not reachable from the core (it binds to the WAN interface); using %s instead",
			a.cfg.Settings.DNS.Direct, fallbackDirectResolver)
		opts.DNSDirect = fallbackDirectResolver
	}

	// Offer IPv6 in the tunnel only if this host has IPv6 to offer.
	opts.IPv6 = hasGlobalIPv6()
	opts.DNSPort = a.cfg.Settings.DNS.Listen
	opts.DNSStrategy = a.cfg.Settings.DNS.Strategy

	// The front core marks its own sockets so the capture rules let them past;
	// without it, TPROXY mode would feed sing-box's outbound connections back
	// into sing-box.
	opts.DefaultMark = netfw.DefaultBypassMark
	if m := a.cfg.Settings.Firewall.BypassMark; m != 0 {
		opts.DefaultMark = m
	}

	// Coexistence with a DPI desynchroniser. Only the "exempt" mode touches the
	// mark: it hides the cores' connections from zapret entirely, which is safe
	// and costs the bypass on the direct path. "share" leaves the mark alone and
	// instead gives zapret's injected packets a way out past the tunnel, which
	// is installed alongside the firewall rules rather than here.
	if a.zapret && a.cfg.Settings.Firewall.Zapret == config.ZapretExempt {
		opts.DefaultMark = netfw.WithZapretExempt(opts.DefaultMark)
	}
	return opts
}

// routingConfig compiles the rules. The caller holds the lock.
func (a *App) routingConfig() (singbox.Config, error) {
	tags := a.plan.CarriedTags()
	proxyGroup := a.cfg.Settings.ProxyGroup
	if proxyGroup == "" {
		proxyGroup = "proxy"
	}

	opts := routing.CompileOptions{ProxyTag: proxyGroup, DirectTag: singbox.TagDirect}
	split := a.cfg.Settings.Split

	// The private-address rule is not part of the split at all. A router that
	// sent its own LAN into the tunnel would cut every device off from every
	// other one, and no mode should be able to ask for that.
	rules := []singbox.Rule{{IPIsPrivate: true, Outbound: singbox.TagDirect}}
	var ruleSets []singbox.RuleSet

	if split.UsesRules() {
		userRules, err := routing.Compile(a.cfg.Rules, opts)
		if err != nil {
			return singbox.Config{}, err
		}

		// The user's rules are compiled above the provider's, and that ordering
		// is the entire mechanism. Routing is first-match-wins, so anything the
		// user wrote beats whatever the subscription shipped for the same
		// destination — without either list having to know the other exists.
		// Change provider and the lower layer is replaced wholesale while the
		// upper one is untouched.
		providerEntries, sets := a.providerRouting()
		providerRules, err := routing.Compile(providerEntries, opts)
		if err != nil {
			return singbox.Config{}, err
		}

		ruleSets = sets
		rules = append(rules, userRules...)
		rules = append(rules, providerRules...)
	}

	final := singbox.TagDirect
	if split.Fallback() == routing.ActionProxy {
		final = proxyGroup
	}

	// The selector starts on whatever the user chose while the cores were down.
	// Without this the choice would be silently forgotten on every restart.
	selected := "auto"
	if s := a.cfg.Settings.SelectedNode; s != "" {
		for _, t := range tags {
			if t == s {
				selected = s
				break
			}
		}
	}

	return singbox.Config{
		Groups: []singbox.Group{
			{Tag: "auto", Type: "urltest", Outbounds: tags, Interval: "3m", Tolerance: 50},
			{Tag: proxyGroup, Type: "selector", Outbounds: append([]string{"auto"}, tags...), Default: selected},
		},
		Rules:    rules,
		RuleSets: ruleSets,
		FinalTag: final,
		ProxyTag: proxyGroup,
	}, nil
}

// providerRouting collects the imported rules from every enabled subscription
// that has them. The caller holds the lock.
func (a *App) providerRouting() ([]routing.Entry, []singbox.RuleSet) {
	var (
		entries []routing.Entry
		sets    []singbox.RuleSet
		seen    = map[string]bool{}
	)

	for _, s := range a.cfg.Subscriptions {
		if !s.Enabled || !s.ImportRules {
			continue
		}
		imported := a.providerRules[s.ID]
		if imported == nil {
			continue
		}
		entries = append(entries, imported.Entries...)
		for _, rs := range imported.RuleSets {
			// Two subscriptions can name the same public rule set; defining it
			// twice would be rejected by the core.
			if seen[rs.Tag] {
				continue
			}
			seen[rs.Tag] = true
			sets = append(sets, rs)
		}
	}
	return entries, sets
}

// newID returns a short unique identifier for a stored object.
func newID() string {
	return fmt.Sprintf("%x", time.Now().UnixNano())[:12]
}

// SetSubscriptionImportRules turns a provider's own routing on or off.
//
// Switching it off leaves the user's rules untouched, which is the point of
// keeping the two layers apart: a provider whose routing turns out to be wrong
// can be silenced without unpicking anything the user wrote.
func (a *App) SetSubscriptionImportRules(ctx context.Context, id string, enabled bool) error {
	a.mu.Lock()
	found := false
	for i := range a.cfg.Subscriptions {
		if a.cfg.Subscriptions[i].ID == id {
			a.cfg.Subscriptions[i].ImportRules = enabled
			found = true
		}
	}
	if !found {
		a.mu.Unlock()
		return fmt.Errorf("no such subscription")
	}
	err := a.save()
	a.mu.Unlock()
	if err != nil {
		return err
	}

	a.events.publish(Event{Type: "rules"})
	a.reloadAfterChange(context.Background())
	return nil
}
