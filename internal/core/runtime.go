package core

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/obelisk-project/obelisk/internal/core/singbox"
	"github.com/obelisk-project/obelisk/internal/core/xray"
)

// RuntimeOptions configures how the cores are launched.
type RuntimeOptions struct {
	// ConfigDir receives the generated configuration files. It must be writable
	// and readable by whatever user the cores run as.
	ConfigDir string

	// SingBoxBinary and XrayBinary are absolute paths to the core executables,
	// normally supplied by the cores package.
	SingBoxBinary string
	XrayBinary    string

	SingBox singbox.Options
	Xray    xray.Options

	// BridgeSettleDelay is how long to wait after (re)starting Xray before
	// pointing the front core at its listeners. Without it, sing-box can dial a
	// bridge port in the moment between the process starting and the listener
	// binding, and the first connections through those nodes fail for no visible
	// reason.
	BridgeSettleDelay time.Duration

	// StopTimeout bounds how long a core is given to exit before its process is
	// abandoned.
	StopTimeout time.Duration
}

func (o *RuntimeOptions) applyDefaults() {
	if o.BridgeSettleDelay == 0 {
		o.BridgeSettleDelay = 300 * time.Millisecond
	}
	if o.StopTimeout == 0 {
		// sing-box tears down its interface and routing on the way out, and
		// being killed partway through that is what strands a LAN.
		o.StopTimeout = 20 * time.Second
	}
	if o.SingBox.Mode == "" {
		o.SingBox = singbox.DefaultOptions()
	}
	if o.Xray.LogLevel == "" {
		o.Xray = xray.DefaultOptions()
	}
}

// Runtime owns the two core processes and keeps them in sync with a Plan.
//
// Its central promise is that applying an unchanged plan is free: configurations
// are hashed, and a core is only restarted when its own configuration actually
// differs. On a router this is the difference between a subscription refresh
// that drops every connection and one nobody notices.
type Runtime struct {
	opts RuntimeOptions

	mu       sync.Mutex
	singbox  *Supervisor
	xray     *Supervisor
	plan     *Plan
	hashes   map[string]string
	stopping bool
}

// NewRuntime creates a runtime. No process is started until Apply is called.
func NewRuntime(opts RuntimeOptions) *Runtime {
	opts.applyDefaults()
	return &Runtime{
		opts:   opts,
		hashes: map[string]string{},
	}
}

// Apply renders the plan into both cores' configurations and brings the
// processes in line with them.
func (r *Runtime) Apply(ctx context.Context, plan *Plan, sbConfig singbox.Config) error {
	if plan == nil {
		return fmt.Errorf("runtime: no plan given")
	}

	r.mu.Lock()
	defer r.mu.Unlock()
	if r.stopping {
		return fmt.Errorf("runtime: shutting down")
	}

	if err := os.MkdirAll(r.opts.ConfigDir, 0o755); err != nil {
		return fmt.Errorf("runtime: %w", err)
	}

	// Render first, write second. A plan that cannot be rendered must not be
	// allowed to overwrite a configuration that currently works.
	sbConfig.Options = r.opts.SingBox
	sbJSON, err := plan.SingBoxConfig(sbConfig)
	if err != nil {
		return fmt.Errorf("runtime: sing-box config: %w", err)
	}
	xrayJSON, err := plan.XrayConfig(r.opts.Xray)
	if err != nil {
		return fmt.Errorf("runtime: xray config: %w", err)
	}

	sbPath := filepath.Join(r.opts.ConfigDir, "sing-box.json")
	xrayPath := filepath.Join(r.opts.ConfigDir, "xray.json")

	sbChanged, err := r.writeIfChanged(sbPath, sbJSON)
	if err != nil {
		return err
	}
	xrayChanged := false
	if xrayJSON != nil {
		if xrayChanged, err = r.writeIfChanged(xrayPath, xrayJSON); err != nil {
			return err
		}
	}

	// Xray comes up first: its bridge listeners must exist before the front core
	// is told to dial them.
	if plan.NeedsXray() {
		started, err := r.ensureXray(ctx, xrayPath, xrayChanged)
		if err != nil {
			return err
		}
		if started {
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(r.opts.BridgeSettleDelay):
			}
		}
	}

	if err := r.ensureSingBox(ctx, sbPath, sbChanged); err != nil {
		return err
	}

	// Only once the front core no longer references the bridges is it safe to
	// shut the backend down.
	if !plan.NeedsXray() && r.xray != nil {
		stopCtx, cancel := context.WithTimeout(ctx, r.opts.StopTimeout)
		defer cancel()
		if err := r.xray.Stop(stopCtx); err != nil {
			return fmt.Errorf("runtime: stopping xray: %w", err)
		}
		r.xray = nil
		delete(r.hashes, xrayPath)
		_ = os.Remove(xrayPath)
	}

	r.plan = plan
	return nil
}

// ensureXray starts the backend core, or restarts it when its config changed.
// It reports whether the process was (re)started.
func (r *Runtime) ensureXray(ctx context.Context, configPath string, changed bool) (bool, error) {
	if r.opts.XrayBinary == "" {
		return false, fmt.Errorf("runtime: this plan needs Xray but no xray binary is configured")
	}

	running := r.xray != nil && r.xray.Status().State != StateStopped
	if running && !changed {
		return false, nil
	}

	if r.xray != nil {
		stopCtx, cancel := context.WithTimeout(ctx, r.opts.StopTimeout)
		defer cancel()
		if err := r.xray.Stop(stopCtx); err != nil {
			return false, fmt.Errorf("runtime: restarting xray: %w", err)
		}
	}

	r.xray = NewSupervisor(Spec{
		Name:    "xray",
		Binary:  r.opts.XrayBinary,
		Args:    []string{"run", "-c", configPath},
		WorkDir: r.opts.ConfigDir,
		Env:     coreEnv(r.opts.ConfigDir),
	})
	if err := r.xray.Start(ctx); err != nil {
		return false, fmt.Errorf("runtime: starting xray: %w", err)
	}
	return true, nil
}

// ensureSingBox starts the front core, or restarts it when its config changed.
func (r *Runtime) ensureSingBox(ctx context.Context, configPath string, changed bool) error {
	if r.opts.SingBoxBinary == "" {
		return fmt.Errorf("runtime: no sing-box binary is configured")
	}

	running := r.singbox != nil && r.singbox.Status().State != StateStopped
	if running && !changed {
		return nil
	}

	if r.singbox != nil {
		stopCtx, cancel := context.WithTimeout(ctx, r.opts.StopTimeout)
		defer cancel()
		if err := r.singbox.Stop(stopCtx); err != nil {
			return fmt.Errorf("runtime: restarting sing-box: %w", err)
		}
	}

	r.singbox = NewSupervisor(Spec{
		Name:    "sing-box",
		Binary:  r.opts.SingBoxBinary,
		Args:    []string{"run", "-c", configPath, "-D", r.opts.ConfigDir},
		WorkDir: r.opts.ConfigDir,
		Env:     coreEnv(r.opts.ConfigDir),
	})
	return r.singbox.Start(ctx)
}

// Stop shuts both cores down.
//
// The front core goes first and is given its full budget: sing-box has real work
// to do on the way out — removing the tun interface and the policy routing it
// installed — and killing it partway through that leaves the LAN pointed at a
// routing table with no route in it. The backend is stopped in parallel, since
// nothing depends on the order between them once the front core is on its way
// down, and stopping them one after another is what made a shutdown overrun its
// deadline and get killed.
func (r *Runtime) Stop(ctx context.Context) error {
	r.mu.Lock()
	r.stopping = true
	sb, xr := r.singbox, r.xray
	r.singbox, r.xray = nil, nil
	r.mu.Unlock()

	var (
		wg       sync.WaitGroup
		mu       sync.Mutex
		firstErr error
	)
	for _, s := range []*Supervisor{sb, xr} {
		if s == nil {
			continue
		}
		wg.Add(1)
		go func(sup *Supervisor) {
			defer wg.Done()
			stopCtx, cancel := context.WithTimeout(ctx, r.opts.StopTimeout)
			defer cancel()
			if err := sup.Stop(stopCtx); err != nil {
				mu.Lock()
				if firstErr == nil {
					firstErr = err
				}
				mu.Unlock()
			}
		}(s)
	}
	wg.Wait()

	r.mu.Lock()
	r.stopping = false
	r.mu.Unlock()
	return firstErr
}

// Status returns a snapshot of every running core.
func (r *Runtime) Status() []Status {
	r.mu.Lock()
	defer r.mu.Unlock()

	var out []Status
	if r.singbox != nil {
		out = append(out, r.singbox.Status())
	}
	if r.xray != nil {
		out = append(out, r.xray.Status())
	}
	return out
}

// Logs returns recent output from one core, or from both when name is empty.
func (r *Runtime) Logs(name string, n int) []LogLine {
	r.mu.Lock()
	sb, xr := r.singbox, r.xray
	r.mu.Unlock()

	var out []LogLine
	if sb != nil && (name == "" || name == "sing-box") {
		out = append(out, sb.Logs(n)...)
	}
	if xr != nil && (name == "" || name == "xray") {
		out = append(out, xr.Logs(n)...)
	}
	return out
}

// XrayBinary returns the backend core's path, empty when none is configured.
func (r *Runtime) XrayBinary() string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.opts.XrayBinary
}

// SetXrayBinary supplies the backend core's path.
//
// Xray is resolved lazily rather than at startup: a subscription made entirely
// of protocols the front core handles never needs the binary, and on a router it
// is worth not downloading 15 MB to find that out.
func (r *Runtime) SetXrayBinary(path string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.opts.XrayBinary = path
}

// Configure updates the core paths and the front core's options before an Apply.
//
// The options matter as much as the routing does — the capture mode, the tun
// name, the resolvers all live here — and a runtime created once at connect time
// would otherwise go on rendering the settings it was born with, so that
// switching from TUN to TPROXY in the interface changed nothing at all.
//
// An empty singBox path leaves the existing one alone; an empty xray path clears
// it, which is how a subscription that no longer needs the backend core stops
// requiring the binary to be present.
func (r *Runtime) Configure(singBox, xray string, opts singbox.Options) {
	r.mu.Lock()
	defer r.mu.Unlock()

	if singBox != "" {
		r.opts.SingBoxBinary = singBox
	}
	r.opts.XrayBinary = xray
	r.opts.SingBox = opts
}

// Plan returns the plan currently in force.
func (r *Runtime) Plan() *Plan {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.plan
}

// writeIfChanged writes a config file only when its contents differ, and reports
// whether it did. The hash is kept in memory rather than re-read from disk so
// that a file edited by hand is treated as changed on the next apply.
func (r *Runtime) writeIfChanged(path string, data []byte) (bool, error) {
	sum := sha256.Sum256(data)
	digest := hex.EncodeToString(sum[:])

	if previous, ok := r.hashes[path]; ok && previous == digest {
		if _, err := os.Stat(path); err == nil {
			return false, nil
		}
	}

	// Written through a temporary file in the same directory: a core reloading
	// at the wrong moment must never see a half-written config.
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return false, fmt.Errorf("runtime: writing %s: %w", path, err)
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return false, fmt.Errorf("runtime: writing %s: %w", path, err)
	}

	r.hashes[path] = digest
	return true, nil
}

// coreEnv builds the environment the cores are launched with.
//
// It is deliberately minimal rather than inherited: the cores read a number of
// environment variables that change their behaviour (asset locations, log
// destinations), and a value leaking in from the shell that started Obelisk
// would make the router's behaviour depend on how it was booted.
func coreEnv(dir string) []string {
	return []string{
		"HOME=" + dir,
		"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
		// Both cores look here for geoip/geosite databases.
		"XRAY_LOCATION_ASSET=" + dir,
		"SING_BOX_LOCATION_ASSET=" + dir,
	}
}
