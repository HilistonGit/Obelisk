package app

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/obelisk-project/obelisk/internal/core/singbox"
	"github.com/obelisk-project/obelisk/internal/probe"
)

func newTestApp(t *testing.T) *App {
	t.Helper()
	dir := t.TempDir()
	a, err := New(Options{
		ConfigPath: filepath.Join(dir, "config.json"),
		ConfigDir:  dir,
		CoreDir:    filepath.Join(dir, "cores"),
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return a
}

// within runs fn and fails the test if it has not returned in time, which is how
// a deadlock reports itself rather than hanging the whole run.
func within(t *testing.T, limit time.Duration, what string, fn func()) {
	t.Helper()
	done := make(chan struct{})
	go func() {
		defer close(done)
		fn()
	}()
	select {
	case <-done:
	case <-time.After(limit):
		t.Fatalf("%s did not finish in %v — the state lock is held across it", what, limit)
	}
}

// The sampling goroutine calls back into App once a second. If that callback
// reaches for the state lock, then stopping the sampler from a path that holds
// the state lock waits forever for a goroutine that is waiting for the lock —
// and connecting a second time wedges the daemon so that every status request,
// every rule listing and the whole interface stop answering.
//
// Holding the lock here is exactly the situation a connect creates.
func TestRecordingASampleDoesNotNeedTheStateLock(t *testing.T) {
	a := newTestApp(t)

	a.mu.Lock()
	defer a.mu.Unlock()

	within(t, 2*time.Second, "recordSample", func() {
		a.recordSample(probe.Sample{At: time.Now(), Up: 1, Down: 2})
	})
	within(t, 2*time.Second, "recordLatency", func() {
		a.recordLatency("node-1", probe.Latency{Delay: 42, At: time.Now()})
	})
}

// Stopping the monitor waits for the sampler to come to a halt, so it must not
// be holding the lock the sampler might need.
func TestStopMonitorDoesNotHoldTheStateLock(t *testing.T) {
	a := newTestApp(t)

	// A monitor pointed at a port nothing answers on still starts the goroutine,
	// which is all this needs: the point is where the locks are taken, not what
	// gets measured.
	opts := singbox.DefaultOptions()
	opts.ClashAPIListen = "127.0.0.1:1"
	a.startMonitor(context.Background(), opts)

	within(t, 5*time.Second, "stopMonitor", func() { a.stopMonitor() })

	// And the state is readable throughout, which is the property that matters
	// to anyone looking at the interface while this happens.
	within(t, 2*time.Second, "Status", func() { _ = a.Status() })
}

// Reload is a no-op when nothing is running, and must say so immediately rather
// than queueing behind the apply lock or touching the cores.
func TestReloadIsFreeWhenDisconnected(t *testing.T) {
	a := newTestApp(t)
	within(t, 2*time.Second, "Reload", func() {
		if err := a.Reload(context.Background()); err != nil {
			t.Errorf("Reload while disconnected: %v", err)
		}
	})
}

// Adding a rule while disconnected must not block on anything: the edit is
// saved, there is no tunnel to bring in line, and the caller is an HTTP handler.
func TestAddingARuleReturnsPromptlyWhenDisconnected(t *testing.T) {
	a := newTestApp(t)
	within(t, 5*time.Second, "AddRules", func() {
		added, errs, err := a.AddRules([]string{"example.com"}, "proxy", "", nil, "")
		if err != nil {
			t.Errorf("AddRules: %v", err)
		}
		if len(errs) != 0 || len(added) != 1 {
			t.Errorf("added %d rules, %d errors", len(added), len(errs))
		}
	})
}
