package core

import (
	"context"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"
)

// The tests below need a child process that behaves like a core: one that
// rejects its configuration and dies, and one that keeps running. Re-executing
// the test binary is the portable way to get both — a shell script would only
// work on the platforms that have a shell.
const (
	envFakeCore = "OBELISK_TEST_FAKE_CORE"
	fakeReject  = "reject"
	fakeRun     = "run"
)

func TestMain(m *testing.M) {
	switch os.Getenv(envFakeCore) {
	case fakeReject:
		fmt.Fprintln(os.Stderr, "\x1b[31mERROR\x1b[0m missing `route.default_domain_resolver` in dial fields")
		fmt.Fprintln(os.Stderr, "\x1b[31mFATAL\x1b[0m to continue using this feature, set the environment variable")
		os.Exit(1)
	case fakeRun:
		time.Sleep(30 * time.Second)
		os.Exit(0)
	}
	os.Exit(m.Run())
}

func fakeCoreSpec(t *testing.T, behaviour string) Spec {
	t.Helper()
	return Spec{
		Name:      "fake",
		Binary:    os.Args[0],
		Args:      []string{"-test.run=TestNothingMatchesThisName"},
		Env:       append(os.Environ(), envFakeCore+"="+behaviour),
		SettleFor: 400 * time.Millisecond,
	}
}

// A core that rejects its configuration exits at once. Reporting that as a
// successful start is how a configuration error turns into a mystery somewhere
// else entirely — found on a real router, where sing-box refused its config and
// the only visible symptom was a control port refusing connections.
func TestStartFailsWhenTheProcessExitsImmediately(t *testing.T) {
	s := NewSupervisor(fakeCoreSpec(t, fakeReject))

	err := s.Start(context.Background())
	if err == nil {
		t.Fatal("Start reported success for a process that died on startup")
	}

	// An exit status says nothing — every misconfiguration is "exit status 1".
	// What the core printed on its way out is the part a person can act on.
	if !strings.Contains(err.Error(), "default_domain_resolver") {
		t.Errorf("the error does not carry the core's own words: %v", err)
	}
	// And the colour codes the cores wrap their log levels in must not travel
	// into a JSON error string.
	if strings.Contains(err.Error(), "\x1b[") {
		t.Errorf("ANSI escapes leaked into the error: %q", err.Error())
	}

	if st := s.Status(); st.State != StateFailed {
		t.Errorf("State = %q, want failed", st.State)
	}
	_ = s.Stop(context.Background())
}

func TestStartSucceedsForAProcessThatKeepsRunning(t *testing.T) {
	s := NewSupervisor(fakeCoreSpec(t, fakeRun))

	if err := s.Start(context.Background()); err != nil {
		t.Fatalf("Start: %v", err)
	}
	if st := s.Status(); st.State != StateRunning {
		t.Errorf("State = %q, want running", st.State)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := s.Stop(ctx); err != nil {
		t.Errorf("Stop: %v", err)
	}
}

func TestStripANSI(t *testing.T) {
	in := "\x1b[31mFATAL\x1b[0m something went wrong"
	if got := stripANSI(in); got != "FATAL something went wrong" {
		t.Errorf("stripANSI = %q", got)
	}
}
