// Package core supervises the Xray and sing-box processes and decides which of
// them carries each node. Obelisk drives both cores as ordinary child processes
// with generated configuration files; neither core is patched or linked in.
package core

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"os/exec"
	"strings"
	"sync"
	"time"
)

// State is the lifecycle position of a supervised process.
type State string

const (
	StateStopped  State = "stopped"
	StateStarting State = "starting"
	StateRunning  State = "running"
	StateBackoff  State = "backoff"
	StateFailed   State = "failed"
)

// Spec describes how to launch one core.
type Spec struct {
	// Name identifies the process in logs and in the API, e.g. "sing-box".
	Name string

	// Binary is the executable path, and Args the arguments after it.
	Binary string
	Args   []string

	WorkDir string
	Env     []string

	// StableAfter is how long a process must stay up before its restart budget
	// is considered spent rather than accumulating. Without it, a core that
	// crashes once an hour would eventually be treated as hopeless.
	StableAfter time.Duration

	// SettleFor is how long Start waits to see whether a freshly launched
	// process survives before reporting success.
	//
	// Without it, "the process started" means only that fork and exec worked. A
	// core that reads its configuration, rejects it and exits a millisecond
	// later looks like a perfectly successful start, and the failure only
	// surfaces later as something unrelated — a control port that will not
	// accept connections, say — with the actual reason nowhere in sight.
	SettleFor time.Duration

	// MaxBackoff caps the wait between restart attempts.
	MaxBackoff time.Duration

	// LogLines is the size of the retained log ring.
	LogLines int
}

func (s *Spec) applyDefaults() {
	if s.StableAfter == 0 {
		s.StableAfter = 60 * time.Second
	}
	if s.MaxBackoff == 0 {
		s.MaxBackoff = 30 * time.Second
	}
	if s.SettleFor == 0 {
		s.SettleFor = 750 * time.Millisecond
	}
	if s.LogLines == 0 {
		s.LogLines = 500
	}
}

// LogLine is one line of a core's output.
type LogLine struct {
	Core   string    `json:"core"`
	Time   time.Time `json:"time"`
	Stream string    `json:"stream"` // stdout or stderr
	Text   string    `json:"text"`
}

// Status is a snapshot of a supervised process.
type Status struct {
	Name      string    `json:"name"`
	State     State     `json:"state"`
	PID       int       `json:"pid,omitempty"`
	StartedAt time.Time `json:"started_at,omitempty"`
	Restarts  int       `json:"restarts"`
	LastError string    `json:"last_error,omitempty"`
}

// Supervisor runs one core, restarts it when it dies unexpectedly, and keeps its
// recent output available for the UI.
//
// The restart loop is deliberately not unbounded-fast: a core that fails
// immediately on a bad configuration would otherwise be relaunched thousands of
// times a second and bury the actual error in its own log spam. Backoff doubles
// up to MaxBackoff, and resets only once the process has stayed up long enough
// to prove the configuration is workable.
type Supervisor struct {
	spec Spec

	mu        sync.RWMutex
	state     State
	pid       int
	startedAt time.Time
	restarts  int
	lastErr   error

	cmd    *exec.Cmd
	cancel context.CancelFunc
	exited chan struct{} // closed when the supervise loop returns

	logs *logRing
}

// NewSupervisor creates a supervisor for the given spec. It does not start
// anything until Start is called.
func NewSupervisor(spec Spec) *Supervisor {
	spec.applyDefaults()
	return &Supervisor{
		spec:  spec,
		state: StateStopped,
		logs:  newLogRing(spec.LogLines),
	}
}

// Name returns the supervised core's name.
func (s *Supervisor) Name() string { return s.spec.Name }

// Start launches the process and begins supervising it. It returns once the
// process has been spawned; readiness is reported through Status.
func (s *Supervisor) Start(ctx context.Context) error {
	s.mu.Lock()
	if s.state != StateStopped && s.state != StateFailed {
		s.mu.Unlock()
		return fmt.Errorf("%s: already %s", s.spec.Name, s.state)
	}
	runCtx, cancel := context.WithCancel(context.WithoutCancel(ctx))
	s.cancel = cancel
	s.state = StateStarting
	s.restarts = 0
	s.exited = make(chan struct{})
	exited := s.exited
	s.mu.Unlock()

	started := make(chan error, 1)
	go s.supervise(runCtx, started, exited)

	select {
	case err := <-started:
		return err
	case <-ctx.Done():
		cancel()
		return ctx.Err()
	}
}

// supervise is the restart loop. It owns every state transition after Start.
func (s *Supervisor) supervise(ctx context.Context, firstStart chan<- error, exited chan struct{}) {
	defer close(exited)

	backoff := time.Second
	first := true

	for {
		if ctx.Err() != nil {
			s.setState(StateStopped, nil)
			return
		}

		startedAt := time.Now()
		err := s.runOnce(ctx, first, firstStart)
		first = false

		if ctx.Err() != nil {
			// A stop was requested; the exit is expected, not a failure.
			s.setState(StateStopped, nil)
			return
		}

		// A core that never got off the ground is a different situation from one
		// that ran and later died. The configuration will not become valid on a
		// second attempt, the caller has already been handed the reason, and
		// retrying would only bury it under restart noise.
		var startup *startupError
		if errors.As(err, &startup) {
			s.setState(StateFailed, startup.err)
			return
		}

		s.mu.Lock()
		s.restarts++
		s.lastErr = err
		if time.Since(startedAt) >= s.spec.StableAfter {
			backoff = time.Second
		}
		s.state = StateBackoff
		wait := backoff
		s.mu.Unlock()

		s.logs.append(LogLine{
			Core:   s.spec.Name,
			Time:   time.Now(),
			Stream: "supervisor",
			Text:   fmt.Sprintf("process exited (%v); restarting in %s", err, wait),
		})

		select {
		case <-ctx.Done():
			s.setState(StateStopped, nil)
			return
		case <-time.After(wait):
		}

		if backoff *= 2; backoff > s.spec.MaxBackoff {
			backoff = s.spec.MaxBackoff
		}
	}
}

// runOnce launches the process and blocks until it exits.
func (s *Supervisor) runOnce(ctx context.Context, first bool, firstStart chan<- error) error {
	cmd := exec.CommandContext(ctx, s.spec.Binary, s.spec.Args...)
	cmd.Dir = s.spec.WorkDir
	cmd.Env = s.spec.Env

	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return s.reportStartFailure(first, firstStart, err)
	}
	stderr, err := cmd.StderrPipe()
	if err != nil {
		return s.reportStartFailure(first, firstStart, err)
	}

	if err := cmd.Start(); err != nil {
		return s.reportStartFailure(first, firstStart, fmt.Errorf("%s: %w", s.spec.Binary, err))
	}

	s.mu.Lock()
	s.cmd = cmd
	s.pid = cmd.Process.Pid
	s.startedAt = time.Now()
	s.state = StateRunning
	s.mu.Unlock()

	var wg sync.WaitGroup
	wg.Add(2)
	go func() { defer wg.Done(); s.pump("stdout", stdout) }()
	go func() { defer wg.Done(); s.pump("stderr", stderr) }()

	// Give the process a moment to prove it can survive its own configuration
	// before calling the launch a success. A core that rejects its config exits
	// almost immediately, and reporting that as "started" is how a config error
	// turns into a mystery somewhere downstream.
	if first {
		exited := make(chan error, 1)
		go func() { wg.Wait(); exited <- cmd.Wait() }()

		select {
		case err := <-exited:
			reason := s.startupFailure(err)
			s.setState(StateFailed, reason)
			firstStart <- reason
			return &startupError{err: reason}
		case <-time.After(s.spec.SettleFor):
			firstStart <- nil
			return <-exited
		}
	}

	wg.Wait()
	return cmd.Wait()
}

// startupError marks a launch that never survived its own configuration, as
// opposed to a process that ran for a while and then died.
type startupError struct{ err error }

func (e *startupError) Error() string { return e.err.Error() }
func (e *startupError) Unwrap() error { return e.err }

// startupFailure turns an immediate exit into an error a person can act on.
//
// The exit status alone says nothing — every misconfiguration is "exit status
// 1". What matters is what the core printed on its way out, so that is what
// gets reported.
func (s *Supervisor) startupFailure(err error) error {
	var reasons []string
	for _, line := range s.logs.tail(12) {
		text := strings.TrimSpace(stripANSI(line.Text))
		if text == "" || line.Stream == "supervisor" {
			continue
		}
		reasons = append(reasons, text)
	}

	if len(reasons) == 0 {
		return fmt.Errorf("%s exited immediately (%v) without saying why", s.spec.Name, err)
	}
	// The last lines are the ones that killed it; earlier output is context.
	if len(reasons) > 4 {
		reasons = reasons[len(reasons)-4:]
	}
	return fmt.Errorf("%s rejected its configuration: %s", s.spec.Name, strings.Join(reasons, " | "))
}

// stripANSI removes the colour codes the cores wrap their log levels in, which
// are noise in a browser and in a JSON error string.
func stripANSI(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] == 0x1b {
			for i < len(s) && s[i] != 'm' {
				i++
			}
			continue
		}
		b.WriteByte(s[i])
	}
	return b.String()
}

// reportStartFailure records a launch that never produced a process.
func (s *Supervisor) reportStartFailure(first bool, firstStart chan<- error, err error) error {
	s.setState(StateFailed, err)
	if first {
		firstStart <- err
	}
	return err
}

// pump copies one output stream into the log ring line by line.
func (s *Supervisor) pump(stream string, r io.Reader) {
	scanner := bufio.NewScanner(r)
	// Core logs are ordinary lines, but a stack trace on a panic is not; a
	// generous limit keeps one long line from truncating the diagnosis.
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)

	for scanner.Scan() {
		s.logs.append(LogLine{
			Core:   s.spec.Name,
			Time:   time.Now(),
			Stream: stream,
			Text:   scanner.Text(),
		})
	}
}

// Stop terminates the process and stops supervising it.
func (s *Supervisor) Stop(ctx context.Context) error {
	s.mu.Lock()
	cancel := s.cancel
	exited := s.exited
	s.cancel = nil
	s.mu.Unlock()

	if cancel == nil {
		return nil
	}
	cancel()

	if exited == nil {
		return nil
	}
	select {
	case <-exited:
		return nil
	case <-ctx.Done():
		return fmt.Errorf("%s: did not stop in time: %w", s.spec.Name, ctx.Err())
	}
}

// Status returns a snapshot of the process.
func (s *Supervisor) Status() Status {
	s.mu.RLock()
	defer s.mu.RUnlock()

	st := Status{
		Name:      s.spec.Name,
		State:     s.state,
		PID:       s.pid,
		StartedAt: s.startedAt,
		Restarts:  s.restarts,
	}
	if s.lastErr != nil {
		st.LastError = s.lastErr.Error()
	}
	return st
}

// Logs returns up to n most recent log lines, newest last.
func (s *Supervisor) Logs(n int) []LogLine { return s.logs.tail(n) }

// Subscribe returns a channel of new log lines and a function to unsubscribe.
// Slow consumers drop lines rather than stalling the core's output pipe.
func (s *Supervisor) Subscribe() (<-chan LogLine, func()) { return s.logs.subscribe() }

// setState records a lifecycle transition.
func (s *Supervisor) setState(state State, err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.state = state
	if err != nil {
		s.lastErr = err
	}
	if state == StateStopped || state == StateFailed {
		s.pid = 0
	}
}
