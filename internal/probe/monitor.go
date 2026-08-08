package probe

import (
	"context"
	"sync"
	"time"
)

// Sample is one second of throughput.
type Sample struct {
	At   time.Time `json:"at"`
	Up   int64     `json:"up"`   // bytes per second
	Down int64     `json:"down"` // bytes per second

	// Tunnel and Direct split the same second by where the bytes went. They sum
	// to roughly Up+Down: roughly, because the totals come from the core's own
	// counters while the split is reconstructed from the connections that were
	// alive for both samples, and a connection that opened and closed in between
	// is counted by the first and missed by the second.
	Tunnel int64 `json:"tunnel"`
	Direct int64 `json:"direct"`
}

// Traffic is what the interface draws.
type Traffic struct {
	Up            int64    `json:"up"`             // current bytes per second
	Down          int64    `json:"down"`           // current bytes per second
	UploadTotal   int64    `json:"upload_total"`   // bytes this session
	DownloadTotal int64    `json:"download_total"` // bytes this session
	Connections   int      `json:"connections"`
	History       []Sample `json:"history"`
	Available     bool     `json:"available"`
	Error         string   `json:"error,omitempty"`
}

// historySize is how many seconds of throughput are retained. Two minutes is
// enough for a graph that shows a burst without holding a meaningful amount of
// a router's memory.
const historySize = 120

// Monitor samples the counters and remembers recent latency measurements.
type Monitor struct {
	mu      sync.RWMutex
	client  *Client
	history []Sample
	last    *Snapshot
	latency map[string]Latency
	lastErr string

	// flows is the previous sample's per-connection counters, keyed by the
	// identifier the core assigns.
	flows map[string]Flow

	// OnSample is called after every reading, outside the lock, so that a slow
	// consumer — writing to disk, say — cannot stall the sampler or deadlock
	// against a reader asking for the current traffic.
	OnSample func(Sample)

	// OnLatency is called after every measurement, on the same terms.
	OnLatency func(node string, result Latency)

	cancel context.CancelFunc
	done   chan struct{}
}

// Latency is the most recent measurement for one node.
type Latency struct {
	Delay int       `json:"delay"` // milliseconds; zero means unreachable
	At    time.Time `json:"at"`
	Error string    `json:"error,omitempty"`
}

// NewMonitor creates a monitor for a controller.
func NewMonitor(client *Client) *Monitor {
	return &Monitor{
		client:  client,
		latency: map[string]Latency{},
	}
}

// Start begins sampling once a second until the context is cancelled.
func (m *Monitor) Start(ctx context.Context) {
	m.Stop()

	runCtx, cancel := context.WithCancel(context.WithoutCancel(ctx))
	done := make(chan struct{})

	m.mu.Lock()
	m.cancel = cancel
	m.done = done
	m.mu.Unlock()

	go func() {
		defer close(done)
		ticker := time.NewTicker(time.Second)
		defer ticker.Stop()

		for {
			select {
			case <-runCtx.Done():
				return
			case <-ticker.C:
				m.sample(runCtx)
			}
		}
	}()
}

// Stop ends sampling.
func (m *Monitor) Stop() {
	m.mu.Lock()
	cancel, done := m.cancel, m.done
	m.cancel, m.done = nil, nil
	m.mu.Unlock()

	if cancel == nil {
		return
	}
	cancel()
	<-done
}

// sample takes one reading and turns the counter difference into a rate.
func (m *Monitor) sample(ctx context.Context) {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	snapshot, err := m.client.Connections(ctx)

	taken, ok := m.record(snapshot, err)
	if ok && m.OnSample != nil {
		m.OnSample(taken)
	}
}

// record folds a reading into the history and reports the sample it produced.
func (m *Monitor) record(snapshot *Snapshot, err error) (Sample, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if err != nil {
		m.lastErr = err.Error()
		return Sample{}, false
	}
	m.lastErr = ""

	var (
		produced Sample
		haveOne  bool
	)
	if m.last != nil {
		elapsed := snapshot.Taken.Sub(m.last.Taken).Seconds()
		if elapsed > 0 {
			up := int64(float64(snapshot.UploadTotal-m.last.UploadTotal) / elapsed)
			down := int64(float64(snapshot.DownloadTotal-m.last.DownloadTotal) / elapsed)
			// A restarted core resets its counters, which would otherwise show
			// up as a large negative rate.
			if up < 0 {
				up = 0
			}
			if down < 0 {
				down = 0
			}
			tunnel, direct := m.splitRates(snapshot, elapsed)
			produced = Sample{At: snapshot.Taken, Up: up, Down: down, Tunnel: tunnel, Direct: direct}
			haveOne = true

			m.history = append(m.history, produced)
			if len(m.history) > historySize {
				m.history = m.history[len(m.history)-historySize:]
			}
		}
	}
	m.last = snapshot
	m.rememberFlows(snapshot)
	return produced, haveOne
}

// splitRates works out how much of the last interval went through the tunnel
// and how much went round it.
//
// Each connection is followed by identifier and only its own increase counted.
// Summing the live connections outright would fall as they close, and a falling
// total differenced against the previous one reads as negative traffic; this way
// a connection that ends simply stops contributing.
func (m *Monitor) splitRates(snapshot *Snapshot, elapsed float64) (tunnel, direct int64) {
	if elapsed <= 0 || m.flows == nil {
		return 0, 0
	}
	var tunnelBytes, directBytes int64
	for _, f := range snapshot.Flows {
		// A connection seen for the first time opened during this interval, so
		// everything it has carried belongs to it. Skipping new connections
		// instead was measurably wrong: a short transfer that begins and ends
		// between two samples would be missed entirely, and the bands would sit
		// far below the total line drawn over them. The first sample of all is
		// handled by the nil check above, where there is no previous map and no
		// interval to attribute anything to.
		previous := m.flows[f.ID]
		delta := (f.Up - previous.Up) + (f.Down - previous.Down)
		if delta <= 0 {
			continue
		}
		if f.Proxied {
			tunnelBytes += delta
		} else {
			directBytes += delta
		}
	}
	return int64(float64(tunnelBytes) / elapsed), int64(float64(directBytes) / elapsed)
}

// rememberFlows keeps the per-connection counters the next sample differences
// against. The map is rebuilt rather than updated so that closed connections
// fall out of it instead of accumulating for the life of the process.
func (m *Monitor) rememberFlows(snapshot *Snapshot) {
	flows := make(map[string]Flow, len(snapshot.Flows))
	for _, f := range snapshot.Flows {
		flows[f.ID] = f
	}
	m.flows = flows
}

// Traffic returns the current throughput and recent history.
func (m *Monitor) Traffic() Traffic {
	m.mu.RLock()
	defer m.mu.RUnlock()

	out := Traffic{
		History:   append([]Sample(nil), m.history...),
		Available: m.last != nil && m.lastErr == "",
		Error:     m.lastErr,
	}
	if m.last != nil {
		out.UploadTotal = m.last.UploadTotal
		out.DownloadTotal = m.last.DownloadTotal
		out.Connections = m.last.Connections
	}
	if n := len(m.history); n > 0 {
		out.Up = m.history[n-1].Up
		out.Down = m.history[n-1].Down
	}
	return out
}

// TestNode measures one node and records the result.
func (m *Monitor) TestNode(ctx context.Context, name, testURL string, timeout time.Duration) Latency {
	delay, err := m.client.Delay(ctx, name, testURL, timeout)

	result := Latency{Delay: delay, At: time.Now()}
	if err != nil {
		result.Delay = 0
		result.Error = err.Error()
	}

	m.mu.Lock()
	m.latency[name] = result
	m.mu.Unlock()

	if m.OnLatency != nil {
		m.OnLatency(name, result)
	}
	return result
}

// TestAll measures every named node, a few at a time.
//
// The concurrency cap is not politeness, it is survival: a hundred simultaneous
// TLS handshakes on a router with a small CPU will starve the traffic actually
// passing through it, and the measurements come back distorted by the load the
// measuring caused.
func (m *Monitor) TestAll(ctx context.Context, names []string, testURL string, timeout time.Duration) map[string]Latency {
	const parallel = 8

	var (
		wg      sync.WaitGroup
		limiter = make(chan struct{}, parallel)
		mu      sync.Mutex
		results = make(map[string]Latency, len(names))
	)

	for _, name := range names {
		select {
		case <-ctx.Done():
			return results
		default:
		}

		wg.Add(1)
		go func(node string) {
			defer wg.Done()
			limiter <- struct{}{}
			defer func() { <-limiter }()

			result := m.TestNode(ctx, node, testURL, timeout)
			mu.Lock()
			results[node] = result
			mu.Unlock()
		}(name)
	}

	wg.Wait()
	return results
}

// Latencies returns every measurement taken so far.
func (m *Monitor) Latencies() map[string]Latency {
	m.mu.RLock()
	defer m.mu.RUnlock()

	out := make(map[string]Latency, len(m.latency))
	for k, v := range m.latency {
		out[k] = v
	}
	return out
}

// Reset clears the counters and history, for when the cores restart underneath.
func (m *Monitor) Reset() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.history = nil
	m.last = nil
	m.lastErr = ""
}
