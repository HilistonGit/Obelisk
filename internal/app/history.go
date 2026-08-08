package app

import (
	"context"
	"fmt"
	"log"
	"path/filepath"
	"time"

	"github.com/obelisk-project/obelisk/internal/probe"
	"github.com/obelisk-project/obelisk/internal/store"
)

// historyDB returns the open database, or nil when there is none.
//
// It deliberately does not touch the state lock. This is called once a second
// from the sampling goroutine, and that goroutine is stopped from paths that
// hold the state lock — reaching for it here would make stopping the sampler
// wait for a lock that only the stopper can release.
func (a *App) historyDB() *store.Store {
	a.histMu.RLock()
	defer a.histMu.RUnlock()
	return a.history
}

// OpenHistory opens the history database and starts the retention loop.
func (a *App) OpenHistory(ctx context.Context) { a.openHistory(ctx) }

// CloseHistory releases the history database.
func (a *App) CloseHistory() { a.closeHistory() }

// openHistory opens the history database and starts the retention loop.
//
// A failure here is reported but not fatal: history is a convenience, and a
// router that cannot write it should still route traffic. Refusing to start
// because a graph is unavailable would be the wrong priority entirely.
func (a *App) openHistory(ctx context.Context) {
	path := filepath.Join(a.opts.ConfigDir, "history.db")

	db, err := store.Open(path)
	if err != nil {
		log.Printf("history unavailable, continuing without it: %v", err)
		return
	}

	a.histMu.Lock()
	a.history = db
	a.histMu.Unlock()

	go a.pruneLoop(ctx)
}

// closeHistory releases the database.
func (a *App) closeHistory() {
	a.histMu.Lock()
	db := a.history
	a.history = nil
	a.histMu.Unlock()

	if db != nil {
		_ = db.Close()
	}
}

// pruneLoop trims the history on a timer. Unbounded growth on a router is not
// theoretical: flash fills, and the first casualty is the configuration write
// that would let a user fix it.
func (a *App) pruneLoop(ctx context.Context) {
	ticker := time.NewTicker(6 * time.Hour)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			db := a.historyDB()

			if db == nil {
				return
			}
			if err := db.Prune(ctx, store.DefaultRetention(), time.Now()); err != nil {
				log.Printf("pruning history: %v", err)
			}
		}
	}
}

// recordSample writes one traffic reading to the history.
func (a *App) recordSample(s probe.Sample) {
	db := a.historyDB()

	if db == nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := db.RecordTraffic(ctx, s.At, s.Up, s.Down); err != nil {
		log.Printf("recording traffic: %v", err)
	}
}

// recordLatency writes one measurement to the history.
func (a *App) recordLatency(node string, result probe.Latency) {
	db := a.historyDB()

	if db == nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := db.RecordLatency(ctx, node, result.Delay, result.At); err != nil {
		log.Printf("recording latency: %v", err)
	}
}

// History is what the interface draws for a period longer than live traffic.
type History struct {
	Span      string               `json:"span"`
	Points    []store.TrafficPoint `json:"points"`
	UpTotal   int64                `json:"up_total"`
	DownTotal int64                `json:"down_total"`
	Available bool                 `json:"available"`
	SizeBytes int64                `json:"size_bytes,omitempty"`
}

// spans maps a period name onto the resolution and window that suit it.
//
// Asking for a day at per-minute resolution would return 1 440 points to draw
// on a graph a few hundred pixels wide, so each period gets the coarsest
// resolution that still fills it.
var spans = map[string]struct {
	span   store.Span
	window time.Duration
}{
	"hour":  {store.SpanMinute, time.Hour},
	"day":   {store.SpanHour, 24 * time.Hour},
	"month": {store.SpanDay, 30 * 24 * time.Hour},
}

// History returns traffic over one of the named periods.
func (a *App) History(ctx context.Context, period string) (*History, error) {
	db := a.historyDB()

	if db == nil {
		return &History{Span: period, Available: false, Points: []store.TrafficPoint{}}, nil
	}

	choice, ok := spans[period]
	if !ok {
		return nil, fmt.Errorf("unknown period %q (expected hour, day or month)", period)
	}

	until := time.Now()
	since := until.Add(-choice.window)

	points, err := db.TrafficSeries(ctx, choice.span, since, until.Add(time.Duration(choice.span)*time.Second))
	if err != nil {
		return nil, err
	}
	if points == nil {
		points = []store.TrafficPoint{}
	}

	out := &History{Span: period, Points: points, Available: true}
	for _, p := range points {
		out.UpTotal += p.Up
		out.DownTotal += p.Down
	}
	if size, err := db.Size(ctx); err == nil {
		out.SizeBytes = size
	}
	return out, nil
}

// NodeStats summarizes how each node has behaved over the last day.
func (a *App) NodeStats(ctx context.Context) (map[string]store.NodeStat, error) {
	db := a.historyDB()

	if db == nil {
		return map[string]store.NodeStat{}, nil
	}
	return db.NodeStats(ctx, time.Now().Add(-24*time.Hour))
}
