//go:build nosqlite

// This build of the history store does nothing.
//
// It exists because the pure-Go SQLite implementation does not support 32-bit
// ARM or MIPS, and those are exactly the architectures a great many routers run.
// Losing them would break the property the whole project rests on: one source
// tree producing a working binary for every OpenWrt target.
//
// So history becomes the optional part rather than the architecture. Built with
// -tags nosqlite, Obelisk does everything else — subscriptions, routing, both
// cores, the firewall, live traffic and latency — and only the long-term graphs
// are missing. Every caller already treats an unavailable history as normal,
// because opening it can fail for ordinary reasons like a read-only filesystem.
package store

import (
	"context"
	"fmt"
	"time"
)

// Span is the resolution of a stored traffic bucket.
type Span int

const (
	SpanMinute Span = 60
	SpanHour   Span = 3600
	SpanDay    Span = 86400
)

// Retention says how long each resolution is kept.
type Retention struct {
	Minutes time.Duration
	Hours   time.Duration
	Days    time.Duration
	Latency time.Duration
}

// DefaultRetention returns the retention policy this build would apply.
func DefaultRetention() Retention {
	return Retention{
		Minutes: 24 * time.Hour,
		Hours:   30 * 24 * time.Hour,
		Days:    365 * 24 * time.Hour,
		Latency: 7 * 24 * time.Hour,
	}
}

// TrafficPoint is one bucket of the series.
type TrafficPoint struct {
	At   time.Time `json:"at"`
	Up   int64     `json:"up"`
	Down int64     `json:"down"`
}

// LatencyPoint is one measurement.
type LatencyPoint struct {
	At    time.Time `json:"at"`
	Delay int       `json:"delay"`
}

// NodeStat summarizes one node's measured behaviour.
type NodeStat struct {
	Node     string  `json:"node"`
	Samples  int     `json:"samples"`
	Average  int     `json:"average"`
	Best     int     `json:"best"`
	Failures int     `json:"failures"`
	Loss     float64 `json:"loss"`
}

// Store is the history database, absent in this build.
type Store struct{}

// Available reports whether this build can store history.
func Available() bool { return false }

// Open reports that history is not part of this build.
//
// Returning an error rather than a silent no-op Store is deliberate: the caller
// logs it once at startup, so an operator learns why the graphs are empty
// instead of assuming something is broken.
func Open(path string) (*Store, error) {
	return nil, fmt.Errorf(
		"store: this build has no history support (SQLite is unavailable on 32-bit ARM and MIPS); everything else works")
}

// Close does nothing.
func (s *Store) Close() error { return nil }

// RecordTraffic does nothing.
func (s *Store) RecordTraffic(ctx context.Context, at time.Time, up, down int64) error { return nil }

// TrafficSeries returns no points.
func (s *Store) TrafficSeries(ctx context.Context, span Span, since, until time.Time) ([]TrafficPoint, error) {
	return nil, nil
}

// TrafficTotal returns zero.
func (s *Store) TrafficTotal(ctx context.Context, since time.Time) (int64, int64, error) {
	return 0, 0, nil
}

// RecordLatency does nothing.
func (s *Store) RecordLatency(ctx context.Context, node string, delay int, at time.Time) error {
	return nil
}

// LatencyHistory returns no points.
func (s *Store) LatencyHistory(ctx context.Context, node string, since time.Time, limit int) ([]LatencyPoint, error) {
	return nil, nil
}

// NodeStats returns nothing.
func (s *Store) NodeStats(ctx context.Context, since time.Time) (map[string]NodeStat, error) {
	return map[string]NodeStat{}, nil
}

// Prune does nothing.
func (s *Store) Prune(ctx context.Context, r Retention, now time.Time) error { return nil }

// Size reports nothing stored.
func (s *Store) Size(ctx context.Context) (int64, error) { return 0, nil }
