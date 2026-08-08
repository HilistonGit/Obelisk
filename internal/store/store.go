//go:build !nosqlite

// Package store keeps the history that does not fit in memory: traffic over
// time and per-node latency.
//
// It is SQLite, through modernc.org/sqlite — a pure-Go implementation. That
// choice is not incidental. Every other SQLite binding needs cgo, and cgo would
// end cross-compilation: the single static binary that goes to amd64, arm64 and
// mipsle alike is the property the whole project is built on, and no storage
// engine is worth trading it for.
//
// Configuration stays in JSON. This is for the append-heavy series nobody edits
// by hand, which is what a database is actually good at.
package store

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	_ "modernc.org/sqlite"
)

// Span is the resolution of a stored traffic bucket.
//
// Samples are rolled up rather than kept per second forever. A router has a
// finite and often small amount of flash, and a year of per-second traffic is
// thirty million rows nobody will ever look at at that resolution.
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

// DefaultRetention keeps roughly a day of fine detail, a month of hourly totals
// and a year of daily ones. That is about 2 500 rows — kilobytes, not megabytes.
func DefaultRetention() Retention {
	return Retention{
		Minutes: 24 * time.Hour,
		Hours:   30 * 24 * time.Hour,
		Days:    365 * 24 * time.Hour,
		Latency: 7 * 24 * time.Hour,
	}
}

// Store is the history database.
type Store struct {
	db *sql.DB
}

// Open creates or opens the database and applies the schema.
func Open(path string) (*Store, error) {
	// WAL keeps a reader from blocking the writer, which matters because the
	// interface polls while the sampler writes. busy_timeout turns the rare
	// collision into a short wait instead of an error.
	dsn := path + "?_pragma=journal_mode(WAL)&_pragma=busy_timeout(5000)&_pragma=synchronous(NORMAL)"

	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("store: %w", err)
	}
	// One writer avoids lock contention entirely; the workload is tiny and
	// serialising it costs nothing.
	db.SetMaxOpenConns(1)

	s := &Store{db: db}
	if err := s.migrate(context.Background()); err != nil {
		db.Close()
		return nil, err
	}
	return s, nil
}

// Close releases the database.
func (s *Store) Close() error {
	if s == nil || s.db == nil {
		return nil
	}
	return s.db.Close()
}

// migrate creates the schema. It is idempotent, so opening an existing database
// is the same code path as creating a new one.
func (s *Store) migrate(ctx context.Context) error {
	const schema = `
CREATE TABLE IF NOT EXISTS traffic (
    span   INTEGER NOT NULL,
    bucket INTEGER NOT NULL,
    up     INTEGER NOT NULL DEFAULT 0,
    down   INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (span, bucket)
) WITHOUT ROWID;

CREATE TABLE IF NOT EXISTS latency (
    node  TEXT    NOT NULL,
    at    INTEGER NOT NULL,
    delay INTEGER NOT NULL,
    PRIMARY KEY (node, at)
) WITHOUT ROWID;

CREATE INDEX IF NOT EXISTS latency_at ON latency (at);
`
	if _, err := s.db.ExecContext(ctx, schema); err != nil {
		return fmt.Errorf("store: applying schema: %w", err)
	}
	return nil
}

// ---------------------------------------------------------------- traffic

// RecordTraffic adds one interval's bytes to every resolution at once.
//
// Writing all three spans on the way in, rather than rolling up later, means
// there is no background job to schedule and no window where an hour is missing
// because the roll-up had not run yet.
func (s *Store) RecordTraffic(ctx context.Context, at time.Time, up, down int64) error {
	if up == 0 && down == 0 {
		return nil
	}

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("store: %w", err)
	}
	defer tx.Rollback()

	const upsert = `
INSERT INTO traffic (span, bucket, up, down) VALUES (?, ?, ?, ?)
ON CONFLICT (span, bucket) DO UPDATE SET up = up + excluded.up, down = down + excluded.down`

	unix := at.Unix()
	for _, span := range []Span{SpanMinute, SpanHour, SpanDay} {
		bucket := unix - unix%int64(span)
		if _, err := tx.ExecContext(ctx, upsert, int64(span), bucket, up, down); err != nil {
			return fmt.Errorf("store: recording traffic: %w", err)
		}
	}
	return tx.Commit()
}

// TrafficPoint is one bucket of the series.
type TrafficPoint struct {
	At   time.Time `json:"at"`
	Up   int64     `json:"up"`
	Down int64     `json:"down"`
}

// TrafficSeries returns the buckets of one resolution within a window.
func (s *Store) TrafficSeries(ctx context.Context, span Span, since, until time.Time) ([]TrafficPoint, error) {
	const query = `
SELECT bucket, up, down FROM traffic
WHERE span = ? AND bucket >= ? AND bucket < ?
ORDER BY bucket`

	rows, err := s.db.QueryContext(ctx, query, int64(span), since.Unix(), until.Unix())
	if err != nil {
		return nil, fmt.Errorf("store: reading traffic: %w", err)
	}
	defer rows.Close()

	var out []TrafficPoint
	for rows.Next() {
		var bucket, up, down int64
		if err := rows.Scan(&bucket, &up, &down); err != nil {
			return nil, err
		}
		out = append(out, TrafficPoint{At: time.Unix(bucket, 0).UTC(), Up: up, Down: down})
	}
	return out, rows.Err()
}

// TrafficTotal sums the traffic since a point in time.
//
// It reads the day buckets, which is the coarsest resolution covering any
// window worth totalling, so the sum touches a handful of rows rather than
// thousands.
func (s *Store) TrafficTotal(ctx context.Context, since time.Time) (up, down int64, err error) {
	const query = `SELECT COALESCE(SUM(up), 0), COALESCE(SUM(down), 0) FROM traffic WHERE span = ? AND bucket >= ?`

	unix := since.Unix()
	bucket := unix - unix%int64(SpanDay)
	row := s.db.QueryRowContext(ctx, query, int64(SpanDay), bucket)
	if err := row.Scan(&up, &down); err != nil {
		return 0, 0, fmt.Errorf("store: totalling traffic: %w", err)
	}
	return up, down, nil
}

// ---------------------------------------------------------------- latency

// RecordLatency stores one measurement. A delay of zero means the node did not
// answer, which is kept rather than discarded: a node that fails often is
// exactly what the history is for.
func (s *Store) RecordLatency(ctx context.Context, node string, delay int, at time.Time) error {
	const upsert = `
INSERT INTO latency (node, at, delay) VALUES (?, ?, ?)
ON CONFLICT (node, at) DO UPDATE SET delay = excluded.delay`

	if _, err := s.db.ExecContext(ctx, upsert, node, at.Unix(), delay); err != nil {
		return fmt.Errorf("store: recording latency: %w", err)
	}
	return nil
}

// LatencyPoint is one measurement.
type LatencyPoint struct {
	At    time.Time `json:"at"`
	Delay int       `json:"delay"`
}

// LatencyHistory returns one node's measurements, newest last.
func (s *Store) LatencyHistory(ctx context.Context, node string, since time.Time, limit int) ([]LatencyPoint, error) {
	if limit <= 0 {
		limit = 200
	}
	const query = `
SELECT at, delay FROM latency
WHERE node = ? AND at >= ?
ORDER BY at DESC LIMIT ?`

	rows, err := s.db.QueryContext(ctx, query, node, since.Unix(), limit)
	if err != nil {
		return nil, fmt.Errorf("store: reading latency: %w", err)
	}
	defer rows.Close()

	var out []LatencyPoint
	for rows.Next() {
		var at int64
		var delay int
		if err := rows.Scan(&at, &delay); err != nil {
			return nil, err
		}
		out = append(out, LatencyPoint{At: time.Unix(at, 0).UTC(), Delay: delay})
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	// The query takes the newest rows; the caller wants them oldest first.
	for i, j := 0, len(out)-1; i < j; i, j = i+1, j-1 {
		out[i], out[j] = out[j], out[i]
	}
	return out, nil
}

// NodeStat summarizes one node's measured behaviour.
type NodeStat struct {
	Node     string  `json:"node"`
	Samples  int     `json:"samples"`
	Average  int     `json:"average"`  // milliseconds, successful attempts only
	Best     int     `json:"best"`     // milliseconds
	Failures int     `json:"failures"` // attempts that got no answer
	Loss     float64 `json:"loss"`     // fraction of attempts that failed
}

// NodeStats summarizes every node measured since a point in time.
//
// Averaging only the successful attempts is deliberate. Counting a failure as
// zero would drag the average down and make an unreliable node look fast; the
// failure rate is reported separately, which is the honest way to say "quick
// when it works, and it often does not".
func (s *Store) NodeStats(ctx context.Context, since time.Time) (map[string]NodeStat, error) {
	const query = `
SELECT node,
       COUNT(*),
       COALESCE(AVG(NULLIF(delay, 0)), 0),
       COALESCE(MIN(NULLIF(delay, 0)), 0),
       SUM(CASE WHEN delay = 0 THEN 1 ELSE 0 END)
FROM latency WHERE at >= ? GROUP BY node`

	rows, err := s.db.QueryContext(ctx, query, since.Unix())
	if err != nil {
		return nil, fmt.Errorf("store: summarizing nodes: %w", err)
	}
	defer rows.Close()

	out := map[string]NodeStat{}
	for rows.Next() {
		var (
			stat    NodeStat
			average float64
		)
		if err := rows.Scan(&stat.Node, &stat.Samples, &average, &stat.Best, &stat.Failures); err != nil {
			return nil, err
		}
		stat.Average = int(average + 0.5)
		if stat.Samples > 0 {
			stat.Loss = float64(stat.Failures) / float64(stat.Samples)
		}
		out[stat.Node] = stat
	}
	return out, rows.Err()
}

// ---------------------------------------------------------------- retention

// Prune deletes data past its retention.
//
// Unbounded growth is not a theoretical concern on a router: flash fills, and
// the first thing a full filesystem breaks is the configuration write that
// would let a user fix it.
func (s *Store) Prune(ctx context.Context, r Retention, now time.Time) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("store: %w", err)
	}
	defer tx.Rollback()

	cutoffs := []struct {
		span Span
		keep time.Duration
	}{
		{SpanMinute, r.Minutes},
		{SpanHour, r.Hours},
		{SpanDay, r.Days},
	}
	for _, c := range cutoffs {
		if c.keep <= 0 {
			continue
		}
		if _, err := tx.ExecContext(ctx,
			`DELETE FROM traffic WHERE span = ? AND bucket < ?`,
			int64(c.span), now.Add(-c.keep).Unix()); err != nil {
			return fmt.Errorf("store: pruning traffic: %w", err)
		}
	}

	if r.Latency > 0 {
		if _, err := tx.ExecContext(ctx,
			`DELETE FROM latency WHERE at < ?`, now.Add(-r.Latency).Unix()); err != nil {
			return fmt.Errorf("store: pruning latency: %w", err)
		}
	}
	return tx.Commit()
}

// Size reports how much space the history occupies, so the interface can say so
// rather than leaving a user to wonder what is filling their flash.
func (s *Store) Size(ctx context.Context) (int64, error) {
	var pageCount, pageSize int64
	if err := s.db.QueryRowContext(ctx, `PRAGMA page_count`).Scan(&pageCount); err != nil {
		return 0, err
	}
	if err := s.db.QueryRowContext(ctx, `PRAGMA page_size`).Scan(&pageSize); err != nil {
		return 0, err
	}
	return pageCount * pageSize, nil
}

// Available reports whether this build can store history.
func Available() bool { return true }
