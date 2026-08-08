package store

import (
	"context"
	"path/filepath"
	"testing"
	"time"
)

func open(t *testing.T) *Store {
	t.Helper()
	s, err := Open(filepath.Join(t.TempDir(), "history.db"))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

func TestOpenIsIdempotent(t *testing.T) {
	path := filepath.Join(t.TempDir(), "history.db")

	first, err := Open(path)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if err := first.RecordTraffic(context.Background(), time.Now(), 10, 20); err != nil {
		t.Fatalf("RecordTraffic: %v", err)
	}
	first.Close()

	// Re-opening an existing database must apply the schema again without
	// complaint and without losing what is already there.
	second, err := Open(path)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	defer second.Close()

	up, down, err := second.TrafficTotal(context.Background(), time.Now().Add(-time.Hour))
	if err != nil {
		t.Fatalf("TrafficTotal: %v", err)
	}
	if up != 10 || down != 20 {
		t.Errorf("after reopen got %d/%d, want 10/20", up, down)
	}
}

func TestRecordTrafficFillsEveryResolution(t *testing.T) {
	s := open(t)
	ctx := context.Background()
	at := time.Date(2026, 8, 7, 14, 30, 45, 0, time.UTC)

	if err := s.RecordTraffic(ctx, at, 100, 900); err != nil {
		t.Fatalf("RecordTraffic: %v", err)
	}

	// One write has to land in all three spans, so an hourly view is never
	// missing data that a per-minute view already has.
	for _, span := range []Span{SpanMinute, SpanHour, SpanDay} {
		points, err := s.TrafficSeries(ctx, span, at.Add(-time.Hour*48), at.Add(time.Hour*48))
		if err != nil {
			t.Fatalf("TrafficSeries(%d): %v", span, err)
		}
		if len(points) != 1 {
			t.Fatalf("span %d: got %d points, want 1", span, len(points))
		}
		if points[0].Up != 100 || points[0].Down != 900 {
			t.Errorf("span %d: got %d/%d", span, points[0].Up, points[0].Down)
		}
		// The bucket has to be aligned to its own resolution.
		if points[0].At.Unix()%int64(span) != 0 {
			t.Errorf("span %d: bucket %v is not aligned", span, points[0].At)
		}
	}
}

func TestRecordTrafficAccumulatesWithinABucket(t *testing.T) {
	s := open(t)
	ctx := context.Background()
	base := time.Date(2026, 8, 7, 14, 30, 0, 0, time.UTC)

	// Three samples inside the same minute must sum, not overwrite. Getting this
	// wrong would silently under-report every minute to its last second.
	for i := 0; i < 3; i++ {
		if err := s.RecordTraffic(ctx, base.Add(time.Duration(i*10)*time.Second), 10, 100); err != nil {
			t.Fatalf("RecordTraffic: %v", err)
		}
	}

	points, err := s.TrafficSeries(ctx, SpanMinute, base.Add(-time.Minute), base.Add(time.Minute))
	if err != nil {
		t.Fatalf("TrafficSeries: %v", err)
	}
	if len(points) != 1 {
		t.Fatalf("got %d points, want 1 minute bucket", len(points))
	}
	if points[0].Up != 30 || points[0].Down != 300 {
		t.Errorf("got %d/%d, want 30/300", points[0].Up, points[0].Down)
	}
}

func TestRecordTrafficIgnoresIdleIntervals(t *testing.T) {
	s := open(t)
	ctx := context.Background()

	if err := s.RecordTraffic(ctx, time.Now(), 0, 0); err != nil {
		t.Fatalf("RecordTraffic: %v", err)
	}
	points, err := s.TrafficSeries(ctx, SpanMinute, time.Now().Add(-time.Hour), time.Now().Add(time.Hour))
	if err != nil {
		t.Fatalf("TrafficSeries: %v", err)
	}
	// A router is idle most of the time; storing a row per second of nothing
	// would fill the database with zeroes.
	if len(points) != 0 {
		t.Errorf("an idle interval was stored: %+v", points)
	}
}

func TestNodeStatsSeparateSpeedFromReliability(t *testing.T) {
	s := open(t)
	ctx := context.Background()
	now := time.Now()

	// A node that answers quickly when it answers at all, and often does not.
	for i, delay := range []int{100, 120, 0, 0, 110} {
		if err := s.RecordLatency(ctx, "node-a", delay, now.Add(time.Duration(i)*time.Second)); err != nil {
			t.Fatalf("RecordLatency: %v", err)
		}
	}

	stats, err := s.NodeStats(ctx, now.Add(-time.Hour))
	if err != nil {
		t.Fatalf("NodeStats: %v", err)
	}
	a := stats["node-a"]

	if a.Samples != 5 || a.Failures != 2 {
		t.Errorf("samples/failures = %d/%d, want 5/2", a.Samples, a.Failures)
	}
	// Counting a failure as zero would average to 66 ms and make an unreliable
	// node look like the fastest one on the list.
	if a.Average != 110 {
		t.Errorf("Average = %d, want 110 (successful attempts only)", a.Average)
	}
	if a.Best != 100 {
		t.Errorf("Best = %d, want 100", a.Best)
	}
	if a.Loss < 0.39 || a.Loss > 0.41 {
		t.Errorf("Loss = %.2f, want 0.40", a.Loss)
	}
}

func TestLatencyHistoryIsOldestFirst(t *testing.T) {
	s := open(t)
	ctx := context.Background()
	now := time.Now()

	for i, delay := range []int{10, 20, 30} {
		if err := s.RecordLatency(ctx, "n", delay, now.Add(time.Duration(i)*time.Second)); err != nil {
			t.Fatalf("RecordLatency: %v", err)
		}
	}

	points, err := s.LatencyHistory(ctx, "n", now.Add(-time.Hour), 10)
	if err != nil {
		t.Fatalf("LatencyHistory: %v", err)
	}
	if len(points) != 3 {
		t.Fatalf("got %d points, want 3", len(points))
	}
	// A graph is drawn left to right in time order.
	if points[0].Delay != 10 || points[2].Delay != 30 {
		t.Errorf("history is not oldest first: %+v", points)
	}
}

func TestLatencyHistoryHonoursTheLimit(t *testing.T) {
	s := open(t)
	ctx := context.Background()
	now := time.Now()

	for i := 0; i < 50; i++ {
		if err := s.RecordLatency(ctx, "n", i+1, now.Add(time.Duration(i)*time.Second)); err != nil {
			t.Fatalf("RecordLatency: %v", err)
		}
	}

	points, err := s.LatencyHistory(ctx, "n", now.Add(-time.Hour), 5)
	if err != nil {
		t.Fatalf("LatencyHistory: %v", err)
	}
	if len(points) != 5 {
		t.Fatalf("got %d points, want 5", len(points))
	}
	// The limit must take the newest measurements, not the oldest.
	if points[len(points)-1].Delay != 50 {
		t.Errorf("the limit kept the wrong end: last delay is %d, want 50", points[len(points)-1].Delay)
	}
}

func TestPruneKeepsEachResolutionForItsOwnWindow(t *testing.T) {
	s := open(t)
	ctx := context.Background()
	now := time.Date(2026, 8, 7, 12, 0, 0, 0, time.UTC)

	// Something two days old: past the minute retention, inside the hour one.
	old := now.Add(-48 * time.Hour)
	if err := s.RecordTraffic(ctx, old, 5, 5); err != nil {
		t.Fatalf("RecordTraffic: %v", err)
	}
	if err := s.RecordTraffic(ctx, now, 7, 7); err != nil {
		t.Fatalf("RecordTraffic: %v", err)
	}
	if err := s.RecordLatency(ctx, "n", 42, now.Add(-30*24*time.Hour)); err != nil {
		t.Fatalf("RecordLatency: %v", err)
	}

	if err := s.Prune(ctx, DefaultRetention(), now); err != nil {
		t.Fatalf("Prune: %v", err)
	}

	minutes, err := s.TrafficSeries(ctx, SpanMinute, old.Add(-time.Hour), now.Add(time.Hour))
	if err != nil {
		t.Fatalf("TrafficSeries: %v", err)
	}
	if len(minutes) != 1 {
		t.Errorf("got %d minute buckets, want only the recent one", len(minutes))
	}

	// The coarser resolutions still hold the old data, which is the point of
	// keeping three of them.
	hours, err := s.TrafficSeries(ctx, SpanHour, old.Add(-time.Hour), now.Add(time.Hour))
	if err != nil {
		t.Fatalf("TrafficSeries: %v", err)
	}
	if len(hours) != 2 {
		t.Errorf("got %d hour buckets, want 2", len(hours))
	}

	stats, err := s.NodeStats(ctx, time.Unix(0, 0))
	if err != nil {
		t.Fatalf("NodeStats: %v", err)
	}
	if _, ok := stats["n"]; ok {
		t.Error("a measurement past the latency retention survived pruning")
	}
}

func TestSizeReportsSomething(t *testing.T) {
	s := open(t)
	ctx := context.Background()

	if err := s.RecordTraffic(ctx, time.Now(), 1, 1); err != nil {
		t.Fatalf("RecordTraffic: %v", err)
	}
	size, err := s.Size(ctx)
	if err != nil {
		t.Fatalf("Size: %v", err)
	}
	if size <= 0 {
		t.Errorf("Size = %d, want a positive byte count", size)
	}
}
