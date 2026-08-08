package core

import "sync"

// logRing keeps the most recent log lines from one core and fans new lines out
// to live subscribers.
//
// Subscribers get a buffered channel and are dropped from, rather than blocked
// on: a browser tab that stopped reading its log stream must never be able to
// stall the pipe that a proxy core is writing its output into.
type logRing struct {
	mu    sync.RWMutex
	buf   []LogLine
	size  int
	start int
	count int

	nextID int
	subs   map[int]chan LogLine
}

// subscriberBuffer is how many lines a subscriber may fall behind before it
// starts losing them.
const subscriberBuffer = 256

func newLogRing(size int) *logRing {
	if size <= 0 {
		size = 500
	}
	return &logRing{
		buf:  make([]LogLine, size),
		size: size,
		subs: make(map[int]chan LogLine),
	}
}

// append records a line and delivers it to every subscriber that can keep up.
func (r *logRing) append(line LogLine) {
	r.mu.Lock()
	idx := (r.start + r.count) % r.size
	r.buf[idx] = line
	if r.count < r.size {
		r.count++
	} else {
		r.start = (r.start + 1) % r.size
	}

	subs := make([]chan LogLine, 0, len(r.subs))
	for _, ch := range r.subs {
		subs = append(subs, ch)
	}
	r.mu.Unlock()

	for _, ch := range subs {
		select {
		case ch <- line:
		default: // subscriber is behind; drop rather than block the core
		}
	}
}

// tail returns up to n most recent lines, oldest first.
func (r *logRing) tail(n int) []LogLine {
	r.mu.RLock()
	defer r.mu.RUnlock()

	if n <= 0 || n > r.count {
		n = r.count
	}
	out := make([]LogLine, 0, n)
	for i := r.count - n; i < r.count; i++ {
		out = append(out, r.buf[(r.start+i)%r.size])
	}
	return out
}

// subscribe registers a live consumer and returns it with its cancel function.
func (r *logRing) subscribe() (<-chan LogLine, func()) {
	r.mu.Lock()
	defer r.mu.Unlock()

	id := r.nextID
	r.nextID++
	ch := make(chan LogLine, subscriberBuffer)
	r.subs[id] = ch

	return ch, func() {
		r.mu.Lock()
		defer r.mu.Unlock()
		if existing, ok := r.subs[id]; ok {
			delete(r.subs, id)
			close(existing)
		}
	}
}
