package app

import "sync"

// Event announces that some part of the state changed.
//
// It carries only what changed, not the new value. The interface reacts by
// re-reading the part it cares about, which keeps the bus trivial and means a
// subscriber that missed an event while it was busy simply catches up on the
// next one instead of drifting out of sync.
type Event struct {
	Type string `json:"type"` // status, nodes, rules, settings, cores
}

// eventBus fans events out to every live subscriber.
type eventBus struct {
	mu     sync.RWMutex
	nextID int
	subs   map[int]chan Event
}

func newEventBus() *eventBus {
	return &eventBus{subs: make(map[int]chan Event)}
}

// subscribe registers a watcher and returns it with its cancel function.
func (b *eventBus) subscribe() (<-chan Event, func()) {
	b.mu.Lock()
	defer b.mu.Unlock()

	id := b.nextID
	b.nextID++
	ch := make(chan Event, 16)
	b.subs[id] = ch

	return ch, func() {
		b.mu.Lock()
		defer b.mu.Unlock()
		if existing, ok := b.subs[id]; ok {
			delete(b.subs, id)
			close(existing)
		}
	}
}

// publish delivers an event to every subscriber that can take it.
//
// A browser tab that stopped reading must never be able to block a state change
// on the router, so a full channel drops the event rather than waiting. Losing
// one notification is harmless: subscribers re-read state on the next event, and
// the interface polls as a backstop.
func (b *eventBus) publish(e Event) {
	b.mu.RLock()
	channels := make([]chan Event, 0, len(b.subs))
	for _, ch := range b.subs {
		channels = append(channels, ch)
	}
	b.mu.RUnlock()

	for _, ch := range channels {
		select {
		case ch <- e:
		default:
		}
	}
}
