package detect

import (
	"sync"
	"time"

	"github.com/aegis-soc/aegis/agent/internal/event"
)

// Ring is a bounded, time-limited in-memory buffer of normalized events used
// by test_rule backtests.
type Ring struct {
	mu     sync.RWMutex
	buf    []event.Event
	head   int // next write position
	size   int
	maxAge time.Duration
}

// DefaultRingCap and DefaultRingAge bound the ring (200k events / 24h).
const (
	DefaultRingCap = 200_000
	DefaultRingAge = 24 * time.Hour
)

// NewRing creates a ring holding at most capacity events newer than maxAge.
func NewRing(capacity int, maxAge time.Duration) *Ring {
	if capacity <= 0 {
		capacity = DefaultRingCap
	}
	if maxAge <= 0 {
		maxAge = DefaultRingAge
	}
	return &Ring{buf: make([]event.Event, capacity), maxAge: maxAge}
}

// Add appends e, overwriting the oldest entry when full.
func (r *Ring) Add(e event.Event) {
	r.mu.Lock()
	r.buf[r.head] = e
	r.head = (r.head + 1) % len(r.buf)
	if r.size < len(r.buf) {
		r.size++
	}
	r.mu.Unlock()
}

// Len returns the number of buffered events.
func (r *Ring) Len() int {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.size
}

// Snapshot returns events (oldest first) not older than max(since, now-maxAge).
func (r *Ring) Snapshot(since time.Time) []event.Event {
	cutoff := time.Now().Add(-r.maxAge)
	if since.After(cutoff) {
		cutoff = since
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]event.Event, 0, r.size)
	start := (r.head - r.size + len(r.buf)) % len(r.buf)
	for i := 0; i < r.size; i++ {
		e := r.buf[(start+i)%len(r.buf)]
		if !e.Time.Before(cutoff) {
			out = append(out, e)
		}
	}
	return out
}
