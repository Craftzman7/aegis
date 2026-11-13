package detect

import "time"

// Window is a keyed sliding-window event counter. Not safe for concurrent use.
type Window struct {
	retain time.Duration
	m      map[string][]time.Time
}

// NewWindow creates a Window that discards entries older than retain.
func NewWindow(retain time.Duration) *Window {
	return &Window{retain: retain, m: map[string][]time.Time{}}
}

// Add records an occurrence for key at t.
func (w *Window) Add(key string, t time.Time) {
	ts := w.m[key]
	ts = append(ts, t)
	// prune
	cut := t.Add(-w.retain)
	i := 0
	for i < len(ts) && ts[i].Before(cut) {
		i++
	}
	w.m[key] = ts[i:]
}

// Count returns occurrences of key in (now-d, now].
func (w *Window) Count(key string, now time.Time, d time.Duration) int {
	n := 0
	for _, t := range w.m[key] {
		if t.After(now.Add(-d)) && !t.After(now) {
			n++
		}
	}
	return n
}

// Reset forgets key.
func (w *Window) Reset(key string) { delete(w.m, key) }

// Sweep drops keys with no entries newer than now-retain.
func (w *Window) Sweep(now time.Time) {
	for k, ts := range w.m {
		if len(ts) == 0 || ts[len(ts)-1].Before(now.Add(-w.retain)) {
			delete(w.m, k)
		}
	}
}

// Len returns the number of tracked keys.
func (w *Window) Len() int { return len(w.m) }
