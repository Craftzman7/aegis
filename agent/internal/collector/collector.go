// Package collector gathers host telemetry and normalizes it into events.
// Parsers are pure functions; OS-specific plumbing lives in *_linux.go files.
package collector

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"log/slog"
	"sync"
	"time"

	"github.com/aegis-soc/aegis/agent/internal/event"
)

// Collector produces events until ctx is cancelled.
type Collector interface {
	Name() string
	Run(ctx context.Context, out chan<- event.Event) error
}

func newID() string {
	var b [8]byte
	_, _ = rand.Read(b[:])
	return hex.EncodeToString(b[:])
}

func emit(ctx context.Context, out chan<- event.Event, e event.Event) bool {
	if e.ID == "" {
		e.ID = newID()
	}
	if e.Time.IsZero() {
		e.Time = time.Now().UTC()
	}
	if e.Logsource.Product == "" {
		e.Logsource.Product = event.ProductLinux
	}
	select {
	case out <- e:
		return true
	case <-ctx.Done():
		return false
	}
}

// RunAll runs the collectors concurrently, logging (not propagating) failures,
// and returns when ctx is done and all have exited.
func RunAll(ctx context.Context, log *slog.Logger, out chan<- event.Event, cs ...Collector) {
	var wg sync.WaitGroup
	for _, c := range cs {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := c.Run(ctx, out); err != nil && ctx.Err() == nil {
				log.Warn("collector stopped", "collector", c.Name(), "err", err)
			}
		}()
	}
	wg.Wait()
}

// tick runs fn immediately and then every d until ctx is done.
func tick(ctx context.Context, d time.Duration, fn func()) {
	fn()
	t := time.NewTicker(d)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			fn()
		}
	}
}
