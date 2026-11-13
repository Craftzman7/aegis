package transport

import (
	"context"
	"errors"
	"log/slog"
	"time"

	"github.com/aegis-soc/aegis/agent/internal/event"
)

// MaxBatch is the PROTOCOL.md per-request anomaly limit.
const MaxBatch = 500

// EventPoster uploads a batch of anomalies.
type EventPoster interface {
	PostEvents(ctx context.Context, batch []event.Anomaly) error
}

// Sender batches anomalies (<=500, flush every FlushEvery) and falls back to
// the spool when the server is unreachable, draining it when it returns.
type Sender struct {
	Poster     EventPoster
	Spool      *Spool
	Log        *slog.Logger
	FlushEvery time.Duration
}

func (s *Sender) interval() time.Duration {
	if s.FlushEvery > 0 {
		return s.FlushEvery
	}
	return 2 * time.Second
}

// Run consumes in until ctx is cancelled, then makes a final bounded flush.
func (s *Sender) Run(ctx context.Context, in <-chan event.Anomaly) {
	t := time.NewTicker(s.interval())
	defer t.Stop()
	var batch []event.Anomaly
	for {
		select {
		case <-ctx.Done():
			fctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			s.flush(fctx, batch)
			cancel()
			return
		case a := <-in:
			batch = append(batch, a)
			if len(batch) >= MaxBatch {
				s.flush(ctx, batch)
				batch = nil
			}
		case <-t.C:
			s.flush(ctx, batch)
			batch = nil
		}
	}
}

func (s *Sender) flush(ctx context.Context, batch []event.Anomaly) {
	online := true
	if len(batch) > 0 {
		if err := s.Poster.PostEvents(ctx, batch); err != nil {
			online = false
			if isPermanent(err) {
				s.Log.Error("dropping batch rejected by server", "count", len(batch), "err", err)
			} else if s.Spool != nil {
				s.Log.Warn("server unreachable; spooling anomalies", "count", len(batch), "err", err)
				if perr := s.Spool.Put(batch); perr != nil {
					s.Log.Error("spool write failed", "err", perr)
				}
			}
		}
	}
	if !online || s.Spool == nil {
		return
	}
	s.Drain(ctx, 10)
}

// Drain uploads up to maxBatches spooled batches, stopping at the first failure.
func (s *Sender) Drain(ctx context.Context, maxBatches int) {
	for i := 0; i < maxBatches && ctx.Err() == nil; i++ {
		keys, as, err := s.Spool.Peek(MaxBatch)
		if err != nil || len(keys) == 0 {
			return
		}
		if len(as) > 0 {
			if err := s.Poster.PostEvents(ctx, as); err != nil && !isPermanent(err) {
				return
			} else if err != nil {
				s.Log.Error("dropping spooled batch rejected by server", "err", err)
			}
		}
		if err := s.Spool.Delete(keys); err != nil {
			s.Log.Error("spool delete failed", "err", err)
			return
		}
	}
}

func isPermanent(err error) bool {
	var he *HTTPError
	return errors.As(err, &he) && he.Permanent()
}
