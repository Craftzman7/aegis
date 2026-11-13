//go:build !linux

package collector

import (
	"context"
	"errors"

	"github.com/aegis-soc/aegis/agent/internal/event"
)

// Auditd is unavailable off Linux.
type Auditd struct{}

func (a *Auditd) Name() string { return "auditd" }

func (a *Auditd) Run(context.Context, chan<- event.Event) error {
	return errors.New("auditd collector is only supported on linux")
}
