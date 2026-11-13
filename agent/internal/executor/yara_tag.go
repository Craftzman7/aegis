//go:build yara

package executor

import (
	"context"
	"errors"
)

// The yara build tag is reserved for the cgo yara-x integration, which is
// intentionally not implemented in this repository yet.
func (e *Executor) yaraScan(ctx context.Context, cmd Command) (map[string]any, string, error) {
	return nil, "", errors.New("yara integration not implemented")
}
