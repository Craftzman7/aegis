//go:build !yara

package executor

import (
	"context"
	"errors"
)

func (e *Executor) yaraScan(ctx context.Context, cmd Command) (map[string]any, string, error) {
	var p struct {
		Path  string `json:"path"`
		Rules string `json:"rules"`
	}
	if err := decode(cmd.Params, &p); err != nil {
		return nil, "", err
	}
	return nil, "", errors.New("built without yara")
}
