package executor

import (
	"encoding/json"
	"errors"
	"os"
	"sync"
	"time"
)

// RollbackRecord is persisted so an opaque rollback_token can undo an action
// later, even across agent restarts.
type RollbackRecord struct {
	Token     string            `json:"token"`
	Action    string            `json:"action"`
	Params    map[string]string `json:"params"`
	CommandID string            `json:"command_id"`
	CreatedAt time.Time         `json:"created_at"`
	// ExpiresAt, when non-zero, triggers automatic rollback (isolate_host, block_ip).
	ExpiresAt time.Time `json:"expires_at,omitempty"`
	Done      bool      `json:"done"`
}

type seenRec struct {
	Result  CommandResult `json:"result"`
	Expires time.Time     `json:"expires"`
}

type storeData struct {
	Seen      map[string]seenRec        `json:"seen"`
	Rollbacks map[string]RollbackRecord `json:"rollbacks"`
}

type store struct {
	mu   sync.Mutex
	path string
	d    storeData
}

func loadStore(path string) (*store, error) {
	s := &store{path: path, d: storeData{Seen: map[string]seenRec{}, Rollbacks: map[string]RollbackRecord{}}}
	b, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return s, nil
	}
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal(b, &s.d); err != nil {
		return nil, err
	}
	if s.d.Seen == nil {
		s.d.Seen = map[string]seenRec{}
	}
	if s.d.Rollbacks == nil {
		s.d.Rollbacks = map[string]RollbackRecord{}
	}
	return s, nil
}

// flush writes state atomically. Caller holds mu.
func (s *store) flush() error {
	b, err := json.Marshal(s.d)
	if err != nil {
		return err
	}
	tmp := s.path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, s.path)
}

func (s *store) seen(id string) (CommandResult, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	r, ok := s.d.Seen[id]
	return r.Result, ok
}

func (s *store) recordSeen(id string, res CommandResult, exp, now time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.d.Seen[id] = seenRec{Result: res, Expires: exp}
	for k, v := range s.d.Seen {
		if now.After(v.Expires.Add(24 * time.Hour)) {
			delete(s.d.Seen, k)
		}
	}
	return s.flush()
}

func (s *store) addRollback(r RollbackRecord) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.d.Rollbacks[r.Token] = r
	return s.flush()
}

func (s *store) rollback(token string) (RollbackRecord, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	r, ok := s.d.Rollbacks[token]
	return r, ok
}

func (s *store) markDone(token string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if r, ok := s.d.Rollbacks[token]; ok {
		r.Done = true
		s.d.Rollbacks[token] = r
	}
	return s.flush()
}

// markActionDone marks all open records of action (e.g. a superseded isolation).
func (s *store) markActionDone(action string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for k, r := range s.d.Rollbacks {
		if r.Action == action && !r.Done {
			r.Done = true
			s.d.Rollbacks[k] = r
		}
	}
	_ = s.flush()
}

func (s *store) expired(now time.Time) []RollbackRecord {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []RollbackRecord
	for _, r := range s.d.Rollbacks {
		if !r.Done && !r.ExpiresAt.IsZero() && now.After(r.ExpiresAt) {
			out = append(out, r)
		}
	}
	return out
}
