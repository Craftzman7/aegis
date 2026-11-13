package transport

import (
	"encoding/binary"
	"encoding/json"
	"path/filepath"
	"time"

	bolt "go.etcd.io/bbolt"

	"github.com/aegis-soc/aegis/agent/internal/event"
)

var spoolBucket = []byte("anomalies")

// DefaultSpoolMax bounds the on-disk spool; oldest entries are dropped first.
const DefaultSpoolMax = 50_000

// Spool is a durable FIFO of anomalies awaiting upload.
type Spool struct {
	db  *bolt.DB
	max int
}

// OpenSpool opens (creating if needed) dir/spool.db.
func OpenSpool(dir string, max int) (*Spool, error) {
	if max <= 0 {
		max = DefaultSpoolMax
	}
	db, err := bolt.Open(filepath.Join(dir, "spool.db"), 0o600, &bolt.Options{Timeout: 5 * time.Second})
	if err != nil {
		return nil, err
	}
	if err := db.Update(func(tx *bolt.Tx) error {
		_, err := tx.CreateBucketIfNotExists(spoolBucket)
		return err
	}); err != nil {
		db.Close()
		return nil, err
	}
	return &Spool{db: db, max: max}, nil
}

// Close closes the database.
func (s *Spool) Close() error { return s.db.Close() }

func key(n uint64) []byte {
	var k [8]byte
	binary.BigEndian.PutUint64(k[:], n)
	return k[:]
}

// Put appends anomalies, trimming the oldest entries beyond the cap.
func (s *Spool) Put(as []event.Anomaly) error {
	return s.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket(spoolBucket)
		for _, a := range as {
			seq, err := b.NextSequence()
			if err != nil {
				return err
			}
			v, err := json.Marshal(a)
			if err != nil {
				return err
			}
			if err := b.Put(key(seq), v); err != nil {
				return err
			}
		}
		n := 0
		_ = b.ForEach(func(_, _ []byte) error { n++; return nil })
		for over := n - s.max; over > 0; over-- {
			c := b.Cursor()
			k, _ := c.First()
			if k == nil {
				break
			}
			if err := b.Delete(k); err != nil {
				return err
			}
		}
		return nil
	})
}

// Peek returns up to n oldest anomalies and their keys.
func (s *Spool) Peek(n int) (keys [][]byte, out []event.Anomaly, err error) {
	err = s.db.View(func(tx *bolt.Tx) error {
		c := tx.Bucket(spoolBucket).Cursor()
		for k, v := c.First(); k != nil && len(out) < n; k, v = c.Next() {
			var a event.Anomaly
			if json.Unmarshal(v, &a) == nil {
				out = append(out, a)
			}
			keys = append(keys, append([]byte(nil), k...))
		}
		return nil
	})
	return
}

// Delete removes the given keys.
func (s *Spool) Delete(keys [][]byte) error {
	return s.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket(spoolBucket)
		for _, k := range keys {
			if err := b.Delete(k); err != nil {
				return err
			}
		}
		return nil
	})
}

// Len returns the number of spooled anomalies.
func (s *Spool) Len() int {
	n := 0
	_ = s.db.View(func(tx *bolt.Tx) error {
		_ = tx.Bucket(spoolBucket).ForEach(func(_, _ []byte) error { n++; return nil })
		return nil
	})
	return n
}
