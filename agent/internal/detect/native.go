package detect

import (
	"net"
	"time"

	"github.com/aegis-soc/aegis/agent/internal/event"
)

// Threshold keys (policy.body.thresholds) and defaults.
const (
	KeyBruteCount    = "native:ssh_bruteforce.count"
	KeyBruteWindow   = "native:ssh_bruteforce.window_s"
	KeySuccessCount  = "native:ssh_success_after_fail.count"
	KeySuccessWindow = "native:ssh_success_after_fail.window_s"
	KeyRareLearning  = "native:rare_outbound.learning_s"
	KeyZScore        = "baseline.zscore"
	KeyLearnSamples  = "baseline.learning_samples"
	KeyDedupCooldown = "dedup.cooldown_s"

	DefBruteCount    = 10
	DefBruteWindow   = 60
	DefSuccessCount  = 5
	DefSuccessWindow = 600
	DefRareLearning  = 600
	DefZScore        = 4
	DefLearnSamples  = 30
	DefCooldown      = 300
)

// SSHTracker implements the SSH brute-force and success-after-failures
// detectors over ssh_failed / ssh_accepted events. Not safe for concurrent use.
type SSHTracker struct {
	fails *Window
}

// NewSSHTracker returns a tracker retaining up to an hour of failures.
func NewSSHTracker() *SSHTracker { return &SSHTracker{fails: NewWindow(time.Hour)} }

// SSHResult describes a tracker hit.
type SSHResult struct {
	Brute        bool
	SuccessAfter bool
	Failures     int
	IP, User     string
}

// Observe feeds an auth event. bruteN/bruteWin and succN/succWin come from the
// policy thresholds.
func (t *SSHTracker) Observe(e *event.Event, bruteN int, bruteWin time.Duration, succN int, succWin time.Duration) (SSHResult, bool) {
	if e.SourceIp == "" {
		return SSHResult{}, false
	}
	switch e.Kind {
	case event.KindSSHFailed, event.KindSSHInvalidUser:
		t.fails.Add(e.SourceIp, e.Time)
		if n := t.fails.Count(e.SourceIp, e.Time, bruteWin); bruteN > 0 && n >= bruteN {
			t.fails.Reset(e.SourceIp) // re-arm: next burst must again reach the threshold
			return SSHResult{Brute: true, Failures: n, IP: e.SourceIp, User: e.User}, true
		}
	case event.KindSSHAccepted:
		if n := t.fails.Count(e.SourceIp, e.Time, succWin); succN > 0 && n >= succN {
			t.fails.Reset(e.SourceIp)
			return SSHResult{SuccessAfter: true, Failures: n, IP: e.SourceIp, User: e.User}, true
		}
	}
	return SSHResult{}, false
}

// Sweep drops stale state.
func (t *SSHTracker) Sweep(now time.Time) { t.fails.Sweep(now) }

// isPublicIP reports whether ip is routable on the public internet.
func isPublicIP(s string) bool {
	ip := net.ParseIP(s)
	if ip == nil {
		return false
	}
	return !(ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() ||
		ip.IsMulticast() || ip.IsUnspecified())
}

// RareDest tracks previously seen outbound destinations. During the learning
// period everything is absorbed silently; afterwards a never-seen public
// destination is "rare". Not safe for concurrent use.
type RareDest struct {
	seen  map[string]struct{}
	start time.Time
	max   int
}

// NewRareDest starts the learning period at start.
func NewRareDest(start time.Time) *RareDest {
	return &RareDest{seen: map[string]struct{}{}, start: start, max: 50_000}
}

// Observe returns true when ip is a new public destination after learning.
func (r *RareDest) Observe(ip string, now time.Time, learning time.Duration) bool {
	if !isPublicIP(ip) {
		return false
	}
	if _, ok := r.seen[ip]; ok {
		return false
	}
	if len(r.seen) < r.max {
		r.seen[ip] = struct{}{}
	}
	return now.Sub(r.start) >= learning
}
