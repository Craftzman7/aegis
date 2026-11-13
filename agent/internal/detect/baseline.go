package detect

import (
	"math"
	"sync"
)

// Baseline tracks an exponentially weighted mean and variance per metric and
// scores new observations with a z-score once the learning window has passed.
type Baseline struct {
	mu    sync.Mutex
	alpha float64
	learn int
	stats map[string]*stat
}

type stat struct {
	mean, vari float64
	n          int
}

// Verdict is the result of observing one sample.
type Verdict struct {
	Z        float64
	Mean     float64
	Std      float64
	Learning bool
}

// minStd prevents tiny variances from producing huge z-scores on count metrics.
const minStd = 1.0

// NewBaseline creates a Baseline. alpha is the EWMA smoothing factor (0,1];
// learn is the number of samples observed before scoring begins.
func NewBaseline(alpha float64, learn int) *Baseline {
	if alpha <= 0 || alpha > 1 {
		alpha = 0.1
	}
	return &Baseline{alpha: alpha, learn: learn, stats: map[string]*stat{}}
}

// SetLearning changes the learning window.
func (b *Baseline) SetLearning(n int) {
	b.mu.Lock()
	b.learn = n
	b.mu.Unlock()
}

// Observe scores v against the metric's history and then folds it in.
// Samples that score above zMax are folded in with a heavily damped weight so
// an attack burst does not poison the baseline; pass zMax<=0 to disable.
func (b *Baseline) Observe(metric string, v, zMax float64) Verdict {
	b.mu.Lock()
	defer b.mu.Unlock()
	s := b.stats[metric]
	if s == nil {
		s = &stat{mean: v}
		b.stats[metric] = s
	}
	std := math.Max(math.Sqrt(s.vari), minStd)
	vd := Verdict{Mean: s.mean, Std: std, Learning: s.n < b.learn}
	if s.n > 0 {
		vd.Z = (v - s.mean) / std
	}
	alpha := b.alpha
	if !vd.Learning && zMax > 0 && vd.Z > zMax {
		alpha *= 0.1
	}
	if s.n > 0 {
		d := v - s.mean
		s.mean += alpha * d
		s.vari = (1 - alpha) * (s.vari + alpha*d*d)
	}
	s.n++
	return vd
}
