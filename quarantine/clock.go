package quarantine

import (
	"sync"
	"time"
)

// Clock abstracts the passage of time so timeout and retry behavior can be
// driven deterministically in tests.
type Clock interface {
	Now() time.Time
	After(d time.Duration) <-chan time.Time
}

// SystemClock is the real-time clock.
type SystemClock struct{}

func (SystemClock) Now() time.Time { return time.Now() }

func (SystemClock) After(d time.Duration) <-chan time.Time { return time.After(d) }

type manualWaiter struct {
	deadline time.Time
	ch       chan time.Time
}

// ManualClock is a Clock advanced explicitly by a test. After returns a
// one-shot channel that fires when Advance moves past the requested deadline.
type ManualClock struct {
	mu      sync.Mutex
	now     time.Time
	waiters []manualWaiter
}

// NewManualClock starts a manual clock at t.
func NewManualClock(t time.Time) *ManualClock {
	return &ManualClock{now: t}
}

func (c *ManualClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *ManualClock) After(d time.Duration) <-chan time.Time {
	ch := make(chan time.Time, 1)
	c.mu.Lock()
	if d <= 0 {
		ch <- c.now
		c.mu.Unlock()
		return ch
	}
	c.waiters = append(c.waiters, manualWaiter{deadline: c.now.Add(d), ch: ch})
	c.mu.Unlock()
	return ch
}

// Advance moves the clock forward by d and fires every waiter whose deadline
// has been reached.
func (c *ManualClock) Advance(d time.Duration) {
	c.mu.Lock()
	c.now = c.now.Add(d)
	now := c.now
	keep := c.waiters[:0]
	for _, w := range c.waiters {
		if !w.deadline.After(now) {
			w.ch <- now
		} else {
			keep = append(keep, w)
		}
	}
	c.waiters = keep
	c.mu.Unlock()
}

// PendingTimers reports how many un-fired After channels are outstanding. It
// is useful for tests that want to wait until a timeout has been armed.
func (c *ManualClock) PendingTimers() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.waiters)
}

// AdvanceTo moves the clock to t (never backwards).
func (c *ManualClock) AdvanceTo(t time.Time) {
	c.mu.Lock()
	d := t.Sub(c.now)
	c.mu.Unlock()
	if d > 0 {
		c.Advance(d)
	}
}
