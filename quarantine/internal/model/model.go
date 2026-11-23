// Package model is a deliberately independent, sequential state machine that
// implements the quarantine commit rules without referencing the engine. It is
// used only by tests to cross-check the concurrent engine on small two-tenant
// interleavings.
//
// The model has no goroutines and no clock. A scan is explicitly advanced by
// Complete, and every other operation is a single atomic transition. This makes
// the intended commit semantics (late results, cancellation, rule updates and
// release) explicit and reviewable on their own.
package model

import "fmt"

// Verdict mirrors the engine's outcome names but is defined independently.
type Verdict string

const (
	Clean    Verdict = "clean"
	Infected Verdict = "infected"
)

// State is a task state.
type State string

const (
	Queued    State = "queued"
	Scanning  State = "scanning"
	CleanS    State = "clean"
	InfectedS State = "infected"
	Cancelled State = "cancelled"
	Released  State = "released"
)

// Task is one submission.
type Task struct {
	ID         uint64
	Tenant     string
	Digest     string
	Rule       int64
	State      State
	Merged     bool
	ResultRule int64
	Verdict    Verdict
	HasResult  bool
	Released   bool
	JobID      string
}

// Result of an operation, as observed by the caller.
type Result struct {
	TaskID uint64
	Route  string // "new", "merged", "cached", "duplicate"
	State  State
	JobID  string
	// Release outcome.
	Released  bool
	Already   bool
	Stale     bool
	NotClean  bool
	TooLate   bool
	Cancelled bool
	Conflict  bool
}

type job struct {
	id      string
	tenant  string
	digest  string
	rule    int64
	verdict Verdict
	tasks   map[uint64]bool
}

// Machine is the reference state machine.
type Machine struct {
	rule       int64
	nextTask   uint64
	nextJob    uint64
	tasks      map[uint64]*Task
	live       map[string]*job // tenant|digest|rule
	cache      map[string]Verdict
	reqs       map[string]uint64
	tenantReqs map[string]map[string]uint64
	calls      int
	released   []string // digests actually released
}

// New creates a machine at rule 1.
func New() *Machine {
	return &Machine{
		rule:       1,
		nextTask:   1,
		nextJob:    1,
		tasks:      map[uint64]*Task{},
		live:       map[string]*job{},
		cache:      map[string]Verdict{},
		reqs:       map[string]uint64{},
		tenantReqs: map[string]map[string]uint64{},
	}
}

func key(tenant, digest string, rule int64) string {
	return fmt.Sprintf("%s|%s|%d", tenant, digest, rule)
}

// Submit creates a task. verdict is the outcome the scan of this digest would
// produce; it is used when the job is completed or adopted from cache.
func (m *Machine) Submit(tenant, digest, requestID string, verdict Verdict) Result {
	if requestID != "" {
		if id, ok := m.reqs[tenant+"|"+requestID]; ok {
			t := m.tasks[id]
			return Result{TaskID: id, Route: "duplicate", State: t.State, JobID: t.JobID}
		}
	}
	id := m.nextTask
	m.nextTask++
	t := &Task{ID: id, Tenant: tenant, Digest: digest, Rule: m.rule, State: Scanning}
	k := key(tenant, digest, m.rule)
	if j := m.live[k]; j != nil {
		j.tasks[id] = true
		t.Merged = true
		t.JobID = j.id
		m.tasks[id] = t
		if requestID != "" {
			m.reqs[tenant+"|"+requestID] = id
		}
		return Result{TaskID: id, Route: "merged", State: t.State, JobID: j.id}
	}
	if v, ok := m.cache[k]; ok {
		t.State = stateFor(v)
		t.Verdict = v
		t.ResultRule = m.rule
		t.HasResult = true
		m.tasks[id] = t
		if requestID != "" {
			m.reqs[tenant+"|"+requestID] = id
		}
		return Result{TaskID: id, Route: "cached", State: t.State}
	}
	j := &job{
		id:      fmt.Sprintf("job-%d", m.nextJob),
		tenant:  tenant,
		digest:  digest,
		rule:    m.rule,
		verdict: verdict,
		tasks:   map[uint64]bool{id: true},
	}
	m.nextJob++
	m.live[k] = j
	t.JobID = j.id
	t.State = Scanning
	m.tasks[id] = t
	m.calls++
	if requestID != "" {
		m.reqs[tenant+"|"+requestID] = id
	}
	return Result{TaskID: id, Route: "new", State: Scanning, JobID: j.id}
}

// Complete resolves the live job for tenant/digest under the current rule.
// It reports false when no such job is live.
func (m *Machine) Complete(tenant, digest string) bool {
	return m.CompleteRule(tenant, digest, m.rule)
}

// CompleteRule resolves the live job for tenant/digest under a specific rule
// version. The rule is explicit so a job frozen before a rule update can be
// completed after it.
func (m *Machine) CompleteRule(tenant, digest string, rule int64) bool {
	k := key(tenant, digest, rule)
	j := m.live[k]
	if j == nil {
		return false
	}
	for id := range j.tasks {
		t := m.tasks[id]
		if t.State == Cancelled {
			continue
		}
		t.State = stateFor(j.verdict)
		t.Verdict = j.verdict
		t.ResultRule = j.rule
		t.HasResult = true
	}
	m.cache[k] = j.verdict
	delete(m.live, k)
	return true
}

// Cancel attempts to cancel a task before its result commits.
func (m *Machine) Cancel(tenant string, id uint64) Result {
	t := m.tasks[id]
	if t == nil || t.Tenant != tenant {
		return Result{TooLate: true}
	}
	if t.HasResult || t.State == Cancelled || t.State == Released {
		return Result{TooLate: true}
	}
	if j := m.live[key(t.Tenant, t.Digest, t.Rule)]; j != nil {
		delete(j.tasks, id)
		if len(j.tasks) == 0 {
			delete(m.live, key(t.Tenant, t.Digest, t.Rule))
		}
	}
	t.State = Cancelled
	return Result{Cancelled: true}
}

// UpdateRules advances the rule version.
func (m *Machine) UpdateRules() int64 {
	m.rule++
	return m.rule
}

// Release applies the release commit rules.
func (m *Machine) Release(tenant string, id uint64) Result {
	t := m.tasks[id]
	if t == nil || t.Tenant != tenant {
		return Result{TooLate: true}
	}
	if t.State == Released {
		return Result{Released: true, Already: true}
	}
	if t.State == Cancelled {
		return Result{Cancelled: true}
	}
	if !t.HasResult {
		return Result{}
	}
	if t.Verdict != Clean {
		return Result{NotClean: true}
	}
	if t.ResultRule != m.rule {
		return Result{Stale: true}
	}
	t.State = Released
	t.Released = true
	m.released = append(m.released, t.Digest)
	return Result{Released: true}
}

// Snapshot returns a copy of every task keyed by ID, plus derived counts.
type Snapshot struct {
	Rule     int64
	Tasks    map[uint64]Task
	Calls    int
	Live     int
	Released []string
}

func (m *Machine) Snapshot() Snapshot {
	s := Snapshot{
		Rule:     m.rule,
		Tasks:    make(map[uint64]Task, len(m.tasks)),
		Calls:    m.calls,
		Live:     len(m.live),
		Released: append([]string(nil), m.released...),
	}
	for id, t := range m.tasks {
		s.Tasks[id] = *t
	}
	return s
}

// LiveJobs lists the live jobs as tenant/digest pairs.
func (m *Machine) LiveJobs() [][2]string {
	out := make([][2]string, 0, len(m.live))
	for _, j := range m.live {
		out = append(out, [2]string{j.tenant, j.digest})
	}
	return out
}

// JobVerdict returns the planned verdict for a live job. It is what Complete
// will commit.
func (m *Machine) JobVerdict(tenant, digest string, rule int64) Verdict {
	if j := m.live[key(tenant, digest, rule)]; j != nil {
		return j.verdict
	}
	return ""
}

func stateFor(v Verdict) State {
	if v == Clean {
		return CleanS
	}
	return InfectedS
}
