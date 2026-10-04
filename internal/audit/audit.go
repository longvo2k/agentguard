// Package audit records permission decisions as JSON Lines and summarizes
// them. The log lives in .agentguard/, which is never mounted into a
// sandbox, so an agent cannot read or rewrite its own history.
package audit

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/longvo2k/agentguard/internal/policy"
)

// Entry is one line of the audit log.
type Entry struct {
	Timestamp time.Time `json:"timestamp"`
	Role      string    `json:"role"`
	Action    string    `json:"action"`
	Resource  string    `json:"resource"`
	Path      string    `json:"path,omitempty"` // workspace-relative, for filesystem actions
	Decision  string    `json:"decision"`       // "allow" or "deny"
	Reason    string    `json:"reason,omitempty"`
	Rule      string    `json:"rule,omitempty"`
	Source    string    `json:"source,omitempty"` // check, run, sandbox, demo
}

// FromDecision converts a policy decision into an audit entry.
func FromDecision(d policy.Decision, source string) Entry {
	verdict := "deny"
	if d.Allowed {
		verdict = "allow"
	}
	return Entry{
		Timestamp: time.Now().UTC(),
		Role:      d.Role,
		Action:    string(d.Action),
		Resource:  d.Resource,
		Path:      d.Path,
		Decision:  verdict,
		Reason:    d.Reason,
		Rule:      d.Rule,
		Source:    source,
	}
}

// Display is the resource as shown to people: the workspace-relative path
// when known, otherwise what was requested.
func (e Entry) Display() string {
	if e.Path != "" && e.Path != e.Resource {
		return e.Path
	}
	return e.Resource
}

// Logger appends entries to a JSONL file.
type Logger struct {
	mu   sync.Mutex
	path string
	err  error
}

// NewLogger returns a logger writing to path. The file is created on first
// write with 0600 permissions.
func NewLogger(path string) *Logger { return &Logger{path: path} }

// Path returns the log file location.
func (l *Logger) Path() string { return l.path }

// Log appends one entry.
func (l *Logger) Log(e Entry) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if err := os.MkdirAll(filepath.Dir(l.path), 0o700); err != nil {
		return l.fail(err)
	}
	f, err := os.OpenFile(l.path, os.O_WRONLY|os.O_APPEND|os.O_CREATE, 0o600)
	if err != nil {
		return l.fail(err)
	}
	defer f.Close()
	line, err := json.Marshal(e)
	if err != nil {
		return l.fail(err)
	}
	if _, err := f.Write(append(line, '\n')); err != nil {
		return l.fail(err)
	}
	return nil
}

func (l *Logger) fail(err error) error {
	if l.err == nil {
		l.err = err
	}
	return err
}

// Err returns the first write error, if any. Callers that log through an
// observer callback use it to fail closed when auditing breaks.
func (l *Logger) Err() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.err
}

// Observer returns a function suitable for policy.Engine.SetObserver.
func (l *Logger) Observer(source string) func(policy.Decision) {
	return func(d policy.Decision) { _ = l.Log(FromDecision(d, source)) }
}

// ReadFile parses an audit log. A missing file yields no entries.
func ReadFile(path string) ([]Entry, error) {
	f, err := os.Open(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return Read(f)
}

// Read parses JSONL entries from r.
func Read(r io.Reader) ([]Entry, error) {
	var out []Entry
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 64*1024), 1024*1024)
	n := 0
	for sc.Scan() {
		n++
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		var e Entry
		if err := json.Unmarshal([]byte(line), &e); err != nil {
			return out, fmt.Errorf("audit log line %d: %w", n, err)
		}
		out = append(out, e)
	}
	return out, sc.Err()
}

// Summary aggregates entries for display.
type Summary struct {
	Total, Allowed, Denied int
	First, Last            time.Time
	ByRole                 map[string][2]int // role -> [allowed, denied]
	ByAction               map[string][2]int
	TopDenied              []Count
}

// Count is a resource with how often it was denied.
type Count struct {
	Key string
	N   int
}

// Summarize computes a Summary over entries.
func Summarize(entries []Entry) Summary {
	s := Summary{ByRole: map[string][2]int{}, ByAction: map[string][2]int{}}
	denied := map[string]int{}
	for _, e := range entries {
		s.Total++
		idx := 1
		if e.Decision == "allow" {
			s.Allowed++
			idx = 0
		} else {
			s.Denied++
			denied[e.Action+" "+e.Display()]++
		}
		r := s.ByRole[e.Role]
		r[idx]++
		s.ByRole[e.Role] = r
		a := s.ByAction[e.Action]
		a[idx]++
		s.ByAction[e.Action] = a
		if s.First.IsZero() || e.Timestamp.Before(s.First) {
			s.First = e.Timestamp
		}
		if e.Timestamp.After(s.Last) {
			s.Last = e.Timestamp
		}
	}
	for k, n := range denied {
		s.TopDenied = append(s.TopDenied, Count{k, n})
	}
	sort.Slice(s.TopDenied, func(i, j int) bool {
		if s.TopDenied[i].N != s.TopDenied[j].N {
			return s.TopDenied[i].N > s.TopDenied[j].N
		}
		return s.TopDenied[i].Key < s.TopDenied[j].Key
	})
	return s
}

// Print writes a human-readable report: a summary plus the last tail entries.
func Print(w io.Writer, entries []Entry, tail int) {
	s := Summarize(entries)
	if s.Total == 0 {
		fmt.Fprintln(w, "No audit entries yet.")
		return
	}
	fmt.Fprintf(w, "Audit summary: %d decisions (%d allowed, %d denied)\n", s.Total, s.Allowed, s.Denied)
	fmt.Fprintf(w, "Period: %s → %s\n\n", s.First.Local().Format(time.DateTime), s.Last.Local().Format(time.DateTime))

	printTable(w, "By role", s.ByRole)
	printTable(w, "By action", s.ByAction)

	if len(s.TopDenied) > 0 {
		fmt.Fprintln(w, "Most denied:")
		for i, c := range s.TopDenied {
			if i == 10 {
				break
			}
			fmt.Fprintf(w, "  %4d× %s\n", c.N, c.Key)
		}
		fmt.Fprintln(w)
	}

	if tail > 0 {
		start := len(entries) - tail
		if start < 0 {
			start = 0
		}
		fmt.Fprintf(w, "Last %d decisions:\n", len(entries)-start)
		for _, e := range entries[start:] {
			mark := "✓"
			if e.Decision != "allow" {
				mark = "✗"
			}
			line := fmt.Sprintf("  %s %s  %-10s %-8s %s", mark, e.Timestamp.Local().Format("15:04:05"), e.Role, e.Action, e.Display())
			if e.Decision != "allow" && e.Reason != "" {
				line += "  (" + e.Reason + ")"
			}
			fmt.Fprintln(w, line)
		}
	}
}

func printTable(w io.Writer, title string, m map[string][2]int) {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	fmt.Fprintf(w, "%s:\n", title)
	for _, k := range keys {
		fmt.Fprintf(w, "  %-12s %5d allowed  %5d denied\n", k, m[k][0], m[k][1])
	}
	fmt.Fprintln(w)
}
