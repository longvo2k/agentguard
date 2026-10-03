package audit

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/longvo2k/agentguard/internal/policy"
)

func TestLogAndRead(t *testing.T) {
	path := filepath.Join(t.TempDir(), "nested", "audit.jsonl")
	l := NewLogger(path)
	obs := l.Observer("check")
	obs(policy.Decision{Role: "developer", Action: policy.ActionRead, Resource: "src/app.js", Allowed: true, Rule: "filesystem.read: src/**"})
	obs(policy.Decision{Role: "developer", Action: policy.ActionRead, Resource: ".env", Reason: "matches deny rule"})
	obs(policy.Decision{Role: "developer", Action: policy.ActionExecute, Resource: "npm", Allowed: true})
	if err := l.Err(); err != nil {
		t.Fatal(err)
	}

	fi, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0o600 {
		t.Errorf("audit log mode = %v, want 0600", fi.Mode().Perm())
	}

	data, _ := os.ReadFile(path)
	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	if len(lines) != 3 {
		t.Fatalf("got %d lines", len(lines))
	}
	var first map[string]any
	if err := json.Unmarshal([]byte(lines[0]), &first); err != nil {
		t.Fatal(err)
	}
	for _, k := range []string{"timestamp", "role", "action", "resource", "decision"} {
		if _, ok := first[k]; !ok {
			t.Errorf("missing key %q in %s", k, lines[0])
		}
	}

	entries, err := ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if entries[1].Decision != "deny" || entries[1].Resource != ".env" {
		t.Errorf("unexpected entry %+v", entries[1])
	}

	s := Summarize(entries)
	if s.Total != 3 || s.Allowed != 2 || s.Denied != 1 {
		t.Errorf("summary = %+v", s)
	}
	if s.ByRole["developer"] != [2]int{2, 1} {
		t.Errorf("by role = %v", s.ByRole)
	}

	var buf bytes.Buffer
	Print(&buf, entries, 5)
	out := buf.String()
	for _, want := range []string{"3 decisions", "2 allowed", "1 denied", "read .env", "✗"} {
		if !strings.Contains(out, want) {
			t.Errorf("report missing %q:\n%s", want, out)
		}
	}
}

func TestReadMissingFile(t *testing.T) {
	entries, err := ReadFile(filepath.Join(t.TempDir(), "nope.jsonl"))
	if err != nil || entries != nil {
		t.Fatalf("got %v, %v", entries, err)
	}
	var buf bytes.Buffer
	Print(&buf, nil, 10)
	if !strings.Contains(buf.String(), "No audit entries") {
		t.Error(buf.String())
	}
}

func TestReadCorruptLine(t *testing.T) {
	_, err := Read(strings.NewReader("{\"role\":\"a\"}\nnot json\n"))
	if err == nil || !strings.Contains(err.Error(), "line 2") {
		t.Fatalf("err = %v", err)
	}
}

func TestLoggerReportsWriteFailure(t *testing.T) {
	dir := t.TempDir()
	// A directory where the file should be makes the write fail.
	path := filepath.Join(dir, "audit.jsonl")
	if err := os.Mkdir(path, 0o700); err != nil {
		t.Fatal(err)
	}
	l := NewLogger(path)
	l.Observer("check")(policy.Decision{Role: "r", Action: policy.ActionRead, Resource: "x"})
	if l.Err() == nil {
		t.Fatal("expected write error")
	}
}
