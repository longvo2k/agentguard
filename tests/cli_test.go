// Package tests holds end-to-end tests that build and run the agentguard
// binary.
package tests

import (
	"bytes"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

var binary string

func TestMain(m *testing.M) {
	dir, err := os.MkdirTemp("", "agentguard-e2e-")
	if err != nil {
		panic(err)
	}
	binary = filepath.Join(dir, "agentguard")
	build := exec.Command("go", "build", "-o", binary, "../cmd/agentguard")
	build.Stderr = os.Stderr
	if err := build.Run(); err != nil {
		panic("build failed: " + err.Error())
	}
	code := m.Run()
	os.RemoveAll(dir)
	os.Exit(code)
}

// isolate gives the test its own home, AgentGuard and Claude directories so
// nothing touches the real user's files and tests do not see each other.
func isolate(t *testing.T) string {
	t.Helper()
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("AGENTGUARD_HOME", filepath.Join(home, "agentguard"))
	t.Setenv("CLAUDE_CONFIG_DIR", filepath.Join(home, ".claude"))
	for _, v := range []string{"XDG_CONFIG_HOME", "XDG_STATE_HOME", "XDG_CACHE_HOME", "AGENTGUARD_ROLE"} {
		t.Setenv(v, "")
	}
	return home
}

func agentguard(t *testing.T, dir string, args ...string) (string, int) {
	t.Helper()
	return agentguardIn(t, dir, "", args...)
}

func agentguardIn(t *testing.T, dir, stdin string, args ...string) (string, int) {
	t.Helper()
	cmd := exec.Command(binary, args...)
	cmd.Dir = dir
	cmd.Stdin = strings.NewReader(stdin)
	var out bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &out
	err := cmd.Run()
	code := 0
	if exit, ok := err.(*exec.ExitError); ok {
		code = exit.ExitCode()
	} else if err != nil {
		t.Fatal(err)
	}
	return out.String(), code
}

func project(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	for name, body := range map[string]string{
		"src/app.js":          "console.log(1)\n",
		"tests/app.test.js":   "",
		"logs/app.log":        "x\n",
		".env":                "SECRET=1\n",
		"secrets/api-key.txt": "sk\n",
	} {
		p := filepath.Join(dir, name)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

func TestNotInitialized(t *testing.T) {
	isolate(t)
	out, code := agentguard(t, t.TempDir(), "check", "read", "src/app.js")
	if code != 2 || !strings.Contains(out, "agentguard setup") {
		t.Fatalf("code=%d out=%s", code, out)
	}
}

func TestInitCheckAudit(t *testing.T) {
	isolate(t)
	dir := project(t)
	if out, code := agentguard(t, dir, "init"); code != 0 || !strings.Contains(out, "developer.yaml") {
		t.Fatalf("init: %d %s", code, out)
	}

	cases := []struct {
		args []string
		code int
	}{
		{[]string{"check", "read", "src/app.js"}, 0},
		{[]string{"check", "write", "src/app.js"}, 0},
		{[]string{"check", "read", ".env"}, 1},
		{[]string{"check", "read", "secrets/api-key.txt"}, 1},
		{[]string{"check", "read", "src/../.env"}, 1},
		{[]string{"check", "read", "../../etc/passwd"}, 1},
		{[]string{"check", "execute", "npm"}, 0},
		{[]string{"check", "execute", "curl"}, 1},
		{[]string{"check", "network"}, 1},
		{[]string{"check", "--role", "tester", "write", "src/app.js"}, 1},
		{[]string{"check", "write", "tests/x.test.js", "--role", "tester"}, 0},
		{[]string{"check", "--role", "reviewer", "write", "tests/x.test.js"}, 1},
		{[]string{"check", "--role", "reviewer", "execute", "git"}, 0},
		{[]string{"check", "--role", "../../etc", "read", "src/app.js"}, 2},
		{[]string{"check", "--role", "nobody", "read", "src/app.js"}, 2},
		{[]string{"check", "delete", "src/app.js"}, 2},
		{[]string{"check", "read"}, 2},
	}
	for _, c := range cases {
		out, code := agentguard(t, dir, c.args...)
		if code != c.code {
			t.Errorf("%v: exit %d, want %d\n%s", c.args, code, c.code, out)
		}
	}

	out, code := agentguard(t, dir, "check", "--json", "read", ".env")
	var d map[string]string
	if err := json.Unmarshal([]byte(out), &d); err != nil || code != 1 || d["decision"] != "deny" || d["rule"] != "deny: .env*" {
		t.Errorf("json check: %d %s", code, out)
	}

	out, code = agentguard(t, dir, "audit")
	if code != 0 || !strings.Contains(out, "denied") || !strings.Contains(out, "read .env") {
		t.Errorf("audit: %d %s", code, out)
	}
	out, _ = agentguard(t, dir, "audit", "--json", "--denied")
	lines := strings.Split(strings.TrimSpace(out), "\n")
	for _, l := range lines {
		var e map[string]any
		if err := json.Unmarshal([]byte(l), &e); err != nil || e["decision"] != "deny" {
			t.Errorf("bad audit line %q", l)
		}
	}
	if len(lines) < 8 {
		t.Errorf("expected at least 8 denied entries, got %d", len(lines))
	}

	// Checks from a subdirectory find the workspace.
	if _, code := agentguard(t, filepath.Join(dir, "src"), "check", "read", "app.js"); code != 1 {
		// Paths are relative to the workspace root, not the current directory.
		t.Errorf("relative-to-root semantics changed (exit %d)", code)
	}
	if _, code := agentguard(t, filepath.Join(dir, "src"), "check", "read", "src/app.js"); code != 0 {
		t.Errorf("check from subdirectory failed (exit %d)", code)
	}
}

func TestRunDryRunAndDeniedCommand(t *testing.T) {
	isolate(t)
	dir := project(t)
	agentguard(t, dir, "init")
	out, code := agentguard(t, dir, "run", "--dry-run", "--", "npm", "test")
	if code != 0 {
		t.Fatalf("dry run: %d %s", code, out)
	}
	for _, want := range []string{"--network none", "--cap-drop ALL", "--read-only", "target=/workspace/src", "target=/workspace/logs,readonly"} {
		if !strings.Contains(out, want) {
			t.Errorf("dry run missing %q:\n%s", want, out)
		}
	}
	for _, bad := range []string{"target=/workspace/.env", "secrets", "docker.sock", "/workspace/.agentguard"} {
		if strings.Contains(out, bad) {
			t.Errorf("dry run contains %q:\n%s", bad, out)
		}
	}

	out, code = agentguard(t, dir, "run", "--", "curl", "https://example.com")
	if code != 126 || !strings.Contains(out, "not in commands.allow") {
		t.Errorf("curl: %d %s", code, out)
	}
	out, code = agentguard(t, dir, "run", "--", "/usr/bin/npm")
	if code != 126 {
		t.Errorf("absolute path: %d %s", code, out)
	}
	if out, code := agentguard(t, dir, "run"); code != 2 {
		t.Errorf("run without command: %d %s", code, out)
	}
}

func TestDemoPolicyOnly(t *testing.T) {
	isolate(t)
	out, code := agentguard(t, t.TempDir(), "demo", "--no-docker")
	if code != 0 {
		t.Fatalf("demo: %d %s", code, out)
	}
	for _, want := range []string{"✓ ALLOW read     src/app.js", "✗ DENY  read     .env", "✗ DENY  read     secrets/api-key.txt", "✗ DENY  execute  curl", "decisions recorded"} {
		if !strings.Contains(out, want) {
			t.Errorf("demo output missing %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, "UNEXPECTED") {
		t.Error(out)
	}
}

// TestDemoWithDocker runs the full demo, including the container. It needs a
// Docker daemon and the sandbox image (or AGENTGUARD_TEST_IMAGE).
func TestDemoWithDocker(t *testing.T) {
	if testing.Short() {
		t.Skip("-short")
	}
	if err := exec.Command("docker", "version").Run(); err != nil {
		t.Skip("Docker not available")
	}
	isolate(t)
	args := []string{"demo"}
	if img := os.Getenv("AGENTGUARD_TEST_IMAGE"); img != "" {
		args = append(args, "--image", img)
	}
	out, code := agentguard(t, t.TempDir(), args...)
	if code != 0 {
		t.Fatalf("demo: %d\n%s", code, out)
	}
	for _, want := range []string{"✓ Read src/app.js", "✓ Write src/app.js", "✓ Execute npm", "✗ Read .env", "✗ Read secrets/api-key.txt", "✗ Execute curl", "no network"} {
		if !strings.Contains(out, want) {
			t.Errorf("demo output missing %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, "!!") {
		t.Errorf("sandbox misbehaved:\n%s", out)
	}
}

func hookEvent(cwd, tool string, input map[string]any) string {
	data, _ := json.Marshal(map[string]any{
		"session_id": "test", "hook_event_name": "PreToolUse", "cwd": cwd,
		"tool_name": tool, "tool_input": input,
	})
	return string(data)
}

func TestSetupHookAndUninstall(t *testing.T) {
	home := isolate(t)
	claudeDir := filepath.Join(home, ".claude")
	if err := os.MkdirAll(claudeDir, 0o700); err != nil {
		t.Fatal(err)
	}
	settings := filepath.Join(claudeDir, "settings.json")
	if err := os.WriteFile(settings, []byte(`{"model":"opus"}`), 0o600); err != nil {
		t.Fatal(err)
	}

	// Without setup, the hook stays out of the way.
	dir := project(t)
	if _, code := agentguardIn(t, dir, hookEvent(dir, "Read", map[string]any{"file_path": filepath.Join(dir, ".env")}), "hook", "claude"); code != 0 {
		t.Fatalf("hook without setup blocked a call (exit %d)", code)
	}

	// Without --yes and without a terminal, setup changes nothing it should ask about.
	out, code := agentguard(t, dir, "setup", "--skip-image")
	if code != 0 || !strings.Contains(out, "rerun with --yes") {
		t.Fatalf("setup without --yes: %d %s", code, out)
	}
	if data, _ := os.ReadFile(settings); strings.Contains(string(data), "agentguard") {
		t.Fatal("hook installed without confirmation")
	}

	out, code = agentguard(t, dir, "setup", "--yes", "--skip-image")
	if code != 0 || !strings.Contains(out, "Claude Code hook installed") {
		t.Fatalf("setup: %d %s", code, out)
	}
	data, _ := os.ReadFile(settings)
	if !strings.Contains(string(data), binary+" hook claude") || !strings.Contains(string(data), `"opus"`) {
		t.Fatalf("settings after setup:\n%s", data)
	}

	// Any project is now covered by the user-level "agent" role.
	if err := os.WriteFile(filepath.Join(dir, "README.md"), []byte("hi"), 0o644); err != nil {
		t.Fatal(err)
	}
	checks := []struct {
		args []string
		code int
	}{
		{[]string{"check", "read", "README.md"}, 0},
		{[]string{"check", "write", "src/app.js"}, 0},
		{[]string{"check", "read", ".env"}, 1},
		{[]string{"check", "write", ".git/hooks/pre-commit"}, 1},
		{[]string{"check", "write", ".claude/settings.json"}, 1},
		{[]string{"check", "execute", "curl"}, 1},
	}
	for _, c := range checks {
		if out, code := agentguard(t, dir, c.args...); code != c.code {
			t.Errorf("%v: exit %d want %d\n%s", c.args, code, c.code, out)
		}
	}

	hooks := []struct {
		tool  string
		input map[string]any
		code  int
	}{
		{"Read", map[string]any{"file_path": filepath.Join(dir, "src/app.js")}, 0},
		{"Read", map[string]any{"file_path": filepath.Join(dir, ".env")}, 2},
		{"Bash", map[string]any{"command": "npm test && cat .env"}, 2},
		{"Bash", map[string]any{"command": "git status"}, 0},
		{"Edit", map[string]any{"file_path": settings}, 2},
		{"WebFetch", map[string]any{"url": "https://example.com"}, 2},
	}
	for _, h := range hooks {
		out, code := agentguardIn(t, dir, hookEvent(dir, h.tool, h.input), "hook", "claude")
		if code != h.code {
			t.Errorf("hook %s %v: exit %d want %d\n%s", h.tool, h.input, code, h.code, out)
		}
		if code == 2 && !strings.Contains(out, "AgentGuard blocked") {
			t.Errorf("hook denial without explanation: %s", out)
		}
	}
	if out, code := agentguardIn(t, dir, "garbage", "hook", "claude"); code != 2 {
		t.Errorf("malformed hook input allowed: %d %s", code, out)
	}

	// Audit entries for the project live in the user state dir.
	out, _ = agentguard(t, dir, "audit", "--denied", "--json")
	if !strings.Contains(out, `"source":"hook"`) || !strings.Contains(out, `"path":".env"`) {
		t.Errorf("hook decisions not audited:\n%s", out)
	}
	if _, err := os.Stat(filepath.Join(dir, ".agentguard")); err == nil {
		t.Error("user-level mode wrote into the project")
	}

	if out, code := agentguard(t, dir, "doctor"); code != 0 || !strings.Contains(out, "Claude Code hook installed") {
		t.Errorf("doctor: %d\n%s", code, out)
	}

	out, code = agentguard(t, dir, "setup", "--uninstall", "--purge", "--yes")
	if code != 0 {
		t.Fatalf("uninstall: %d %s", code, out)
	}
	data, _ = os.ReadFile(settings)
	if strings.Contains(string(data), "agentguard") || !strings.Contains(string(data), "opus") {
		t.Errorf("settings after uninstall:\n%s", data)
	}
	if _, err := os.Stat(filepath.Join(home, "agentguard", "config")); err == nil {
		t.Error("purge left user config behind")
	}
}

func TestTrustFlow(t *testing.T) {
	isolate(t)
	dir := project(t)
	if _, code := agentguard(t, dir, "init"); code != 0 {
		t.Fatal("init failed")
	}
	if _, code := agentguard(t, dir, "check", "read", "src/app.js"); code != 0 {
		t.Fatal("freshly initialized project not trusted")
	}
	// Someone (or something) loosens the policy.
	pol := filepath.Join(dir, ".agentguard/policies/developer.yaml")
	data, _ := os.ReadFile(pol)
	if err := os.WriteFile(pol, []byte(strings.Replace(string(data), "enabled: false", "enabled: true", 1)), 0o600); err != nil {
		t.Fatal(err)
	}
	out, code := agentguard(t, dir, "check", "network")
	if code != 2 || !strings.Contains(out, "changed since they were trusted") {
		t.Fatalf("changed policy used without review: %d %s", code, out)
	}
	out, code = agentguard(t, dir, "trust")
	if code != 0 || !strings.Contains(out, "developer") {
		t.Fatalf("trust: %d %s", code, out)
	}
	if _, code := agentguard(t, dir, "check", "network"); code != 0 {
		t.Error("reviewed policy not applied")
	}
	// A cloned repository's policies are not trusted until reviewed.
	clone := t.TempDir()
	if err := exec.Command("cp", "-r", filepath.Join(dir, ".agentguard"), clone).Run(); err != nil {
		t.Fatal(err)
	}
	if out, code := agentguard(t, clone, "check", "read", "src/app.js"); code != 2 || !strings.Contains(out, "not created by `agentguard init`") {
		t.Errorf("foreign .agentguard accepted: %d %s", code, out)
	}
}
