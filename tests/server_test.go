package tests

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// Server mode needs root (it writes root-owned files) and setpriv (to run
// the hook as an unprivileged agent user). The system paths are redirected
// into a temp directory, so nothing outside it is touched; in particular the
// real /etc/claude-code is never written.
type serverFixture struct {
	t                         *testing.T
	base, app, other, sysDir  string
	logDir, managed, bin, env string
}

func newServerFixture(t *testing.T) *serverFixture {
	t.Helper()
	if os.Geteuid() != 0 {
		t.Skip("server mode tests need root")
	}
	if _, err := exec.LookPath("setpriv"); err != nil {
		t.Skip("setpriv not available")
	}
	isolate(t)
	base, err := os.MkdirTemp("", "agsrv-")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(base, 0o755); err != nil {
		t.Fatal(err)
	}
	f := &serverFixture{
		t: t, base: base,
		app: filepath.Join(base, "srv", "app"), other: filepath.Join(base, "srv", "other"),
		sysDir: filepath.Join(base, "etc", "agentguard"), logDir: filepath.Join(base, "log"),
		managed: filepath.Join(base, "etc", "claude-code", "managed-settings.d"),
		bin:     filepath.Join(base, "bin", "agentguard"),
	}
	t.Cleanup(func() {
		logs, _ := filepath.Glob(filepath.Join(f.logDir, "*.jsonl"))
		if len(logs) > 0 {
			_ = exec.Command("chattr", append([]string{"-a"}, logs...)...).Run()
		}
		os.RemoveAll(base)
	})
	for name, body := range map[string]string{
		"srv/app/src/app.js":    "console.log(1)\n",
		"srv/app/.env":          "DB_PASS=x\n",
		"srv/app/.git/HEAD":     "ref: refs/heads/main\n",
		"srv/other/secret.txt":  "other team's secret\n",
		"srv/app/.agentguard/x": "", // a project-level config the agent could have planted
	} {
		p := filepath.Join(base, name)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("AGENTGUARD_SYSTEM_DIR", f.sysDir)
	t.Setenv("AGENTGUARD_LOG_DIR", f.logDir)
	t.Setenv("AGENTGUARD_CLAUDE_MANAGED_DIR", f.managed)
	t.Setenv("AGENTGUARD_SERVER_BIN", f.bin)
	return f
}

// hookAs runs the installed hook as uid 1000 with a PreToolUse event.
func (f *serverFixture) hookAs(uid int, cwd, tool string, input map[string]any) (string, int) {
	f.t.Helper()
	args := []string{f.bin, "hook", "claude", "--server"}
	if uid != 0 {
		args = append([]string{fmt.Sprintf("--reuid=%d", uid), fmt.Sprintf("--regid=%d", uid), "--clear-groups"}, args...)
		args = append([]string{"setpriv"}, args...)
	}
	cmd := exec.Command(args[0], args[1:]...)
	cmd.Dir = "/"
	// Whoever starts Claude Code must not be able to pick a looser role.
	cmd.Env = append(os.Environ(), "AGENTGUARD_ROLE=careless", "HOME=/nonexistent")
	cmd.Stdin = strings.NewReader(hookEvent(cwd, tool, input))
	out, err := cmd.CombinedOutput()
	code := 0
	if exit, ok := err.(*exec.ExitError); ok {
		code = exit.ExitCode()
	} else if err != nil {
		f.t.Fatal(err)
	}
	return string(out), code
}

func TestServerMode(t *testing.T) {
	f := newServerFixture(t)
	out, code := agentguard(t, f.base, "setup", "--server", "--yes",
		"--workspace", f.app, "--allow-domain", "registry.npmjs.org", "--allow-domain", "*.github.com")
	if code != 0 {
		t.Fatalf("setup --server: %d\n%s", code, out)
	}

	// Managed settings: the hook, its lock, and the enforced sandbox.
	data, err := os.ReadFile(filepath.Join(f.managed, "50-agentguard.json"))
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal(data, &m); err != nil {
		t.Fatalf("managed settings are not valid JSON: %v", err)
	}
	sb := m["sandbox"].(map[string]any)
	if m["allowManagedHooksOnly"] != true || sb["enabled"] != true || sb["failIfUnavailable"] != true || sb["allowUnsandboxedCommands"] != false {
		t.Errorf("managed settings not locked down:\n%s", data)
	}
	if !strings.Contains(string(data), f.bin+" hook claude --server") {
		t.Errorf("managed hook does not run the installed binary:\n%s", data)
	}
	realApp, _ := filepath.EvalSymlinks(f.app)
	for _, want := range []string{realApp + "/**/.env*", realApp + "/.git", "registry.npmjs.org"} {
		if !strings.Contains(string(data), want) {
			t.Errorf("managed settings missing %q", want)
		}
	}

	// The agent, as uid 1000.
	cases := []struct {
		name, cwd, tool string
		input           map[string]any
		code            int
	}{
		{"read in workspace", f.app, "Read", map[string]any{"file_path": filepath.Join(f.app, "src/app.js")}, 0},
		{"edit in workspace", f.app, "Edit", map[string]any{"file_path": filepath.Join(f.app, "src/app.js")}, 0},
		{"read .env", f.app, "Read", map[string]any{"file_path": filepath.Join(f.app, ".env")}, 2},
		{"cat .env", f.app, "Bash", map[string]any{"command": "cat .env"}, 2},
		{"read other project", f.app, "Read", map[string]any{"file_path": filepath.Join(f.other, "secret.txt")}, 2},
		{"edit system policy", f.app, "Edit", map[string]any{"file_path": filepath.Join(f.sysDir, "policies/agent.yaml")}, 2},
		{"fetch allowed host", f.app, "WebFetch", map[string]any{"url": "https://registry.npmjs.org/x"}, 0},
		{"fetch other host", f.app, "WebFetch", map[string]any{"url": "https://evil.example.com/"}, 2},
		{"cwd outside workspaces", f.other, "Read", map[string]any{"file_path": filepath.Join(f.other, "secret.txt")}, 2},
		{"cwd /", "/", "Bash", map[string]any{"command": "ls"}, 2},
	}
	for _, c := range cases {
		if out, code := f.hookAs(1000, c.cwd, c.tool, c.input); code != c.code {
			t.Errorf("%s: exit %d want %d\n%s", c.name, code, c.code, out)
		}
	}

	// As root, everything is blocked.
	if out, code := f.hookAs(0, f.app, "Read", map[string]any{"file_path": filepath.Join(f.app, "src/app.js")}); code != 2 || !strings.Contains(out, "root") {
		t.Errorf("root not blocked: %d %s", code, out)
	}

	// Decisions are logged, including refusals outside every workspace.
	wsLog, _ := filepath.Glob(filepath.Join(f.logDir, "app-*.jsonl"))
	if len(wsLog) != 1 {
		t.Fatalf("workspace logs = %v", wsLog)
	}
	logData, _ := os.ReadFile(wsLog[0])
	if !strings.Contains(string(logData), `"path":".env"`) || !strings.Contains(string(logData), `"role":"agent"`) {
		t.Errorf("workspace log:\n%s", logData)
	}
	serverLog, _ := os.ReadFile(filepath.Join(f.logDir, "server.jsonl"))
	if !strings.Contains(string(serverLog), "outside the workspaces") || !strings.Contains(string(serverLog), "running as root") {
		t.Errorf("server log:\n%s", serverLog)
	}

	// The agent's user cannot tamper with the log or the policy.
	for _, sh := range []string{
		"truncate -s0 " + wsLog[0],
		"echo x > " + wsLog[0],
		"echo x >> " + filepath.Join(f.sysDir, "policies", "agent.yaml"),
		"rm -f " + filepath.Join(f.sysDir, "config.yaml"),
	} {
		cmd := exec.Command("setpriv", "--reuid=1000", "--regid=1000", "--clear-groups", "sh", "-c", sh)
		if err := cmd.Run(); err == nil {
			t.Errorf("agent user could run %q", sh)
		}
	}

	// A configuration that is no longer root-only blocks everything.
	pol := filepath.Join(f.sysDir, "policies", "agent.yaml")
	if err := os.Chmod(pol, 0o666); err != nil {
		t.Fatal(err)
	}
	if out, code := f.hookAs(1000, f.app, "Read", map[string]any{"file_path": filepath.Join(f.app, "src/app.js")}); code != 2 || !strings.Contains(out, "writable") {
		t.Errorf("tampered config not refused: %d %s", code, out)
	}
	if err := os.Chmod(pol, 0o644); err != nil {
		t.Fatal(err)
	}

	// check --server answers with the workspace's role.
	if out, code := agentguard(t, f.app, "check", "--server", "read", ".env"); code != 1 {
		t.Errorf("check --server read .env: %d %s", code, out)
	}
	if out, code := agentguard(t, f.app, "check", "--server", "--role", "x", "read", ".env"); code != 2 {
		t.Errorf("check --server --role accepted: %d %s", code, out)
	}

	// doctor --server reports the installation (bubblewrap may be missing here).
	out, _ = agentguard(t, f.app, "doctor", "--server")
	for _, want := range []string{"System configuration", "managed settings", "Hook binary"} {
		if !strings.Contains(out, want) {
			t.Errorf("doctor --server missing %q:\n%s", want, out)
		}
	}

	out, code = agentguard(t, f.base, "setup", "--server", "--uninstall", "--purge", "--yes")
	if code != 0 {
		t.Fatalf("uninstall: %d %s", code, out)
	}
	for _, p := range []string{filepath.Join(f.managed, "50-agentguard.json"), f.sysDir, f.logDir} {
		if _, err := os.Stat(p); err == nil {
			t.Errorf("%s still exists after uninstall --purge", p)
		}
	}
}

func TestServerSetupNeedsRoot(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("running as root")
	}
	isolate(t)
	out, code := agentguard(t, t.TempDir(), "setup", "--server", "--workspace", t.TempDir(), "--yes")
	if code == 0 || !strings.Contains(out, "sudo") {
		t.Errorf("server setup without root: %d %s", code, out)
	}
}
