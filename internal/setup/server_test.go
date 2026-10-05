package setup

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/longvo2k/agentguard/internal/policy"
)

func mustPolicy(t *testing.T, yml string) *policy.Policy {
	t.Helper()
	p, err := policy.Parse([]byte(yml))
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func strs(v any) []string {
	var out []string
	for _, x := range v.([]string) {
		out = append(out, x)
	}
	return out
}

func has(list []string, want string) bool {
	for _, s := range list {
		if s == want {
			return true
		}
	}
	return false
}

func TestManagedSettings(t *testing.T) {
	ws := t.TempDir()
	if err := os.Mkdir(filepath.Join(ws, ".git"), 0o755); err != nil {
		t.Fatal(err)
	}
	agent := mustPolicy(t, "role: agent\nfilesystem:\n  read: ['**']\n  write: ['**']\nnetwork:\n  enabled: true\n  allow: [registry.npmjs.org, '*.github.com']\ndeny: [.env*, secrets/**, ~/.ssh/**]\n")
	settings, warnings, err := ManagedSettings(ManagedOptions{
		HookCommand: "/usr/local/bin/agentguard hook claude --server",
		Workspaces:  []ServerWorkspace{{Root: ws, Policy: agent}},
		DenyRead:    []string{"/etc/myapp"},
		SystemDir:   "/etc/agentguard",
		LogDir:      "/var/log/agentguard",
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(warnings) != 0 {
		t.Errorf("unexpected warnings %v", warnings)
	}
	// It must be valid JSON with the keys Claude Code documents.
	data, err := json.Marshal(settings)
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	if err := json.Unmarshal(data, &doc); err != nil {
		t.Fatal(err)
	}
	if doc["allowManagedHooksOnly"] != true {
		t.Error("allowManagedHooksOnly not set")
	}
	pre := doc["hooks"].(map[string]any)["PreToolUse"].([]any)[0].(map[string]any)
	cmd := pre["hooks"].([]any)[0].(map[string]any)["command"]
	if cmd != "/usr/local/bin/agentguard hook claude --server" || !strings.Contains(pre["matcher"].(string), "Bash") {
		t.Errorf("hook entry = %v", pre)
	}
	if doc["permissions"].(map[string]any)["disableBypassPermissionsMode"] != "disable" {
		t.Error("bypass mode not disabled")
	}

	sb := settings["sandbox"].(map[string]any)
	for _, k := range []string{"enabled", "failIfUnavailable"} {
		if sb[k] != true {
			t.Errorf("sandbox.%s = %v", k, sb[k])
		}
	}
	for _, k := range []string{"allowUnsandboxedCommands", "enableWeakerNestedSandbox", "enableWeakerNetworkIsolation"} {
		if sb[k] != false {
			t.Errorf("sandbox.%s = %v", k, sb[k])
		}
	}
	fsys := sb["filesystem"].(map[string]any)
	denyRead, allowRead, denyWrite := strs(fsys["denyRead"]), strs(fsys["allowRead"]), strs(fsys["denyWrite"])
	for _, want := range []string{"/home", "/root", "/srv", "~/.ssh", "~/.claude", "/etc/myapp", ws + "/.env*", ws + "/**/.env*", ws + "/secrets", ws + "/**/*.pem", ws + "/.git/config"} {
		if !has(denyRead, want) {
			t.Errorf("denyRead missing %s", want)
		}
	}
	if !has(allowRead, ws) || !has(allowRead, "~/") {
		t.Errorf("allowRead = %v", allowRead)
	}
	for _, want := range []string{ws + "/.git", "/etc/agentguard", "/var/log/agentguard"} {
		if !has(denyWrite, want) {
			t.Errorf("denyWrite missing %s", want)
		}
	}
	for _, w := range denyWrite {
		if strings.ContainsAny(w, "*?[") {
			t.Errorf("denyWrite has a wildcard, which Linux ignores: %s", w)
		}
	}
	if fsys["allowManagedReadPathsOnly"] != true {
		t.Error("allowManagedReadPathsOnly not set")
	}
	net := sb["network"].(map[string]any)
	if got := strings.Join(net["allowedDomains"].([]string), ","); got != "*.github.com,registry.npmjs.org" {
		t.Errorf("allowedDomains = %s", got)
	}
	if net["allowManagedDomainsOnly"] != true || net["strictAllowlist"] != true {
		t.Error("network allowlist not locked")
	}
}

func TestManagedSettingsWarnings(t *testing.T) {
	open := mustPolicy(t, "role: open\nnetwork:\n  enabled: true\nfilesystem:\n  allow_sensitive: [.env.example]\n")
	settings, warnings, err := ManagedSettings(ManagedOptions{
		HookCommand: "agentguard hook claude --server",
		Workspaces:  []ServerWorkspace{{Root: "/srv/app", Policy: open}},
		SystemDir:   "/etc/agentguard", LogDir: "/var/log/agentguard",
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(warnings) != 2 {
		t.Errorf("warnings = %v", warnings)
	}
	if d := settings["sandbox"].(map[string]any)["network"].(map[string]any)["allowedDomains"].([]string); len(d) != 0 {
		t.Errorf("network without allowlist produced domains %v", d)
	}
}

func TestWriteAndRemoveManagedSettings(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "managed-settings.d")
	t.Setenv("AGENTGUARD_CLAUDE_MANAGED_DIR", dir)
	path, err := WriteManagedSettings(map[string]any{"allowManagedHooksOnly": true})
	if err != nil {
		t.Fatal(err)
	}
	if fi, _ := os.Stat(path); fi.Mode().Perm() != 0o644 {
		t.Errorf("mode %v", fi.Mode().Perm())
	}
	if removed, err := RemoveManagedSettings(); !removed || err != nil {
		t.Errorf("remove: %v %v", removed, err)
	}
	if removed, _ := RemoveManagedSettings(); removed {
		t.Error("second remove reported a file")
	}
}

func TestPrepareLogFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "log", "app.jsonl")
	appendOnly, err := PrepareLogFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if appendOnly {
		t.Cleanup(func() { _ = exec.Command("chattr", "-a", path).Run() })
	}
	fi, err := os.Stat(path)
	if err != nil || fi.Mode().Perm() != 0o622 {
		t.Fatalf("log file %v %v", fi, err)
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_APPEND, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteString("{}\n"); err != nil {
		t.Errorf("append failed: %v", err)
	}
	f.Close()
	if appendOnly {
		// Even root cannot truncate or rewrite an append-only file.
		if err := os.Truncate(path, 0); err == nil {
			t.Error("append-only log could be truncated")
		}
		if err := os.WriteFile(path, []byte("x"), 0o622); err == nil {
			t.Error("append-only log could be rewritten")
		}
	} else {
		t.Log("chattr +a not supported here; append-only protection not tested")
	}
}
