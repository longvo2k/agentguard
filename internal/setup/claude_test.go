package setup

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func read(t *testing.T, path string) map[string]any {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal(data, &m); err != nil {
		t.Fatal(err)
	}
	return m
}

func TestInstallIntoMissingFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), ".claude", "settings.json")
	cmd := HookCommand("/usr/local/bin/agentguard", false)
	changed, err := InstallClaudeHook(path, cmd)
	if err != nil || !changed {
		t.Fatalf("changed=%v err=%v", changed, err)
	}
	got, ok := ClaudeHookInstalled(path)
	if !ok || got != "/usr/local/bin/agentguard hook claude" {
		t.Errorf("installed = %q %v", got, ok)
	}
	fi, _ := os.Stat(path)
	if fi.Mode().Perm() != 0o600 {
		t.Errorf("mode = %v", fi.Mode().Perm())
	}
	// Installing again is a no-op.
	if changed, err := InstallClaudeHook(path, cmd); err != nil || changed {
		t.Errorf("second install: changed=%v err=%v", changed, err)
	}
}

func TestInstallPreservesOtherSettings(t *testing.T) {
	path := filepath.Join(t.TempDir(), "settings.json")
	orig := `{
  "model": "opus",
  "permissions": {"allow": ["Bash(npm test)"]},
  "hooks": {
    "PreToolUse": [{"matcher": "Bash", "hooks": [{"type": "command", "command": "my-linter"}]}],
    "Stop": [{"hooks": [{"type": "command", "command": "notify"}]}]
  }
}`
	if err := os.WriteFile(path, []byte(orig), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := InstallClaudeHook(path, HookCommand("/opt/ag/agentguard", false)); err != nil {
		t.Fatal(err)
	}
	m := read(t, path)
	if m["model"] != "opus" || m["permissions"] == nil {
		t.Errorf("settings lost: %v", m)
	}
	hooks := m["hooks"].(map[string]any)
	if hooks["Stop"] == nil {
		t.Error("Stop hook lost")
	}
	pre := hooks["PreToolUse"].([]any)
	if len(pre) != 2 {
		t.Fatalf("PreToolUse = %v", pre)
	}
	if fi, _ := os.Stat(path); fi.Mode().Perm() != 0o644 {
		t.Errorf("file mode changed to %v", fi.Mode().Perm())
	}
	if backup, err := os.ReadFile(path + ".agentguard-backup"); err != nil || string(backup) != orig {
		t.Errorf("backup missing or wrong: %v", err)
	}

	// Moving the binary updates the existing entry instead of adding one.
	if changed, _ := InstallClaudeHook(path, HookCommand("/new/place/agentguard", false)); !changed {
		t.Error("expected update")
	}
	pre = read(t, path)["hooks"].(map[string]any)["PreToolUse"].([]any)
	if len(pre) != 2 {
		t.Errorf("duplicate entry added: %v", pre)
	}
	if got, _ := ClaudeHookInstalled(path); got != "/new/place/agentguard hook claude" {
		t.Errorf("command = %q", got)
	}

	// Uninstall removes only our entry.
	if changed, err := UninstallClaudeHook(path); err != nil || !changed {
		t.Fatalf("uninstall changed=%v err=%v", changed, err)
	}
	m = read(t, path)
	pre = m["hooks"].(map[string]any)["PreToolUse"].([]any)
	if len(pre) != 1 || m["model"] != "opus" {
		t.Errorf("after uninstall: %v", m)
	}
	if _, ok := ClaudeHookInstalled(path); ok {
		t.Error("hook still installed")
	}
	if changed, _ := UninstallClaudeHook(path); changed {
		t.Error("second uninstall changed the file")
	}
}

func TestUninstallCleansEmptyHooks(t *testing.T) {
	path := filepath.Join(t.TempDir(), "settings.json")
	if _, err := InstallClaudeHook(path, HookCommand("agentguard", false)); err != nil {
		t.Fatal(err)
	}
	if _, err := UninstallClaudeHook(path); err != nil {
		t.Fatal(err)
	}
	if m := read(t, path); len(m) != 0 {
		t.Errorf("leftovers: %v", m)
	}
}

func TestInvalidSettingsAreNotOverwritten(t *testing.T) {
	path := filepath.Join(t.TempDir(), "settings.json")
	if err := os.WriteFile(path, []byte("{ not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := InstallClaudeHook(path, HookCommand("agentguard", false)); err == nil {
		t.Fatal("expected error")
	}
	if data, _ := os.ReadFile(path); string(data) != "{ not json" {
		t.Error("invalid file was overwritten")
	}
}

func TestHookCommandQuoting(t *testing.T) {
	if got := HookCommand("/Users/me/My Tools/agentguard", false); got != "'/Users/me/My Tools/agentguard' hook claude" {
		t.Errorf("got %q", got)
	}
}

func TestSwitchingToGlobalUpdatesTheEntry(t *testing.T) {
	path := filepath.Join(t.TempDir(), "settings.json")
	if _, err := InstallClaudeHook(path, HookCommand("/bin/agentguard", false)); err != nil {
		t.Fatal(err)
	}
	if changed, err := InstallClaudeHook(path, HookCommand("/bin/agentguard", true)); err != nil || !changed {
		t.Fatalf("changed=%v err=%v", changed, err)
	}
	pre := read(t, path)["hooks"].(map[string]any)["PreToolUse"].([]any)
	if len(pre) != 1 {
		t.Fatalf("duplicate entries: %v", pre)
	}
	if got, _ := ClaudeHookInstalled(path); got != "/bin/agentguard hook claude --global" {
		t.Errorf("command = %q", got)
	}
	if changed, _ := UninstallClaudeHook(path); !changed {
		t.Error("global hook not recognized by uninstall")
	}
}
