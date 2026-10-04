// Package setup installs and removes AgentGuard's integrations with coding
// agents on the user's machine.
package setup

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/longvo2k/agentguard/internal/hook"
)

// hookMarker identifies AgentGuard's entry in an agent's settings.
const hookMarker = " hook claude"

// ClaudeSettingsPath returns the user-level Claude Code settings file.
func ClaudeSettingsPath() (string, error) {
	if d := os.Getenv("CLAUDE_CONFIG_DIR"); d != "" {
		return filepath.Join(d, "settings.json"), nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, ".claude", "settings.json"), nil
}

// ClaudeDetected reports whether Claude Code seems to be installed.
func ClaudeDetected() bool {
	if p, err := ClaudeSettingsPath(); err == nil {
		if _, err := os.Stat(filepath.Dir(p)); err == nil {
			return true
		}
	}
	return lookPath("claude")
}

// HookCommand is the command line Claude Code runs for the hook.
func HookCommand(exe string) string {
	return shellQuote(exe) + hookMarker
}

func isOurs(cmd string) bool {
	return strings.Contains(cmd, "agentguard") && strings.HasSuffix(strings.TrimSpace(cmd), strings.TrimSpace(hookMarker))
}

// readSettings returns the settings object, or an empty one if the file
// does not exist.
func readSettings(path string) (map[string]any, os.FileMode, error) {
	data, err := os.ReadFile(path)
	if errors.Is(err, fs.ErrNotExist) {
		return map[string]any{}, 0o600, nil
	}
	if err != nil {
		return nil, 0, err
	}
	mode := os.FileMode(0o600)
	if fi, err := os.Stat(path); err == nil {
		mode = fi.Mode().Perm()
	}
	settings := map[string]any{}
	if len(strings.TrimSpace(string(data))) == 0 {
		return settings, mode, nil
	}
	if err := json.Unmarshal(data, &settings); err != nil {
		return nil, 0, fmt.Errorf("%s is not valid JSON (%v); fix it or move it aside, then rerun setup", path, err)
	}
	return settings, mode, nil
}

func writeSettings(path string, settings map[string]any, mode os.FileMode) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	// Keep one backup of the file as it was before AgentGuard touched it.
	backup := path + ".agentguard-backup"
	if _, err := os.Lstat(backup); errors.Is(err, fs.ErrNotExist) {
		if data, err := os.ReadFile(path); err == nil {
			if err := os.WriteFile(backup, data, 0o600); err != nil {
				return err
			}
		}
	}
	data, err := json.MarshalIndent(settings, "", "  ")
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".settings-*.json")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.Write(append(data, '\n')); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Chmod(tmp.Name(), mode); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
}

func asList(v any) []any {
	l, _ := v.([]any)
	return l
}

func asMap(v any) map[string]any {
	m, _ := v.(map[string]any)
	return m
}

// InstallClaudeHook adds (or updates) AgentGuard's PreToolUse hook. Other
// settings and hooks are preserved. It reports whether the file changed.
func InstallClaudeHook(path, command string) (bool, error) {
	settings, mode, err := readSettings(path)
	if err != nil {
		return false, err
	}
	hooks := asMap(settings["hooks"])
	if settings["hooks"] != nil && hooks == nil {
		return false, fmt.Errorf("%s: \"hooks\" is not an object", path)
	}
	if hooks == nil {
		hooks = map[string]any{}
	}
	original, _ := json.Marshal(settings)
	groups := asList(hooks["PreToolUse"])
	entry := map[string]any{"type": "command", "command": command, "timeout": 30}

	found := false
	for _, g := range groups {
		gm := asMap(g)
		hs := asList(gm["hooks"])
		for i, h := range hs {
			if hm := asMap(h); hm != nil && isOurs(fmt.Sprint(hm["command"])) {
				found = true
				gm["matcher"] = hook.ClaudeMatcher
				hs[i] = entry
			}
		}
	}
	if !found {
		groups = append(groups, map[string]any{
			"matcher": hook.ClaudeMatcher,
			"hooks":   []any{entry},
		})
	}
	hooks["PreToolUse"] = groups
	settings["hooks"] = hooks
	if updated, _ := json.Marshal(settings); string(updated) == string(original) {
		return false, nil
	}
	return true, writeSettings(path, settings, mode)
}

// UninstallClaudeHook removes AgentGuard's hook and nothing else.
func UninstallClaudeHook(path string) (bool, error) {
	settings, mode, err := readSettings(path)
	if err != nil {
		return false, err
	}
	hooks := asMap(settings["hooks"])
	if hooks == nil {
		return false, nil
	}
	changed := false
	var kept []any
	for _, g := range asList(hooks["PreToolUse"]) {
		gm := asMap(g)
		var hs []any
		for _, h := range asList(gm["hooks"]) {
			if hm := asMap(h); hm != nil && isOurs(fmt.Sprint(hm["command"])) {
				changed = true
				continue
			}
			hs = append(hs, h)
		}
		if len(hs) > 0 {
			gm["hooks"] = hs
			kept = append(kept, gm)
		}
	}
	if !changed {
		return false, nil
	}
	if len(kept) > 0 {
		hooks["PreToolUse"] = kept
	} else {
		delete(hooks, "PreToolUse")
	}
	if len(hooks) == 0 {
		delete(settings, "hooks")
	}
	return true, writeSettings(path, settings, mode)
}

// ClaudeHookInstalled returns the installed hook command, if any.
func ClaudeHookInstalled(path string) (string, bool) {
	settings, _, err := readSettings(path)
	if err != nil {
		return "", false
	}
	for _, g := range asList(asMap(settings["hooks"])["PreToolUse"]) {
		for _, h := range asList(asMap(g)["hooks"]) {
			if cmd := fmt.Sprint(asMap(h)["command"]); isOurs(cmd) {
				return cmd, true
			}
		}
	}
	return "", false
}

func shellQuote(s string) string {
	if s != "" && strings.Trim(s, "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_./+@%:") == "" {
		return s
	}
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}
