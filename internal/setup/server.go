package setup

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"syscall"

	"github.com/longvo2k/agentguard/internal/hook"
	"github.com/longvo2k/agentguard/internal/policy"
)

// Server mode hands Claude Code a root-owned managed settings file. Claude
// Code gives managed settings the highest precedence and lets nothing else
// disable managed hooks, so the agent cannot switch AgentGuard off. The same
// file turns on Claude Code's own Bash sandbox (bubblewrap on Linux), which
// confines every command and its child processes at the OS level, closing
// the gap the hook leaves for interpreters such as `python3 -c`.

// ManagedSettingsDir is where Claude Code reads managed settings drop-ins.
// AGENTGUARD_CLAUDE_MANAGED_DIR overrides it (for tests).
func ManagedSettingsDir() string {
	if d := os.Getenv("AGENTGUARD_CLAUDE_MANAGED_DIR"); d != "" {
		return d
	}
	return "/etc/claude-code/managed-settings.d"
}

// ManagedSettingsFile is AgentGuard's drop-in.
func ManagedSettingsFile() string {
	return filepath.Join(ManagedSettingsDir(), "50-agentguard.json")
}

// ServerWorkspace is a workspace and the policy that governs it.
type ServerWorkspace struct {
	Root   string
	Policy *policy.Policy
}

// ManagedOptions describe the server to generate settings for.
type ManagedOptions struct {
	HookCommand string
	Workspaces  []ServerWorkspace
	DenyRead    []string // extra absolute paths from server.deny_read
	SystemDir   string   // /etc/agentguard
	LogDir      string   // /var/log/agentguard
}

// Directories that usually hold other people's or other services' data.
// Sandboxed commands may not read them; workspaces and the agent's own home
// are re-opened below, and narrower deny entries still win inside those.
var serverDenyRead = []string{
	"/home", "/root", "/srv", "/mnt", "/media",
	"/var/lib", "/var/backups", "/var/log", "/var/mail", "/var/spool",
	"/etc/ssh", "/etc/ssl/private", "/etc/letsencrypt", "/etc/sudoers.d",
}

// Credential stores in the agent's own home.
var homeDenyRead = []string{
	"~/.ssh", "~/.aws", "~/.azure", "~/.config/gcloud", "~/.kube", "~/.docker",
	"~/.gnupg", "~/.claude", "~/.claude.json", "~/.netrc", "~/.npmrc", "~/.pypirc",
	"~/.git-credentials", "~/.bash_history", "~/.zsh_history",
}

// ManagedSettings builds the managed settings document. It also returns
// warnings about policy features the sandbox cannot express.
func ManagedSettings(o ManagedOptions) (map[string]any, []string, error) {
	var warnings []string
	denyRead := append(append([]string{}, serverDenyRead...), homeDenyRead...)
	denyRead = append(denyRead, o.DenyRead...)
	allowRead := []string{"~/"}
	denyWrite := []string{o.SystemDir, o.LogDir}
	domains := map[string]bool{}

	for _, w := range o.Workspaces {
		allowRead = append(allowRead, w.Root)
		patterns := append(append([]string{}, w.Policy.Deny...), policy.SensitivePatterns...)
		for _, pat := range patterns {
			globs, err := policy.SandboxGlobs(pat, w.Root)
			if err != nil {
				return nil, nil, fmt.Errorf("policy %s: %w", w.Policy.Role, err)
			}
			denyRead = append(denyRead, globs...)
		}
		if len(w.Policy.Filesystem.AllowSensitive) > 0 {
			warnings = append(warnings, fmt.Sprintf("role %s: allow_sensitive is not applied to sandboxed commands; they cannot read those files", w.Policy.Role))
		}
		// Linux only accepts concrete paths for write denials.
		for _, name := range []string{".git", ".agentguard", ".claude"} {
			if _, err := os.Lstat(filepath.Join(w.Root, name)); err == nil {
				denyWrite = append(denyWrite, filepath.Join(w.Root, name))
			}
		}
		n := w.Policy.Network
		switch {
		case !n.Enabled:
		case len(n.Allow) == 0:
			warnings = append(warnings, fmt.Sprintf("role %s enables the network without network.allow; in server mode commands only reach listed hosts, so it gets none", w.Policy.Role))
		default:
			for _, d := range n.Allow {
				domains[d] = true
			}
		}
	}

	allowedDomains := make([]string, 0, len(domains))
	for d := range domains {
		allowedDomains = append(allowedDomains, d)
	}
	sort.Strings(allowedDomains)

	permDeny := []string{
		"Read(~/.ssh/**)", "Read(~/.aws/**)", "Read(~/.claude/.credentials.json)",
		"Read(//root/**)", "Read(//etc/shadow)",
		"Edit(//" + trimSlash(o.SystemDir) + "/**)",
		"Edit(//" + trimSlash(o.LogDir) + "/**)",
		"Edit(//etc/claude-code/**)",
	}
	for _, w := range o.Workspaces {
		permDeny = append(permDeny, "Read(//"+trimSlash(w.Root)+"/**/.env*)")
	}

	settings := map[string]any{
		"allowManagedHooksOnly": true,
		"hooks": map[string]any{
			"PreToolUse": []any{map[string]any{
				"matcher": hook.ClaudeMatcher,
				"hooks": []any{map[string]any{
					"type": "command", "command": o.HookCommand, "timeout": 30,
				}},
			}},
		},
		"permissions": map[string]any{
			"deny":                         permDeny,
			"disableBypassPermissionsMode": "disable",
		},
		"sandbox": map[string]any{
			"enabled":                      true,
			"failIfUnavailable":            true,
			"allowUnsandboxedCommands":     false,
			"enableWeakerNestedSandbox":    false,
			"enableWeakerNetworkIsolation": false,
			"filesystem": map[string]any{
				"denyRead":                  dedupe(denyRead),
				"allowRead":                 dedupe(allowRead),
				"denyWrite":                 dedupe(denyWrite),
				"allowManagedReadPathsOnly": true,
			},
			"network": map[string]any{
				"allowedDomains":          allowedDomains,
				"allowManagedDomainsOnly": true,
				"strictAllowlist":         true,
				"allowLocalBinding":       false,
				"allowAllUnixSockets":     false,
			},
		},
	}
	return settings, warnings, nil
}

// WriteManagedSettings writes the drop-in as root-owned, world-readable JSON.
func WriteManagedSettings(settings map[string]any) (string, error) {
	path := ManagedSettingsFile()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return "", err
	}
	data, err := json.MarshalIndent(settings, "", "  ")
	if err != nil {
		return "", err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".agentguard-*.json")
	if err != nil {
		return "", err
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.Write(append(data, '\n')); err != nil {
		tmp.Close()
		return "", err
	}
	if err := tmp.Close(); err != nil {
		return "", err
	}
	if err := os.Chmod(tmp.Name(), 0o644); err != nil {
		return "", err
	}
	return path, os.Rename(tmp.Name(), path)
}

// RemoveManagedSettings deletes the drop-in. It reports whether one existed.
func RemoveManagedSettings() (bool, error) {
	err := os.Remove(ManagedSettingsFile())
	if errors.Is(err, fs.ErrNotExist) {
		return false, nil
	}
	return err == nil, err
}

// InstallBinary copies the running binary to dst (root-owned, 0755) unless
// it already is that file. The managed hook must point at a binary the
// agent's user cannot replace.
func InstallBinary(dst string) (bool, error) {
	exe, err := os.Executable()
	if err != nil {
		return false, err
	}
	exe, _ = filepath.EvalSymlinks(exe)
	if real, err := filepath.EvalSymlinks(dst); err == nil && real == exe {
		return false, nil
	}
	src, err := os.Open(exe)
	if err != nil {
		return false, err
	}
	defer src.Close()
	if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
		return false, err
	}
	tmp, err := os.CreateTemp(filepath.Dir(dst), ".agentguard-new-*")
	if err != nil {
		return false, err
	}
	defer os.Remove(tmp.Name())
	if _, err := io.Copy(tmp, src); err != nil {
		tmp.Close()
		return false, err
	}
	if err := tmp.Close(); err != nil {
		return false, err
	}
	if err := os.Chmod(tmp.Name(), 0o755); err != nil {
		return false, err
	}
	return true, os.Rename(tmp.Name(), dst)
}

// PrepareLogFile creates a root-owned log file that any user may append to
// (the hook runs as the agent's user) and, where the filesystem supports
// it, marks it append-only so it cannot be truncated or rewritten.
func PrepareLogFile(path string) (appendOnly bool, err error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return false, err
	}
	if err := os.Chmod(filepath.Dir(path), 0o755); err != nil {
		return false, err
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o622)
	if err != nil {
		return false, err
	}
	f.Close()
	if err := os.Chmod(path, 0o622); err != nil {
		return false, err
	}
	if _, err := exec.LookPath("chattr"); err == nil {
		if exec.Command("chattr", "+a", path).Run() == nil {
			return true, nil
		}
	}
	return false, nil
}

// OwnedByRoot reports whether path is owned by root and not writable by
// group or others.
func OwnedByRoot(path string) bool {
	fi, err := os.Stat(path)
	if err != nil {
		return false
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	return ok && st.Uid == 0 && fi.Mode().Perm()&0o022 == 0
}

func trimSlash(p string) string {
	for len(p) > 0 && p[0] == '/' {
		p = p[1:]
	}
	return p
}

func dedupe(in []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, s := range in {
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	return out
}
