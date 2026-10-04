package config

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
)

// User-level directories. AGENTGUARD_HOME, if set, holds all three (config/,
// state/, cache/); otherwise the XDG base directories are used, falling back
// to ~/.config, ~/.local/state and ~/.cache on both Linux and macOS.
//
// None of these are ever inside a workspace (see checkWorkspaceRoot), so a
// sandboxed agent can never reach the user's policies, trust list or logs.

// UserConfigDir holds the user-level config.yaml and policies/.
func UserConfigDir() (string, error) { return userDir("config", "XDG_CONFIG_HOME", ".config") }

// UserStateDir holds the trust list and per-project audit logs.
func UserStateDir() (string, error) { return userDir("state", "XDG_STATE_HOME", ".local/state") }

// UserCacheDir holds derived data such as resolved command paths.
func UserCacheDir() (string, error) { return userDir("cache", "XDG_CACHE_HOME", ".cache") }

func userDir(sub, xdgVar, homeRel string) (string, error) {
	if h := os.Getenv("AGENTGUARD_HOME"); h != "" {
		return absClean(filepath.Join(h, sub))
	}
	if x := os.Getenv(xdgVar); x != "" && filepath.IsAbs(x) {
		return filepath.Join(x, "agentguard"), nil
	}
	home, err := os.UserHomeDir()
	if err != nil || home == "" {
		return "", errors.New("cannot determine the home directory; set AGENTGUARD_HOME")
	}
	return filepath.Join(home, homeRel, "agentguard"), nil
}

func absClean(p string) (string, error) {
	a, err := filepath.Abs(p)
	if err != nil {
		return "", err
	}
	return filepath.Clean(a), nil
}

// realPath resolves symlinks in the longest existing prefix of p.
func realPath(p string) string {
	p, err := absClean(p)
	if err != nil {
		return p
	}
	if r, err := filepath.EvalSymlinks(p); err == nil {
		return r
	}
	if parent := filepath.Dir(p); parent != p {
		return filepath.Join(realPath(parent), filepath.Base(p))
	}
	return p
}

// within reports whether p is base or below it.
func within(p, base string) bool {
	if p == base {
		return true
	}
	if !strings.HasSuffix(base, string(filepath.Separator)) {
		base += string(filepath.Separator)
	}
	return strings.HasPrefix(p, base)
}

// checkWorkspaceRoot refuses roots that would put the user's home directory,
// or AgentGuard's own user-level files, inside the sandbox's reach. With such
// a root, a role with broad write access could edit ~/.config/agentguard or
// ~/.claude/settings.json and loosen its own restrictions.
func checkWorkspaceRoot(root string) error {
	r := realPath(root)
	type entry struct{ dir, what string }
	var protected []entry
	if home, err := os.UserHomeDir(); err == nil && home != "" {
		protected = append(protected, entry{realPath(home), "your home directory"})
	}
	for _, d := range []struct {
		name string
		fn   func() (string, error)
	}{{"config", UserConfigDir}, {"state", UserStateDir}, {"cache", UserCacheDir}} {
		if dir, err := d.fn(); err == nil {
			protected = append(protected, entry{realPath(dir), "AgentGuard's user " + d.name + " directory"})
		}
	}
	for _, p := range protected {
		if within(p.dir, r) {
			return &rootError{root: r, what: p.what}
		}
	}
	return nil
}

type rootError struct{ root, what string }

func (e *rootError) Error() string {
	return "refusing to use " + e.root + " as a workspace because it contains " + e.what + "; run AgentGuard from inside a project directory"
}

// projectRoot picks the workspace root for user-level policies: the nearest
// enclosing git repository, or start itself.
func projectRoot(start string) string {
	dir := realPath(start)
	for d := dir; ; {
		if _, err := os.Lstat(filepath.Join(d, ".git")); err == nil {
			return d
		}
		parent := filepath.Dir(d)
		if parent == d {
			return dir
		}
		d = parent
	}
}
