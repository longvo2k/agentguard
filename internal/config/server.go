package config

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"syscall"

	"gopkg.in/yaml.v3"

	"github.com/longvo2k/agentguard/internal/policy"
)

// Server mode is for machines where the agent must not wander: the policies
// live in a root-owned system directory, the agent runs as its own
// unprivileged user, and it may only work in the workspaces listed here.
// Project .agentguard/ directories and user-level policies are ignored in
// server mode, because the agent's user can write to both.

// ScopeServer: the root-owned system configuration in server mode.
const ScopeServer Scope = "server"

// Server is the `server:` section of the system config.yaml.
type Server struct {
	// Workspaces are the only directories the agent may work in.
	Workspaces []ServerWorkspace `yaml:"workspaces"`
	// DenyRead lists extra absolute paths that sandboxed commands may not
	// read, such as /etc/myapp or /opt/myapp/secrets.
	DenyRead []string `yaml:"deny_read,omitempty"`
}

// ServerWorkspace is one directory the agent may work in, and its role.
type ServerWorkspace struct {
	Path string `yaml:"path"`
	Role string `yaml:"role,omitempty"`
}

// ErrNoServerConfig means server mode is requested but not configured.
var ErrNoServerConfig = errors.New("server mode is not configured; run `sudo agentguard setup --server --workspace <dir>`")

// SystemConfigDir is /etc/agentguard (AGENTGUARD_SYSTEM_DIR overrides it).
func SystemConfigDir() string {
	if d := os.Getenv("AGENTGUARD_SYSTEM_DIR"); d != "" {
		return filepath.Clean(d)
	}
	return "/etc/agentguard"
}

// SystemLogDir is /var/log/agentguard (AGENTGUARD_LOG_DIR overrides it).
func SystemLogDir() string {
	if d := os.Getenv("AGENTGUARD_LOG_DIR"); d != "" {
		return filepath.Clean(d)
	}
	return "/var/log/agentguard"
}

func (s *Server) validate() error {
	if len(s.Workspaces) == 0 {
		return errors.New("server.workspaces is empty")
	}
	for _, w := range s.Workspaces {
		if !filepath.IsAbs(w.Path) || filepath.Clean(w.Path) != w.Path || w.Path == "/" {
			return fmt.Errorf("server.workspaces: %q must be a clean absolute path other than /", w.Path)
		}
		if strings.ContainsAny(w.Path, ",\"\n\r") {
			return fmt.Errorf("server.workspaces: %q contains unsupported characters", w.Path)
		}
		if w.Role != "" && !policy.ValidRole(w.Role) {
			return fmt.Errorf("server.workspaces: invalid role %q", w.Role)
		}
	}
	for _, d := range s.DenyRead {
		if !filepath.IsAbs(d) {
			return fmt.Errorf("server.deny_read: %q must be an absolute path", d)
		}
	}
	return nil
}

// ServerConfig is a loaded, verified system configuration.
type ServerConfig struct {
	Dir    string
	Config Config
}

// LoadServer loads the system configuration and refuses it unless every
// file is owned by root and writable by nobody else, so the agent's user
// cannot have changed it.
func LoadServer() (*ServerConfig, error) {
	dir := SystemConfigDir()
	if _, err := os.Stat(filepath.Join(dir, "config.yaml")); errors.Is(err, fs.ErrNotExist) {
		return nil, ErrNoServerConfig
	}
	if err := CheckRootOwned(dir); err != nil {
		return nil, err
	}
	cfg, err := loadConfig(dir)
	if err != nil {
		return nil, err
	}
	if cfg.Server == nil {
		return nil, fmt.Errorf("%s/config.yaml has no server: section", dir)
	}
	return &ServerConfig{Dir: dir, Config: cfg}, nil
}

// CheckRootOwned verifies that dir, its parents, and every file below it are
// owned by root and not writable by group or others.
func CheckRootOwned(dir string) error {
	check := func(p string, fi fs.FileInfo) error {
		st, ok := fi.Sys().(*syscall.Stat_t)
		if !ok {
			return fmt.Errorf("cannot read the owner of %s", p)
		}
		if st.Uid != 0 {
			return fmt.Errorf("%s must be owned by root (it is owned by uid %d), or the agent's user could change its own policy", p, st.Uid)
		}
		if fi.Mode().Perm()&0o022 != 0 && fi.Mode()&fs.ModeSymlink == 0 {
			if !(fi.IsDir() && fi.Mode()&fs.ModeSticky != 0) {
				return fmt.Errorf("%s must not be writable by group or others (mode %v)", p, fi.Mode().Perm())
			}
		}
		return nil
	}
	// Parents: someone who can write a parent can replace the directory.
	for d := filepath.Dir(dir); ; d = filepath.Dir(d) {
		fi, err := os.Stat(d)
		if err != nil {
			return err
		}
		if err := check(d, fi); err != nil {
			return err
		}
		if filepath.Dir(d) == d {
			break
		}
	}
	return filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		fi, err := os.Lstat(p)
		if err != nil {
			return err
		}
		if fi.Mode()&fs.ModeSymlink != 0 {
			return fmt.Errorf("%s is a symlink; the system configuration must not contain symlinks", p)
		}
		return check(p, fi)
	})
}

// WorkspaceFor returns the workspace containing dir, if any. When
// workspaces nest, the innermost one wins.
func (sc *ServerConfig) WorkspaceFor(dir string) (*Workspace, error) {
	real := realPath(dir)
	var best *ServerWorkspace
	for i, w := range sc.Config.Server.Workspaces {
		if within(real, realPath(w.Path)) && (best == nil || len(w.Path) > len(best.Path)) {
			best = &sc.Config.Server.Workspaces[i]
		}
	}
	if best == nil {
		var list []string
		for _, w := range sc.Config.Server.Workspaces {
			list = append(list, w.Path)
		}
		return nil, fmt.Errorf("%s is outside the workspaces the agent may use on this server (%s)", real, strings.Join(list, ", "))
	}
	cfg := sc.Config
	if best.Role != "" {
		cfg.DefaultRole = best.Role
	}
	root := realPath(best.Path)
	sum := sha256.Sum256([]byte(root))
	cache, err := UserCacheDir()
	if err != nil {
		cache = filepath.Join(os.TempDir(), "agentguard-cache")
	}
	return &Workspace{
		Root:      root,
		Scope:     ScopeServer,
		ConfigDir: sc.Dir,
		Config:    cfg,
		auditPath: ServerAuditPath(root, sum),
		cacheDir:  cache,
	}, nil
}

// ServerAuditPath is the per-workspace audit log in the system log dir.
func ServerAuditPath(root string, sum [32]byte) string {
	return filepath.Join(SystemLogDir(), filepath.Base(root)+"-"+hex.EncodeToString(sum[:4])+".jsonl")
}

// ServerLogPath records calls refused outside any workspace.
func ServerLogPath() string { return filepath.Join(SystemLogDir(), "server.jsonl") }

// AuditPathForServerWorkspace returns the audit log path for a workspace.
func AuditPathForServerWorkspace(path string) string {
	root := realPath(path)
	return ServerAuditPath(root, sha256.Sum256([]byte(root)))
}

// InitServer writes the system configuration: config.yaml with the given
// workspaces (merged into any existing list) and the built-in policies if
// missing. Files are created root-owned with mode 0644 by the caller's
// process, which must be root.
func InitServer(workspaces []ServerWorkspace) (written []string, cfg Config, err error) {
	dir := SystemConfigDir()
	if err := os.MkdirAll(filepath.Join(dir, "policies"), 0o755); err != nil {
		return nil, cfg, err
	}
	for _, d := range []string{dir, filepath.Join(dir, "policies")} {
		if err := os.Chmod(d, 0o755); err != nil {
			return nil, cfg, err
		}
	}
	cfg = Default()
	cfg.DefaultRole = "agent"
	if existing, err := loadConfig(dir); err == nil {
		cfg = existing
	} else if !errors.Is(err, ErrNotInitialized) {
		return nil, cfg, err
	}
	if cfg.Server == nil {
		cfg.Server = &Server{}
	}
	for _, w := range workspaces {
		w.Path = filepath.Clean(w.Path)
		found := false
		for i := range cfg.Server.Workspaces {
			if cfg.Server.Workspaces[i].Path == w.Path {
				if w.Role != "" {
					cfg.Server.Workspaces[i].Role = w.Role
				}
				found = true
			}
		}
		if !found {
			cfg.Server.Workspaces = append(cfg.Server.Workspaces, w)
		}
	}
	if err := cfg.Validate(); err != nil {
		return nil, cfg, err
	}
	data, err := yaml.Marshal(cfg)
	if err != nil {
		return nil, cfg, err
	}
	header := "# AgentGuard server configuration (root-owned). The agent may only work in\n" +
		"# server.workspaces. After editing, run `sudo agentguard setup --server` to\n" +
		"# regenerate Claude Code's managed settings.\n"
	cfgPath := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(cfgPath, append([]byte(header), data...), 0o644); err != nil {
		return nil, cfg, err
	}
	if err := os.Chmod(cfgPath, 0o644); err != nil {
		return nil, cfg, err
	}
	written = append(written, cfgPath)
	files, err := initDir(dir, "", cfg, false)
	for _, f := range files {
		if f == cfgPath {
			continue
		}
		if err := os.Chmod(f, 0o644); err != nil {
			return written, cfg, err
		}
		written = append(written, f)
	}
	return written, cfg, err
}

// SavePolicy writes a policy file into the system policies directory.
func SavePolicy(dir string, p *policy.Policy) error {
	data, err := p.Marshal()
	if err != nil {
		return err
	}
	path := filepath.Join(dir, "policies", p.Role+".yaml")
	if err := os.WriteFile(path, data, 0o644); err != nil {
		return err
	}
	return os.Chmod(path, 0o644)
}
