// Package config locates an AgentGuard workspace and loads its settings and
// role policies, either from the project's .agentguard/ or from the user's
// AgentGuard config directory (~/.config/agentguard).
package config

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/longvo2k/agentguard"
	"github.com/longvo2k/agentguard/internal/policy"
)

// DirName is the per-workspace configuration directory.
const DirName = policy.ProtectedDir

// The official sandbox image is published with each release. When it
// cannot be pulled, AgentGuard builds LocalImage from the embedded
// Dockerfile instead.
const (
	ImageRepo  = "ghcr.io/longvo2k/agentguard-sandbox"
	ImageTag   = "0.1"
	LocalImage = "agentguard-sandbox:local"
	// legacyImage is what v0.1.0 wrote into config.yaml.
	legacyImage = "agentguard-sandbox:0.1"
)

// imageDigest pins the official image. Release builds set it with
// -ldflags "-X github.com/longvo2k/agentguard/internal/config.imageDigest=sha256:...".
var imageDigest = ""

// DefaultImage returns the official sandbox image reference, pinned by
// digest in release builds.
func DefaultImage() string {
	if imageDigest != "" {
		return ImageRepo + "@" + imageDigest
	}
	return ImageRepo + ":" + ImageTag
}

// IsDefaultImage reports whether ref names the official image (in which case
// a local build is an acceptable fallback).
func IsDefaultImage(ref string) bool {
	return ref == "" || ref == DefaultImage() || ref == ImageRepo+":"+ImageTag || ref == legacyImage || ref == LocalImage
}

// ErrNotInitialized is returned when no configuration applies.
var ErrNotInitialized = errors.New("AgentGuard is not set up here; run `agentguard setup` once (all projects) or `agentguard init` (this project)")

// Config is .agentguard/config.yaml.
type Config struct {
	Version     int     `yaml:"version"`
	DefaultRole string  `yaml:"default_role"`
	AuditLog    string  `yaml:"audit_log"`
	Sandbox     Sandbox `yaml:"sandbox"`
}

// Sandbox holds container settings.
type Sandbox struct {
	// Image is the sandbox image. Empty means the official image.
	Image     string `yaml:"image,omitempty"`
	Memory    string `yaml:"memory"`
	CPUs      string `yaml:"cpus"`
	PidsLimit int    `yaml:"pids_limit"`
	// User is an optional uid:gid for the container (never 0). Default: the
	// invoking user, or 1000:1000 when agentguard runs as root.
	User string `yaml:"user,omitempty"`
}

// Default returns the configuration written by `agentguard init`.
func Default() Config {
	return Config{
		Version:     1,
		DefaultRole: "developer",
		AuditLog:    "audit.jsonl",
		Sandbox: Sandbox{
			Memory:    "1g",
			CPUs:      "2",
			PidsLimit: 256,
		},
	}
}

// Validate checks values that affect the security model.
func (c *Config) Validate() error {
	if c.Version != 1 {
		return fmt.Errorf("unsupported config version %d", c.Version)
	}
	if c.DefaultRole != "" && !policy.ValidRole(c.DefaultRole) {
		return fmt.Errorf("invalid default_role %q", c.DefaultRole)
	}
	// The audit log must stay inside .agentguard/, which is never mounted.
	if c.AuditLog == "" || filepath.IsAbs(c.AuditLog) || strings.Contains(c.AuditLog, "..") {
		return fmt.Errorf("audit_log %q must be a relative path inside %s/", c.AuditLog, DirName)
	}
	if c.Sandbox.PidsLimit < 0 {
		return errors.New("sandbox.pids_limit must not be negative")
	}
	return nil
}

// Image returns the sandbox image to use.
func (c *Config) Image() string {
	if c.Sandbox.Image == "" || c.Sandbox.Image == legacyImage {
		return DefaultImage()
	}
	return c.Sandbox.Image
}

// Scope says where a workspace's policies come from.
type Scope string

const (
	// ScopeProject: .agentguard/ in the project (trusted via the trust list).
	ScopeProject Scope = "project"
	// ScopeUser: the user's config directory, applied to any project.
	ScopeUser Scope = "user"
)

// Workspace is a directory the sandbox may expose, plus the configuration
// that governs it.
type Workspace struct {
	Root      string // the directory mounted at /workspace
	Scope     Scope
	ConfigDir string // holds config.yaml and policies/
	Config    Config
	auditPath string
	cacheDir  string
}

// CacheDir holds derived data such as resolved command paths per image.
func (w *Workspace) CacheDir() string { return w.cacheDir }

// AuditPath returns the audit log file path.
func (w *Workspace) AuditPath() string { return w.auditPath }

// PolicyPath returns where the policy for role is stored.
func (w *Workspace) PolicyPath(role string) string {
	return filepath.Join(w.ConfigDir, "policies", role+".yaml")
}

// LoadPolicy loads the policy for role. It never falls back to a built-in
// policy: what is enforced is exactly what is on disk.
func (w *Workspace) LoadPolicy(role string) (*policy.Policy, error) {
	if !policy.ValidRole(role) {
		return nil, fmt.Errorf("invalid role name %q", role)
	}
	path := w.PolicyPath(role)
	p, err := policy.LoadFile(path)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, fmt.Errorf("no policy for role %q (expected %s)", role, path)
	}
	if err != nil {
		return nil, err
	}
	if p.Role != role {
		return nil, fmt.Errorf("%s declares role %q, expected %q", path, p.Role, role)
	}
	return p, nil
}

// Roles lists the roles that have a policy file.
func (w *Workspace) Roles() []string {
	matches, _ := filepath.Glob(filepath.Join(w.ConfigDir, "policies", "*.yaml"))
	var out []string
	for _, m := range matches {
		out = append(out, strings.TrimSuffix(filepath.Base(m), ".yaml"))
	}
	return out
}

// Find resolves the workspace for start. A project's .agentguard/ wins if
// one exists (and must be trusted); otherwise the user-level configuration
// applies to the enclosing git repository, or to start itself.
func Find(start string) (*Workspace, error) {
	dir, err := filepath.Abs(start)
	if err != nil {
		return nil, err
	}
	project, found, err := ProjectRoot(dir)
	if err != nil {
		return nil, err
	}
	if found {
		if err := checkWorkspaceRoot(project); err != nil {
			return nil, err
		}
		state, err := TrustStatus(project)
		if err != nil {
			return nil, err
		}
		switch state {
		case Untrusted:
			return nil, fmt.Errorf("%w: %s was not created by `agentguard init` on this machine. Review its policies, then run `agentguard trust`", ErrUntrusted, filepath.Join(project, DirName))
		case Changed:
			return nil, fmt.Errorf("%w: the policies in %s changed since they were trusted. Review them, then run `agentguard trust`", ErrUntrusted, filepath.Join(project, DirName))
		}
		return Open(project)
	}

	userDir, err := UserConfigDir()
	if err != nil {
		return nil, err
	}
	if _, err := os.Stat(filepath.Join(userDir, "config.yaml")); err != nil {
		return nil, ErrNotInitialized
	}
	root := projectRoot(dir)
	if err := checkWorkspaceRoot(root); err != nil {
		return nil, err
	}
	return OpenUser(root)
}

// ProjectRoot finds the project directory holding .agentguard/ at or above
// start. More than one is refused: an agent with write access to a
// subdirectory could otherwise plant its own policy there for a later run
// to pick up.
func ProjectRoot(start string) (string, bool, error) {
	dir, err := filepath.Abs(start)
	if err != nil {
		return "", false, err
	}
	var found []string
	for d := dir; ; {
		if fi, err := os.Lstat(filepath.Join(d, DirName)); err == nil && fi.IsDir() {
			found = append(found, d)
		}
		parent := filepath.Dir(d)
		if parent == d {
			break
		}
		d = parent
	}
	switch len(found) {
	case 0:
		return "", false, nil
	case 1:
		return found[0], true, nil
	}
	return "", false, fmt.Errorf("found nested %s directories in %s and %s; refusing to guess which policy applies (remove the one you did not create)", DirName, found[0], found[1])
}

// Open loads the project-scoped workspace rooted at root. It does not check
// the trust list; Find does.
func Open(root string) (*Workspace, error) {
	cfgDir := filepath.Join(root, DirName)
	cfg, err := loadConfig(cfgDir)
	if err != nil {
		return nil, err
	}
	return &Workspace{
		Root:      root,
		Scope:     ScopeProject,
		ConfigDir: cfgDir,
		Config:    cfg,
		auditPath: filepath.Join(cfgDir, cfg.AuditLog),
		cacheDir:  filepath.Join(cfgDir, "cache"),
	}, nil
}

// OpenUser loads the user-level configuration for the workspace at root.
// Its audit log lives in the user state directory, one per project.
func OpenUser(root string) (*Workspace, error) {
	cfgDir, err := UserConfigDir()
	if err != nil {
		return nil, err
	}
	cfg, err := loadConfig(cfgDir)
	if err != nil {
		return nil, err
	}
	state, err := UserStateDir()
	if err != nil {
		return nil, err
	}
	cache, err := UserCacheDir()
	if err != nil {
		return nil, err
	}
	root = realPath(root)
	sum := sha256.Sum256([]byte(root))
	project := filepath.Base(root) + "-" + hex.EncodeToString(sum[:4])
	return &Workspace{
		Root:      root,
		Scope:     ScopeUser,
		ConfigDir: cfgDir,
		Config:    cfg,
		auditPath: filepath.Join(state, "projects", project, "audit.jsonl"),
		cacheDir:  cache,
	}, nil
}

func loadConfig(cfgDir string) (Config, error) {
	path := filepath.Join(cfgDir, "config.yaml")
	data, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return Config{}, ErrNotInitialized
		}
		return Config{}, err
	}
	cfg := Default()
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	if err := dec.Decode(&cfg); err != nil && !errors.Is(err, io.EOF) {
		return Config{}, fmt.Errorf("%s: %w", path, err)
	}
	if err := cfg.Validate(); err != nil {
		return Config{}, fmt.Errorf("%s: %w", path, err)
	}
	return cfg, nil
}

const configHeader = `# AgentGuard workspace configuration.
# Policies live in policies/<role>.yaml. This directory is never mounted
# into a sandbox, so agents cannot read or change their own policy or logs.
# After editing policies, run ` + "`agentguard trust`" + ` to approve the change.
`

const userConfigHeader = `# AgentGuard user configuration. These policies apply to every project
# that has no .agentguard/ of its own. The workspace is the enclosing git
# repository, or the current directory.
`

// Init creates .agentguard/ in root with a default config and the built-in
// example policies. Existing files are kept unless force is set. It returns
// the paths it wrote. Callers that act for the user should also call Trust.
func Init(root string, force bool) ([]string, error) {
	if err := checkWorkspaceRoot(root); err != nil {
		return nil, err
	}
	return initDir(filepath.Join(root, DirName), configHeader, Default(), force)
}

// InitUser creates the user-level configuration directory.
func InitUser(force bool) ([]string, error) {
	dir, err := UserConfigDir()
	if err != nil {
		return nil, err
	}
	cfg := Default()
	// The user-level default applies to arbitrary projects, so it uses the
	// broad-but-safe agent role instead of the src/tests layout of developer.
	cfg.DefaultRole = "agent"
	return initDir(dir, userConfigHeader, cfg, force)
}

func initDir(dir, header string, c Config, force bool) ([]string, error) {
	if err := os.MkdirAll(filepath.Join(dir, "policies"), 0o700); err != nil {
		return nil, err
	}
	var written []string
	write := func(path string, data []byte) error {
		if !force {
			if _, err := os.Lstat(path); err == nil {
				return nil
			}
		}
		if err := os.WriteFile(path, data, 0o600); err != nil {
			return err
		}
		written = append(written, path)
		return nil
	}
	cfg, err := yaml.Marshal(c)
	if err != nil {
		return nil, err
	}
	body := append([]byte(header), cfg...)
	body = append(body, []byte("# sandbox.image defaults to the official image ("+ImageRepo+").\n")...)
	if err := write(filepath.Join(dir, "config.yaml"), body); err != nil {
		return written, err
	}
	files, err := fs.Glob(agentguard.BuiltinPolicies, "policies/*.yaml")
	if err != nil {
		return written, err
	}
	for _, f := range files {
		data, err := agentguard.BuiltinPolicies.ReadFile(f)
		if err != nil {
			return written, err
		}
		if err := write(filepath.Join(dir, "policies", filepath.Base(f)), data); err != nil {
			return written, err
		}
	}
	return written, nil
}

// BuiltinPolicy returns one of the embedded example policies.
func BuiltinPolicy(role string) (*policy.Policy, error) {
	if !policy.ValidRole(role) {
		return nil, fmt.Errorf("invalid role name %q", role)
	}
	data, err := agentguard.BuiltinPolicies.ReadFile("policies/" + role + ".yaml")
	if err != nil {
		return nil, fmt.Errorf("no built-in policy for role %q", role)
	}
	return policy.Parse(data)
}
