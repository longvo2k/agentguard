// Package config locates an AgentGuard workspace and loads its settings and
// role policies from .agentguard/.
package config

import (
	"bytes"
	"errors"
	"fmt"
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

// DefaultImage is the sandbox image AgentGuard builds on first use.
const DefaultImage = "agentguard-sandbox:0.1"

// ErrNotInitialized is returned when no .agentguard directory is found.
var ErrNotInitialized = errors.New("no .agentguard directory found; run `agentguard init` first")

// Config is .agentguard/config.yaml.
type Config struct {
	Version     int     `yaml:"version"`
	DefaultRole string  `yaml:"default_role"`
	AuditLog    string  `yaml:"audit_log"`
	Sandbox     Sandbox `yaml:"sandbox"`
}

// Sandbox holds container settings.
type Sandbox struct {
	Image     string `yaml:"image"`
	Memory    string `yaml:"memory"`
	CPUs      string `yaml:"cpus"`
	PidsLimit int    `yaml:"pids_limit"`
}

// Default returns the configuration written by `agentguard init`.
func Default() Config {
	return Config{
		Version:     1,
		DefaultRole: "developer",
		AuditLog:    "audit.jsonl",
		Sandbox: Sandbox{
			Image:     DefaultImage,
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
	if c.Sandbox.Image == "" {
		return errors.New("sandbox.image must be set")
	}
	if c.Sandbox.PidsLimit < 0 {
		return errors.New("sandbox.pids_limit must not be negative")
	}
	return nil
}

// Workspace is an initialized project directory.
type Workspace struct {
	Root   string
	Config Config
}

// Dir returns the .agentguard directory.
func (w *Workspace) Dir() string { return filepath.Join(w.Root, DirName) }

// CacheDir holds derived data such as resolved command paths per image.
func (w *Workspace) CacheDir() string { return filepath.Join(w.Dir(), "cache") }

// AuditPath returns the audit log file path.
func (w *Workspace) AuditPath() string { return filepath.Join(w.Dir(), w.Config.AuditLog) }

// PolicyPath returns where the policy for role is stored.
func (w *Workspace) PolicyPath(role string) string {
	return filepath.Join(w.Dir(), "policies", role+".yaml")
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
	matches, _ := filepath.Glob(filepath.Join(w.Dir(), "policies", "*.yaml"))
	var out []string
	for _, m := range matches {
		out = append(out, strings.TrimSuffix(filepath.Base(m), ".yaml"))
	}
	return out
}

// Find walks up from start looking for an initialized workspace.
func Find(start string) (*Workspace, error) {
	dir, err := filepath.Abs(start)
	if err != nil {
		return nil, err
	}
	for {
		cfgPath := filepath.Join(dir, DirName, "config.yaml")
		if _, err := os.Stat(cfgPath); err == nil {
			return Open(dir)
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return nil, ErrNotInitialized
		}
		dir = parent
	}
}

// Open loads the workspace rooted at root.
func Open(root string) (*Workspace, error) {
	data, err := os.ReadFile(filepath.Join(root, DirName, "config.yaml"))
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, ErrNotInitialized
		}
		return nil, err
	}
	cfg := Default()
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	if err := dec.Decode(&cfg); err != nil {
		return nil, fmt.Errorf("config.yaml: %w", err)
	}
	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("config.yaml: %w", err)
	}
	return &Workspace{Root: root, Config: cfg}, nil
}

const configHeader = `# AgentGuard workspace configuration.
# Policies live in policies/<role>.yaml. This directory is never mounted
# into a sandbox, so agents cannot read or change their own policy or logs.
`

// Init creates .agentguard/ with a default config and the built-in example
// policies. Existing files are kept unless force is set. It returns the
// paths it wrote.
func Init(root string, force bool) ([]string, error) {
	dir := filepath.Join(root, DirName)
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
	cfg, err := yaml.Marshal(Default())
	if err != nil {
		return nil, err
	}
	if err := write(filepath.Join(dir, "config.yaml"), append([]byte(configHeader), cfg...)); err != nil {
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
