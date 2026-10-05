// Package policy parses AgentGuard role policies and evaluates permission
// requests against them. Evaluation is deterministic and default-deny: an
// action is allowed only when an explicit rule allows it and no deny rule,
// built-in protection or workspace boundary forbids it.
package policy

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"regexp"
	"time"

	"gopkg.in/yaml.v3"
)

// Action is a kind of operation an agent can request.
type Action string

const (
	ActionRead    Action = "read"
	ActionWrite   Action = "write"
	ActionExecute Action = "execute"
	ActionNetwork Action = "network"
)

// ParseAction converts a user-supplied string into an Action.
func ParseAction(s string) (Action, error) {
	switch a := Action(s); a {
	case ActionRead, ActionWrite, ActionExecute, ActionNetwork:
		return a, nil
	}
	return "", fmt.Errorf("unknown action %q (want read, write, execute or network)", s)
}

// Policy is the YAML document describing what one role may do.
type Policy struct {
	Role        string     `yaml:"role"`
	Description string     `yaml:"description,omitempty"`
	Filesystem  Filesystem `yaml:"filesystem"`
	Commands    Commands   `yaml:"commands"`
	Network     Network    `yaml:"network"`
	Deny        []string   `yaml:"deny"`
	Metadata    Metadata   `yaml:"metadata,omitempty"`
}

// Filesystem lists workspace-relative path patterns. Write implies read.
type Filesystem struct {
	Read  []string `yaml:"read"`
	Write []string `yaml:"write"`
	// AllowSensitive exempts paths from the built-in sensitive-file list
	// (for example ".env.example"). The policy's own deny list still applies.
	AllowSensitive []string `yaml:"allow_sensitive,omitempty"`
}

// Commands lists executables, by bare name, that may be started.
type Commands struct {
	Allow []string `yaml:"allow"`
}

// Network controls outbound network access. The MVP only supports on/off.
type Network struct {
	Enabled bool `yaml:"enabled"`
	// Allow, if set, limits network access to these hosts. "*.example.com"
	// matches subdomains of example.com. Claude Code's sandbox enforces it for
	// commands in server mode; the Docker sandbox cannot, so it keeps the
	// network off for roles with an allowlist.
	Allow []string `yaml:"allow,omitempty"`
}

// Metadata describes where a policy came from. It is reserved for future
// generated, human-approved, temporary policies; today only ExpiresAt is
// enforced (an expired policy denies everything).
type Metadata struct {
	Source     string     `yaml:"source,omitempty"`
	ApprovedBy string     `yaml:"approved_by,omitempty"`
	ExpiresAt  *time.Time `yaml:"expires_at,omitempty"`
}

var (
	roleRe    = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,63}$`)
	commandRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._+-]{0,127}$`)
	domainRe  = regexp.MustCompile(`^(\*\.)?[A-Za-z0-9]([A-Za-z0-9-]{0,62}[A-Za-z0-9])?(\.[A-Za-z0-9]([A-Za-z0-9-]{0,62}[A-Za-z0-9])?)*(:[0-9]{1,5})?$`)
)

// Parse decodes and validates a policy. Unknown fields are rejected so a
// typo such as "deney:" cannot silently drop a rule.
func Parse(data []byte) (*Policy, error) {
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	var p Policy
	if err := dec.Decode(&p); err != nil {
		if errors.Is(err, io.EOF) {
			return nil, errors.New("policy is empty")
		}
		return nil, fmt.Errorf("parse policy: %w", err)
	}
	var extra yaml.Node
	if err := dec.Decode(&extra); !errors.Is(err, io.EOF) {
		return nil, errors.New("policy must contain exactly one YAML document")
	}
	if err := p.Validate(); err != nil {
		return nil, err
	}
	return &p, nil
}

// LoadFile reads and parses a policy file.
func LoadFile(path string) (*Policy, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	p, err := Parse(data)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return p, nil
}

// Validate checks the policy for malformed roles, patterns and commands.
func (p *Policy) Validate() error {
	if !roleRe.MatchString(p.Role) {
		return fmt.Errorf("invalid role %q: use lowercase letters, digits, '-' or '_'", p.Role)
	}
	home, _ := os.UserHomeDir()
	check := func(field string, list []string, allowAbsolute bool) error {
		for _, raw := range list {
			pt, err := compilePattern(raw, home)
			if err != nil {
				return fmt.Errorf("%s: %w", field, err)
			}
			if pt.absolute && !allowAbsolute {
				return fmt.Errorf("%s: pattern %q must be relative to the workspace", field, raw)
			}
		}
		return nil
	}
	if err := check("filesystem.read", p.Filesystem.Read, false); err != nil {
		return err
	}
	if err := check("filesystem.write", p.Filesystem.Write, false); err != nil {
		return err
	}
	if err := check("filesystem.allow_sensitive", p.Filesystem.AllowSensitive, false); err != nil {
		return err
	}
	if err := check("deny", p.Deny, true); err != nil {
		return err
	}
	for _, d := range p.Network.Allow {
		if !domainRe.MatchString(d) {
			return fmt.Errorf("network.allow: %q must be a host name such as registry.npmjs.org or *.github.com", d)
		}
	}
	for _, c := range p.Commands.Allow {
		if !commandRe.MatchString(c) {
			return fmt.Errorf("commands.allow: %q must be a bare executable name (no paths, spaces or shell syntax)", c)
		}
	}
	return nil
}

// Marshal renders the policy as YAML.
func (p *Policy) Marshal() ([]byte, error) {
	return yaml.Marshal(p)
}

// ValidRole reports whether name is an acceptable role name. Role names are
// used to build file paths, so this also rules out path traversal.
func ValidRole(name string) bool { return roleRe.MatchString(name) }
