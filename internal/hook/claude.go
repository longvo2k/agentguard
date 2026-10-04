// Package hook connects AgentGuard to coding agents that run on the host and
// offer a pre-tool-use hook. The agent asks before each tool call; AgentGuard
// answers from the role policy and logs the decision.
//
// This mode is a guard rail, not a sandbox: the agent keeps the user's
// permissions and an allowed interpreter can still reach anything. For a
// hard boundary, run commands with `agentguard run`.
package hook

import (
	"encoding/json"
	"fmt"
	"io"
	"net/url"
	"path/filepath"

	"github.com/longvo2k/agentguard/internal/policy"
)

// ClaudeInput is the part of Claude Code's PreToolUse payload AgentGuard uses.
type ClaudeInput struct {
	HookEventName string         `json:"hook_event_name"`
	Cwd           string         `json:"cwd"`
	ToolName      string         `json:"tool_name"`
	ToolInput     map[string]any `json:"tool_input"`
}

// ClaudeMatcher lists the tools AgentGuard checks.
const ClaudeMatcher = "Read|Write|Edit|MultiEdit|NotebookEdit|Glob|Grep|Bash|WebFetch|WebSearch"

type request struct {
	action   policy.Action
	resource string
}

// Verdict is the hook's answer.
type Verdict struct {
	Allowed bool
	Reason  string
}

// ParseClaude reads a PreToolUse payload.
func ParseClaude(r io.Reader) (*ClaudeInput, error) {
	var in ClaudeInput
	dec := json.NewDecoder(io.LimitReader(r, 16<<20))
	if err := dec.Decode(&in); err != nil {
		return nil, fmt.Errorf("invalid hook input: %w", err)
	}
	return &in, nil
}

// claudeRequests maps a tool call to policy requests. Tools AgentGuard does
// not know about are allowed (no requests).
func claudeRequests(in *ClaudeInput) ([]request, error) {
	str := func(keys ...string) string {
		for _, k := range keys {
			if v, ok := in.ToolInput[k].(string); ok && v != "" {
				return v
			}
		}
		return ""
	}
	cwd := in.Cwd
	path := func(keys ...string) (string, error) {
		p := str(keys...)
		if p == "" {
			return "", fmt.Errorf("%s call without a %s", in.ToolName, keys[0])
		}
		return abs(cwd, p), nil
	}
	switch in.ToolName {
	case "Read":
		p, err := path("file_path", "path")
		if err != nil {
			return nil, err
		}
		return []request{{policy.ActionRead, p}}, nil
	case "Write", "Edit", "MultiEdit":
		p, err := path("file_path", "path")
		if err != nil {
			return nil, err
		}
		return []request{{policy.ActionWrite, p}}, nil
	case "NotebookEdit":
		p, err := path("notebook_path", "file_path")
		if err != nil {
			return nil, err
		}
		return []request{{policy.ActionWrite, p}}, nil
	case "Glob":
		// Glob returns file names only; check the directory it searches.
		if p := str("path"); p != "" {
			return []request{{policy.ActionRead, abs(cwd, p)}}, nil
		}
		return nil, nil
	case "Grep":
		// Grep returns file contents, so its search root must be readable.
		p := str("path")
		if p == "" {
			p = cwd
		}
		return []request{{policy.ActionRead, abs(cwd, p)}}, nil
	case "Bash":
		cmd := str("command")
		if cmd == "" {
			return nil, nil
		}
		return bashRequests(cmd, cwd)
	case "WebFetch":
		host := str("url")
		if u, err := url.Parse(host); err == nil && u.Host != "" {
			host = u.Host
		}
		return []request{{policy.ActionNetwork, host}}, nil
	case "WebSearch":
		return []request{{policy.ActionNetwork, "web search"}}, nil
	}
	return nil, nil
}

// DecideClaude evaluates a tool call. Every request goes through the engine,
// so each one is audited; the first denial decides.
func DecideClaude(e *policy.Engine, in *ClaudeInput) Verdict {
	if in.HookEventName != "" && in.HookEventName != "PreToolUse" {
		return Verdict{Allowed: true}
	}
	if in.Cwd == "" || !filepath.IsAbs(in.Cwd) {
		in.Cwd = e.Root()
	}
	reqs, err := claudeRequests(in)
	if err != nil {
		return Verdict{Reason: err.Error()}
	}
	for _, r := range reqs {
		d := e.Evaluate(r.action, r.resource)
		if !d.Allowed {
			res := r.resource
			if d.Path != "" {
				res = d.Path
			}
			reason := fmt.Sprintf("%s %s denied for role %q: %s", r.action, res, d.Role, d.Reason)
			if d.Rule != "" {
				reason += " (" + d.Rule + ")"
			}
			return Verdict{Reason: reason}
		}
	}
	return Verdict{Allowed: true}
}
