package hook

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/longvo2k/agentguard/internal/policy"
)

// Bash commands are checked on a best-effort basis. The parser understands
// enough shell to find each command in a list or pipeline, its redirections
// and its file arguments; anything it cannot follow safely (command
// substitution, eval, heredocs) is refused rather than guessed at. It is a
// guard rail for an agent that runs on the host, not a sandbox: an allowed
// interpreter can still do anything (python -c, node -e, npm scripts).

// errUnsupported marks shell syntax the hook refuses to interpret.
type errUnsupported struct{ what string }

func (e errUnsupported) Error() string {
	return e.what + " is not allowed under AgentGuard (it hides what will actually run)"
}

// builtins are shell builtins that only affect the shell itself.
var builtins = map[string]bool{
	"cd": true, "pushd": true, "popd": true, "pwd": true, "echo": true, "printf": true,
	"true": true, "false": true, "test": true, "[": true, ":": true, "exit": true,
	"export": true, "unset": true, "set": true, "shift": true, "read": true, "wait": true,
	"local": true, "return": true, "break": true, "continue": true,
}

// keywords that start a compound command; the next word is a command.
var prefixKeywords = map[string]bool{
	"if": true, "then": true, "else": true, "elif": true, "do": true,
	"while": true, "until": true, "!": true, "time": true, "{": true,
}

// keywords whose segment contains no command.
var skipKeywords = map[string]bool{
	"fi": true, "done": true, "esac": true, "}": true, "for": true, "case": true, "select": true,
}

// mutating commands: their path arguments are checked as writes.
var mutating = map[string]bool{
	"rm": true, "rmdir": true, "mv": true, "cp": true, "touch": true, "mkdir": true,
	"tee": true, "ln": true, "chmod": true, "chown": true, "truncate": true,
	"unlink": true, "install": true,
}

var assignRe = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*=`)

type token struct {
	text string
	op   bool // a redirection operator
}

// splitCommands splits a command line into simple commands (separated by
// ;, &, &&, ||, |, newlines and parentheses) made of words and
// redirection operators. Quotes are removed from words.
func splitCommands(line string) ([][]token, error) {
	var (
		cmds   [][]token
		cur    []token
		word   strings.Builder
		inWord bool
		quote  rune // 0, '\'' or '"'
	)
	flushWord := func() {
		if inWord {
			cur = append(cur, token{text: word.String()})
			word.Reset()
			inWord = false
		}
	}
	flushCmd := func() {
		flushWord()
		if len(cur) > 0 {
			cmds = append(cmds, cur)
			cur = nil
		}
	}
	rs := []rune(line)
	for i := 0; i < len(rs); i++ {
		c := rs[i]
		next := rune(0)
		if i+1 < len(rs) {
			next = rs[i+1]
		}
		if quote == '\'' {
			if c == '\'' {
				quote = 0
			} else {
				word.WriteRune(c)
			}
			continue
		}
		if c == '`' {
			return nil, errUnsupported{"command substitution (`...`)"}
		}
		if c == '$' && next == '(' {
			return nil, errUnsupported{"command substitution $(...)"}
		}
		if quote == '"' {
			switch {
			case c == '"':
				quote = 0
			case c == '\\' && next != 0:
				i++
				word.WriteRune(rs[i])
			default:
				word.WriteRune(c)
			}
			continue
		}
		switch {
		case c == '\\':
			if next == '\n' {
				i++ // line continuation
				continue
			}
			if next != 0 {
				i++
				word.WriteRune(rs[i])
				inWord = true
			}
		case c == '\'' || c == '"':
			quote = c
			inWord = true
		case c == ' ' || c == '\t':
			flushWord()
		case c == '#' && !inWord:
			// Comment to end of line.
			for i < len(rs) && rs[i] != '\n' {
				i++
			}
			flushCmd()
		case (c == '<' || c == '>') && next == '(':
			return nil, errUnsupported{"process substitution"}
		case c == '<' && next == '<':
			return nil, errUnsupported{"heredoc or here-string"}
		case c == '>' || c == '<' || (c == '&' && next == '>'):
			// A word made only of digits right before > is a file descriptor.
			if inWord && isDigits(word.String()) {
				word.Reset()
				inWord = false
			}
			flushWord()
			op := string(c)
			for i+1 < len(rs) && strings.ContainsRune(">&|", rs[i+1]) {
				i++
				op += string(rs[i])
			}
			cur = append(cur, token{text: op, op: true})
		case c == ';' || c == '\n' || c == '&' || c == '|' || c == '(' || c == ')':
			flushCmd()
		default:
			word.WriteRune(c)
			inWord = true
		}
	}
	if quote != 0 {
		return nil, errors.New("unterminated quote in command")
	}
	flushCmd()
	return cmds, nil
}

func isDigits(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}

// bashRequests lists the policy requests a command line implies. cwd is the
// directory the command starts in; `cd` updates it for later commands.
func bashRequests(line, cwd string) ([]request, error) {
	cmds, err := splitCommands(line)
	if err != nil {
		return nil, err
	}
	var reqs []request
	dir := cwd
	for _, toks := range cmds {
		r, newDir, err := commandRequests(toks, dir)
		if err != nil {
			return nil, err
		}
		reqs = append(reqs, r...)
		dir = newDir
	}
	return reqs, nil
}

func commandRequests(toks []token, dir string) ([]request, string, error) {
	var reqs []request
	var words []string
	// Redirections first: they apply whatever the command is.
	for i := 0; i < len(toks); i++ {
		t := toks[i]
		if !t.op {
			words = append(words, t.text)
			continue
		}
		if i+1 >= len(toks) || toks[i+1].op {
			return nil, dir, fmt.Errorf("redirection %q without a target", t.text)
		}
		target := toks[i+1].text
		i++
		if strings.HasSuffix(t.text, "&") || strings.HasPrefix(t.text, ">&") {
			if isDigits(target) || target == "-" {
				continue // fd duplication like 2>&1
			}
		}
		if target == "/dev/null" {
			continue
		}
		action := policy.ActionWrite
		if t.text == "<" {
			action = policy.ActionRead
		}
		reqs = append(reqs, request{action, abs(dir, target)})
	}

	// Find the command word.
	for len(words) > 0 {
		w := words[0]
		switch {
		case assignRe.MatchString(w):
			words = words[1:]
		case prefixKeywords[w]:
			words = words[1:]
		case skipKeywords[w]:
			return reqs, dir, nil
		case w == "exec" || w == "command" || w == "builtin" || w == "nohup":
			words = words[1:]
		default:
			goto found
		}
	}
	return reqs, dir, nil

found:
	name, args := words[0], words[1:]
	switch name {
	case "eval", "source", ".":
		return nil, dir, errUnsupported{name}
	}
	if name == "cd" || name == "pushd" {
		target := ""
		for _, a := range args {
			if !strings.HasPrefix(a, "-") {
				target = a
				break
			}
		}
		if target == "" || target == "~" {
			home, _ := os.UserHomeDir()
			target = home
		}
		next := abs(dir, target)
		reqs = append(reqs, request{policy.ActionRead, next})
		return reqs, next, nil
	}
	if !builtins[name] {
		reqs = append(reqs, request{policy.ActionExecute, name})
	}
	if name == "find" {
		for _, a := range args {
			switch a {
			case "-exec", "-execdir", "-ok", "-okdir", "-delete", "-fprint", "-fprintf", "-fls":
				return nil, dir, errUnsupported{"find " + a}
			}
		}
	}

	// Arguments that are paths: writes for mutating commands, reads for
	// anything else that names an existing file.
	for _, a := range args {
		if a == "" || strings.HasPrefix(a, "-") || a == "/dev/null" {
			continue
		}
		if !builtins[name] && strings.Contains(a, "$") && (strings.HasPrefix(a, "$") || strings.Contains(a, "/")) {
			// A variable would expand to a path the hook cannot see.
			return nil, dir, errUnsupported{"a variable in a file argument (" + a + ")"}
		}
		if mutating[name] {
			reqs = append(reqs, request{policy.ActionWrite, abs(dir, a)})
			continue
		}
		for _, p := range existingPaths(dir, a) {
			reqs = append(reqs, request{policy.ActionRead, p})
		}
	}
	return reqs, dir, nil
}

// existingPaths returns the paths an argument refers to on disk: itself if
// it exists, or what a shell glob would expand to.
func existingPaths(dir, arg string) []string {
	p := abs(dir, arg)
	if strings.ContainsAny(arg, "*?[") {
		matches, _ := filepath.Glob(p)
		return matches
	}
	if _, err := os.Lstat(p); err == nil {
		return []string{p}
	}
	// Absolute and home paths are checked even if they do not exist, so
	// probing for host files is refused too.
	if filepath.IsAbs(arg) || strings.HasPrefix(arg, "~") {
		return []string{p}
	}
	return nil
}

func abs(dir, p string) string {
	if strings.HasPrefix(p, "~/") || p == "~" {
		if home, err := os.UserHomeDir(); err == nil {
			p = home + strings.TrimPrefix(p, "~")
		}
	}
	if filepath.IsAbs(p) {
		return filepath.Clean(p)
	}
	return filepath.Join(dir, p)
}
