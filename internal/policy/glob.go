package policy

import (
	"errors"
	"fmt"
	"path"
	"strings"
)

// pattern is a compiled path pattern.
//
// Matching follows .gitignore conventions so policies read naturally:
//
//   - A pattern without a slash (".env*", "*.pem", "node_modules") matches a
//     file or directory name at any depth.
//   - A pattern with a slash ("src/**", "secrets/**", "./package.json") is
//     anchored at the workspace root. A leading "./" only anchors.
//   - "**" matches zero or more path segments; "*", "?" and "[...]" match
//     within a single segment.
//   - If a directory matches, everything below it matches too.
//   - A pattern starting with "/" or "~/" is an absolute host path and is
//     only meaningful in deny lists.
type pattern struct {
	raw      string
	segs     []string
	anchored bool
	absolute bool
}

var errEmptyPattern = errors.New("empty pattern")

func compilePattern(raw string, home string) (pattern, error) {
	p := strings.TrimSpace(raw)
	if p == "" {
		return pattern{}, errEmptyPattern
	}
	if strings.ContainsRune(p, 0) {
		return pattern{}, fmt.Errorf("pattern %q contains a NUL byte", raw)
	}
	pt := pattern{raw: raw}
	switch {
	case p == "~" || strings.HasPrefix(p, "~/"):
		if home == "" {
			return pattern{}, fmt.Errorf("pattern %q uses ~ but the home directory is unknown", raw)
		}
		p = home + strings.TrimPrefix(p, "~")
		pt.absolute = true
	case strings.HasPrefix(p, "/"):
		pt.absolute = true
	case strings.HasPrefix(p, "~"):
		return pattern{}, fmt.Errorf("pattern %q: ~user is not supported", raw)
	}
	dotSlash := strings.HasPrefix(p, "./")
	p = strings.TrimPrefix(p, "./")
	p = strings.TrimSuffix(p, "/")
	if p == "" {
		return pattern{}, fmt.Errorf("pattern %q matches nothing useful", raw)
	}
	pt.anchored = pt.absolute || dotSlash || strings.Contains(p, "/")
	for _, s := range strings.Split(strings.TrimPrefix(p, "/"), "/") {
		switch s {
		case "":
			continue
		case ".", "..":
			return pattern{}, fmt.Errorf("pattern %q must not contain %q segments", raw, s)
		}
		if _, err := path.Match(s, ""); err != nil {
			return pattern{}, fmt.Errorf("pattern %q: %w", raw, err)
		}
		pt.segs = append(pt.segs, s)
	}
	if len(pt.segs) == 0 && !pt.absolute {
		return pattern{}, fmt.Errorf("pattern %q matches nothing useful", raw)
	}
	// "**" means everything, the workspace root included. Matching it as a
	// name pattern would miss the root, which has no name.
	allDoubleStar := true
	for _, seg := range pt.segs {
		allDoubleStar = allDoubleStar && seg == "**"
	}
	if allDoubleStar {
		pt.anchored = true
	}
	return pt, nil
}

// match reports whether the slash-separated path segments (workspace-relative,
// or absolute host segments for absolute patterns) match the pattern. When
// fold is true the comparison is case-insensitive.
func (p pattern) match(segs []string, fold bool) bool {
	ps := p.segs
	if fold {
		ps = lowerAll(ps)
		segs = lowerAll(segs)
	}
	if !p.anchored {
		// Name pattern: any single component matching means the component
		// (or a directory containing the path) matches.
		for _, s := range segs {
			if ok, _ := path.Match(ps[0], s); ok {
				return true
			}
		}
		return false
	}
	// Anchored: the path itself or any of its ancestors must match.
	if matchSegs(ps, segs) {
		return true
	}
	for i := 1; i < len(segs); i++ {
		if matchSegs(ps, segs[:i]) {
			return true
		}
	}
	return false
}

// literalPrefix returns the leading segments that contain no glob syntax.
// It is used by the sandbox to decide which host directory to mount.
func (p pattern) literalPrefix() []string {
	var out []string
	for _, s := range p.segs {
		if strings.ContainsAny(s, "*?[\\") {
			break
		}
		out = append(out, s)
	}
	return out
}

// isLiteral reports whether the pattern has no glob syntax at all.
func (p pattern) isLiteral() bool {
	return len(p.literalPrefix()) == len(p.segs)
}

func matchSegs(p, s []string) bool {
	for len(p) > 0 {
		if p[0] == "**" {
			for len(p) > 0 && p[0] == "**" {
				p = p[1:]
			}
			if len(p) == 0 {
				return true
			}
			for i := 0; i <= len(s); i++ {
				if matchSegs(p, s[i:]) {
					return true
				}
			}
			return false
		}
		if len(s) == 0 {
			return false
		}
		if ok, _ := path.Match(p[0], s[0]); !ok {
			return false
		}
		p, s = p[1:], s[1:]
	}
	return len(s) == 0
}

func lowerAll(in []string) []string {
	out := make([]string, len(in))
	for i, s := range in {
		out[i] = strings.ToLower(s)
	}
	return out
}

func splitPath(p string) []string {
	var out []string
	for _, s := range strings.Split(p, "/") {
		if s != "" && s != "." {
			out = append(out, s)
		}
	}
	return out
}
