package sandbox

import (
	"bytes"
	"context"
	"crypto/sha256"
	_ "embed"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/longvo2k/agentguard/internal/policy"
)

//go:embed Dockerfile
var dockerfile []byte

// Dockerfile returns the embedded sandbox image definition.
func Dockerfile() []byte { return dockerfile }

// ErrCommandDenied is returned when the requested command is not allowed.
var ErrCommandDenied = errors.New("command denied by policy")

// DockerArgs returns the full `docker run` argument list for argv. The
// command is passed as an argument vector and is never interpreted by a
// host shell.
func (p *Plan) DockerArgs(argv []string, tty bool) []string {
	o := p.Options
	args := []string{
		"run", "--rm", "-i",
		"--pull=never",
		"--init",
		"--label", "org.agentguard=1",
		"--label", "org.agentguard.role=" + p.Engine.Policy().Role,
		"--hostname", "agentguard",
		"--user", fmt.Sprintf("%d:%d", p.UID, p.GID),
		"--cap-drop", "ALL",
		"--security-opt", "no-new-privileges",
		"--read-only",
		"--ipc", "private",
		"--tmpfs", "/tmp:rw,noexec,nosuid,nodev,size=256m",
		"--tmpfs", HomeDir + ":rw,noexec,nosuid,nodev,size=256m,mode=1777",
		"--workdir", WorkspaceDir,
		// Only these variables exist inside; nothing is inherited from the host.
		"--env", "HOME=" + HomeDir,
		"--env", "PATH=" + ShimDir,
		"--env", "USER=agent",
		"--env", "npm_config_update_notifier=false",
		"--env", "npm_config_cache=" + HomeDir + "/.npm",
		"--env", "GIT_CONFIG_NOSYSTEM=1",
		"--env", "GIT_CONFIG_COUNT=1",
		"--env", "GIT_CONFIG_KEY_0=safe.directory",
		"--env", "GIT_CONFIG_VALUE_0=" + WorkspaceDir,
	}
	if _, ok := o.CommandPaths["npm"]; ok {
		// npm runs package scripts through a shell, which is not on PATH.
		// Allowing npm therefore allows its scripts to use /bin/sh (with the
		// same restricted PATH). This is documented as a known limitation.
		args = append(args, "--env", "npm_config_script_shell=/bin/sh")
	}
	if p.Network {
		args = append(args, "--network", "bridge")
	} else {
		args = append(args, "--network", "none")
	}
	if o.PidsLimit > 0 {
		args = append(args, "--pids-limit", strconv.Itoa(o.PidsLimit))
	}
	if o.Memory != "" {
		args = append(args, "--memory", o.Memory)
	}
	if o.CPUs != "" {
		args = append(args, "--cpus", o.CPUs)
	}
	if tty {
		args = append(args, "-t", "--env", "TERM=xterm-256color")
	}
	for _, m := range p.Mounts {
		spec := "type=bind,source=" + m.Source + ",target=" + m.Target
		if m.ReadOnly {
			spec += ",readonly"
		}
		args = append(args, "--mount", spec)
	}
	// The image's own entrypoint never runs: the process started is exactly
	// the allowed command, via its PATH shim.
	if len(argv) > 0 {
		args = append(args, "--entrypoint", path.Join(ShimDir, argv[0]))
		argv = argv[1:]
	}
	args = append(args, o.Image)
	return append(args, argv...)
}

// Run checks argv[0] against the policy and, if allowed, runs it in a new
// container. It returns the command's exit code.
func (p *Plan) Run(ctx context.Context, argv []string, stdin io.Reader, stdout, stderr io.Writer) (int, error) {
	if len(argv) == 0 {
		return 0, errors.New("no command given")
	}
	if d := p.Engine.Evaluate(policy.ActionExecute, argv[0]); !d.Allowed {
		return 126, fmt.Errorf("%w: %s (%s)", ErrCommandDenied, argv[0], d.Reason)
	}
	cmd := exec.CommandContext(ctx, "docker", p.DockerArgs(argv, IsTerminal(stdin) && IsTerminal(stdout))...)
	cmd.Stdin, cmd.Stdout, cmd.Stderr = stdin, stdout, stderr
	cmd.Env = dockerEnv()
	err := cmd.Run()
	var exit *exec.ExitError
	if errors.As(err, &exit) {
		return exit.ExitCode(), nil
	}
	if err != nil {
		return 1, err
	}
	return 0, nil
}

// Available reports whether a Docker daemon is reachable.
func Available(ctx context.Context) error {
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	if _, err := exec.LookPath("docker"); err != nil {
		return errors.New("docker CLI not found in PATH")
	}
	cmd := exec.CommandContext(ctx, "docker", "version", "--format", "{{.Server.Version}}")
	cmd.Env = dockerEnv()
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("docker daemon not reachable: %s", strings.TrimSpace(string(out)))
	}
	return nil
}

// EnsureImage makes sure image is available locally and returns the
// reference to run. A missing image is pulled. If that fails and fallback is
// set, the embedded Dockerfile is built once, tagged fallback, and fallback
// is returned instead.
func EnsureImage(ctx context.Context, image, fallback string, log io.Writer) (string, error) {
	if ImageExists(ctx, image) {
		return image, nil
	}
	fmt.Fprintf(log, "Pulling sandbox image %s (first run only)...\n", image)
	pull := exec.CommandContext(ctx, "docker", "pull", "--quiet", image)
	pull.Env = dockerEnv()
	pullOut, pullErr := pull.CombinedOutput()
	if pullErr == nil {
		return image, nil
	}
	if fallback == "" {
		return "", fmt.Errorf("sandbox image %q is not available: %s", image, strings.TrimSpace(string(pullOut)))
	}
	if ImageExists(ctx, fallback) {
		return fallback, nil
	}
	fmt.Fprintf(log, "Pull failed (%s); building %s from the built-in Dockerfile instead...\n", firstLine(pullOut), fallback)
	build := exec.CommandContext(ctx, "docker", "build", "--quiet", "-t", fallback, "-")
	build.Env = dockerEnv()
	build.Stdin = bytes.NewReader(dockerfile)
	var out bytes.Buffer
	build.Stdout, build.Stderr = &out, &out
	if err := build.Run(); err != nil {
		return "", fmt.Errorf("pulling %s failed and building %s failed: %v\n%s", image, fallback, err, out.String())
	}
	return fallback, nil
}

// ImageExists reports whether image is present locally.
func ImageExists(ctx context.Context, image string) bool {
	inspect := exec.CommandContext(ctx, "docker", "image", "inspect", "--format", "{{.Id}}", image)
	inspect.Env = dockerEnv()
	return inspect.Run() == nil
}

func firstLine(b []byte) string {
	s, _, _ := strings.Cut(strings.TrimSpace(string(b)), "\n")
	return s
}

// dockerEnv is the environment for the docker CLI itself (not the
// container). It is inherited so DOCKER_HOST, contexts and proxies work;
// the container environment is built explicitly in DockerArgs.
func dockerEnv() []string { return os.Environ() }

// IsTerminal reports whether v is an *os.File attached to a terminal.
func IsTerminal(v any) bool {
	f, ok := v.(*os.File)
	if !ok {
		return false
	}
	fi, err := f.Stat()
	return err == nil && fi.Mode()&os.ModeCharDevice != 0
}

// ImageID returns the local ID of image.
func ImageID(ctx context.Context, image string) (string, error) {
	cmd := exec.CommandContext(ctx, "docker", "image", "inspect", "--format", "{{.Id}}", image)
	cmd.Env = dockerEnv()
	out, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("sandbox image %q not found locally", image)
	}
	return strings.TrimSpace(string(out)), nil
}

// probeScript prints "name=path" for each argument found on the image's
// PATH. Names arrive as positional arguments, never spliced into the script.
const probeScript = `for c in "$@"; do p=$(command -v "$c" 2>/dev/null) && case "$p" in /*) printf '%s=%s\n' "$c" "$p";; esac; done`

// ResolveCommands finds where each command lives inside image, so that only
// allowed commands are placed on the sandbox PATH. The probe itself runs in
// a locked-down container. Results are cached in cacheDir by image ID.
func ResolveCommands(ctx context.Context, image string, commands []string, cacheDir string) (map[string]string, error) {
	if len(commands) == 0 {
		return map[string]string{}, nil
	}
	id, err := ImageID(ctx, image)
	if err != nil {
		return nil, err
	}
	sorted := append([]string(nil), commands...)
	sort.Strings(sorted)
	sum := sha256.Sum256([]byte(id + "\n" + strings.Join(sorted, "\n")))
	cacheFile := ""
	if cacheDir != "" {
		cacheFile = filepath.Join(cacheDir, "commands-"+hex.EncodeToString(sum[:8])+".json")
		if data, err := os.ReadFile(cacheFile); err == nil {
			var m map[string]string
			if json.Unmarshal(data, &m) == nil {
				return m, nil
			}
		}
	}
	args := []string{"run", "--rm", "--pull=never", "--network", "none", "--cap-drop", "ALL",
		"--security-opt", "no-new-privileges", "--read-only", "--user", "65534:65534",
		"--entrypoint", "/bin/sh", image, "-c", probeScript, "agentguard-probe"}
	cmd := exec.CommandContext(ctx, "docker", append(args, sorted...)...)
	cmd.Env = dockerEnv()
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("probing commands in %s (the image needs /bin/sh): %v %s", image, err, strings.TrimSpace(stderr.String()))
	}
	m := map[string]string{}
	for _, line := range strings.Split(string(out), "\n") {
		name, p, ok := strings.Cut(strings.TrimSpace(line), "=")
		if ok && path.IsAbs(p) && !strings.ContainsAny(p, ",\"") {
			m[name] = path.Clean(p)
		}
	}
	if cacheFile != "" {
		if err := os.MkdirAll(cacheDir, 0o700); err == nil {
			data, _ := json.Marshal(m)
			_ = os.WriteFile(cacheFile, data, 0o600)
		}
	}
	return m, nil
}
