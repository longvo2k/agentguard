# AgentGuard

**Least-privilege sandboxing for AI coding agents.**
*Give AI agents only the access they need.*

> **Status: experimental MVP (v0.1).** AgentGuard enforces real technical
> boundaries, but it has not been audited and has known gaps (listed
> [below](#known-limitations)). Do not rely on it as your only protection for
> production secrets yet.

---

AgentGuard runs an AI coding agent (or any command) inside a disposable
Docker container that can only see, change and run what the agent's **role
policy** allows. A developer agent gets `src/` and `tests/`. It does not get
your `.env`, your `~/.ssh`, your production config or the internet, and that
is enforced by the kernel, not by asking the model nicely.

```yaml
# .agentguard/policies/developer.yaml
role: developer
filesystem:
  read:  [src/**, tests/**, logs/**]
  write: [src/**, tests/**]
commands:
  allow: [git, node, npm]
network:
  enabled: false
deny: [.env*, secrets/**, production/**, ~/.ssh/**]
```

```console
$ agentguard run --role developer -- npm test     # runs in the sandbox
$ agentguard check read .env                      # DENY (exit 1)
```

## Why agents need least privilege

Coding agents read files, run shell commands and install packages on your
behalf. Today most of them run with **your** permissions: every file in your
home directory, every credential in your environment, your SSH keys, your
cloud CLIs and an open network connection.

Telling an agent "don't read `.env`" is not a security control. A prompt
injection hidden in a README, an issue or a dependency can make the agent do
otherwise, and a well-meaning agent can still `cat` the wrong file while
debugging. The safe default is the one we already use for people and
services: **grant only the access a task needs, enforce it outside the
actor, and log every decision.**

AgentGuard does exactly that for a local workspace:

- **Policies are data**, written in YAML, per role.
- **Enforcement is outside the agent.** Files you deny are never mounted into
  its container, writes outside allowed paths fail with `EROFS`, the network
  interface does not exist, and denied commands are refused before Docker
  starts.
- **Every decision is audited** to a JSONL log the agent cannot reach.

## 30-second demo

Requires Go and a running Docker daemon.

```console
$ go install github.com/longvo2k/agentguard/cmd/agentguard@latest
$ agentguard demo
```

The demo creates a throwaway project containing fake secrets, then shows the
policy engine and a real container refusing to hand them over:

```text
1. Policy engine (what `agentguard check` answers)
   ✓ ALLOW read     src/app.js              filesystem.read: src/**
   ✓ ALLOW write    src/app.js              filesystem.write: src/**
   ✓ ALLOW read     logs/app.log            filesystem.read: logs/**
   ✓ ALLOW execute  npm                     commands.allow: npm
   ✗ DENY  read     .env                    matches deny rule (deny: .env*)
   ✗ DENY  read     secrets/api-key.txt     matches deny rule (deny: secrets/**)
   ✗ DENY  read     src/../.env             matches deny rule (deny: .env*)
   ✗ DENY  read     ~/.ssh/id_rsa           path is outside the workspace
   ✗ DENY  execute  curl                    command is not in commands.allow (default deny)

2. Sandbox enforcement (a real Docker container)
   ✓ Read src/app.js
   ✓ Write src/app.js
   ✓ Read logs/app.log
   ✓ Execute npm (npm 10.9.9)
   ✗ Read .env
     Permission denied: not present in the sandbox (never mounted)
   ✗ Read secrets/api-key.txt
     Permission denied: not present in the sandbox (never mounted)
   ✗ Read src/config/.env.local (inside an allowed folder)
     Permission denied: hidden behind an unreadable placeholder
   ✗ Write logs/app.log
     Permission denied: mounted read-only
   ✗ Connect to the internet
     Permission denied: the sandbox has no network
   ✗ Execute curl
     Permission denied: not in commands.allow, blocked before any container starts
```

Part 2 is not a simulation. A `node` process inside the container really
tries each operation and reports the kernel's answer. The demo also works as
a self-test: it exits non-zero if any boundary does not hold. Use
`agentguard demo --keep` to explore the project afterwards, or
`--no-docker` to see only the policy engine.

The first run builds the sandbox image (`node:22-alpine` plus `git`), which
needs access to Docker Hub and the Alpine package mirror.

## Installation

**Requirements:** Linux or macOS, Go 1.22+, Docker 20.10+ (Docker Desktop,
Colima, OrbStack or Docker Engine).

```sh
# from source
git clone https://github.com/longvo2k/agentguard
cd agentguard
make build            # produces ./bin/agentguard, a single static binary
make install          # or: go install ./cmd/agentguard

# or directly
go install github.com/longvo2k/agentguard/cmd/agentguard@latest
```

The only Go dependency is `gopkg.in/yaml.v3`. AgentGuard talks to Docker
through the `docker` CLI, so `DOCKER_HOST` and Docker contexts work as usual.

## Usage

### `agentguard init`

Creates the workspace configuration in the current directory:

```text
.agentguard/
├── config.yaml          # default role, image, resource limits
└── policies/
    ├── developer.yaml
    ├── tester.yaml
    └── reviewer.yaml
```

Existing files are never overwritten unless you pass `--force`.

### `agentguard check [--role R] <action> [resource]`

Asks the policy engine for a decision without running anything. Exit code
`0` means allow, `1` deny, `2` usage or configuration error, so it works in
scripts and agent hooks. Paths are relative to the workspace root.

```console
$ agentguard check read src/app.js
ALLOW  read src/app.js  [role developer]
  filesystem.read: src/**

$ agentguard check --role reviewer write src/app.js
DENY  write src/app.js  [role reviewer]
  no filesystem.write rule matches (default deny)

$ agentguard check --json read secrets/api-key.txt
{"action":"read","decision":"deny","path":"secrets/api-key.txt","reason":"matches deny rule","resource":"secrets/api-key.txt","role":"developer","rule":"deny: secrets/**"}
```

Actions are `read`, `write`, `execute` and `network`.

### `agentguard run [--role R] [--image I] [--dry-run] [-v] -- <command> [args...]`

Runs one command in a fresh sandbox and removes the container when it exits.
The exit code is the command's.

```sh
agentguard run --role developer -- npm test
agentguard run --role tester -- node --test tests/
agentguard run --role reviewer -- git log --oneline -20
agentguard run --role developer --dry-run -- npm test   # print the plan and docker command
```

The command must be in the role's `commands.allow`. It is passed to Docker as
an argument vector and never interpreted by a host shell. To run an
interactive agent inside the sandbox, allow its binary in the policy and use
an image that contains it (see [Roadmap](#roadmap)).

### `agentguard audit [--tail N] [--denied] [--role R] [--json]`

Summarizes `.agentguard/audit.jsonl`:

```text
Audit summary: 20 decisions (12 allowed, 8 denied)

By action:
  execute          2 allowed      3 denied
  network          0 allowed      3 denied
  read             4 allowed      1 denied
  write            6 allowed      1 denied

Most denied:
     1× execute bash
     1× read .env

Last 8 decisions:
  ✓ 20:04:46  developer  read     logs/
  ✓ 20:04:46  developer  write    src/
  ✗ 20:04:47  developer  execute  bash  (command is not in commands.allow (default deny))
```

Each line of the log is one decision:

```json
{"timestamp":"2026-10-03T20:04:26Z","role":"developer","action":"read","resource":".env","decision":"deny","reason":"matches deny rule","rule":"deny: .env*","source":"check"}
```

## Policy configuration

A policy is one YAML file per role in `.agentguard/policies/<role>.yaml`.
Unknown keys are rejected, so a typo like `deney:` fails loudly instead of
silently dropping a rule.

```yaml
role: tester                      # must match the file name
description: Runs and writes tests.
filesystem:
  read:  [src/**, tests/**, logs/**]
  write: [tests/**]               # write implies read
  allow_sensitive: [.env.example] # opt out of the built-in sensitive list
commands:
  allow: [npm, node]              # bare executable names only
network:
  enabled: false
deny: [.env*, secrets/**, production/**, ~/.ssh/**]
metadata:                         # optional
  source: hand-written
  approved_by: alice@example.com
  expires_at: 2026-12-31T18:00:00Z  # after this, every request is denied
```

### Path patterns

Patterns follow `.gitignore` conventions:

| Pattern | Matches |
|---|---|
| `src/**` | `src/` and everything below it |
| `src/**/*.js` | `.js` files at any depth under `src/` |
| `docs/*.md` | `.md` files directly in `docs/` (`*` never crosses `/`) |
| `.env*` | any name starting with `.env`, **at any depth** (no `/` in the pattern) |
| `./package.json` | only the root `package.json` (`./` anchors) |
| `~/.ssh/**`, `/etc/**` | absolute host paths (deny lists only) |

If a directory matches, everything inside it matches too.

### How a request is decided

Evaluation is deterministic and **default-deny**. The first rule that applies
wins:

1. **Expired policy** → deny everything.
2. **Workspace boundary.** The path is resolved the way the kernel would,
   following each symlink in order, so `link/..` means the parent of the
   link's target. Anything outside the workspace is denied, whether reached by
   `../`, an absolute path, `~` or a symlink.
3. **Protected paths.** `.agentguard/` (at any depth) is never readable or
   writable. `.git/` is never writable, because hooks and config would run on
   your host.
4. **`deny` rules**, matched case-insensitively (so `.ENV` is caught on
   case-insensitive filesystems).
5. **Built-in sensitive files**, denied even if a policy forgets them:
   `.env*`, `*.pem`, `*.key`, `*.p12`, `*.pfx`, `id_rsa*`, `id_ed25519*`,
   `id_ecdsa*`, `id_dsa*`, `.ssh`, `.gnupg`, `.aws`, `.azure`, `.kube`,
   `.docker`, `.npmrc`, `.pypirc`, `.netrc`, `.git-credentials`,
   `.git/config`. A path listed in `allow_sensitive` skips this step only.
6. **Allow rules:** `filesystem.read` (plus `write`) for reads, and
   `filesystem.write` for writes. When `git` is allowed, `.git/**` is
   readable.
7. Otherwise **deny**.

Both the resolved path and the path as written must pass, so a symlink named
`.env-link` is denied even if it points somewhere harmless.

Commands are allowed only by exact, case-sensitive name. Paths (`/bin/sh`,
`./npm`) and anything with shell syntax (`npm;curl`) are denied.

### `config.yaml`

```yaml
version: 1
default_role: developer
audit_log: audit.jsonl          # always inside .agentguard/
sandbox:
  image: agentguard-sandbox:0.1 # built automatically; or any image with /bin/sh
  memory: 1g
  cpus: "2"
  pids_limit: 256
  user: "1000:1000"             # optional; never 0
```

More examples live in [`examples/`](examples/).

## Architecture

```text
               agentguard CLI  (cmd/agentguard)
     init     check      run       audit      demo
       │        │         │          │          │
       ▼        ▼         ▼          ▼          ▼
 ┌──────────┐ ┌──────────────┐ ┌──────────┐ ┌──────────┐
 │  config  │ │    policy    │ │  audit   │ │   demo   │
 │ discover │ │ parse+engine │ │  JSONL   │ │ temp proj│
 │ .agent-  │ │ Evaluate()   │─┤ observer │ └──────────┘
 │ guard/   │ │ default deny │ └──────────┘
 └──────────┘ └──────┬───────┘
                     │ allowed patterns, deny rules
                     ▼
              ┌──────────────┐   docker run --rm --network none --read-only
              │   sandbox    │──▶  --cap-drop ALL --user 1000:1000 ...
              │ Plan → mounts│     --mount src → /workspace/src (rw)
              │ hide, shims  │     --mount logs → /workspace/logs (ro)
              └──────────────┘     --mount <0000 file> → /workspace/src/.env.local
```

| Package | Job |
|---|---|
| `internal/policy` | Parses and validates YAML; `Engine.Evaluate(action, resource)` returns a `Decision` with the rule that decided it. Pure Go, no I/O except resolving symlinks. |
| `internal/sandbox` | Turns an engine into a `Plan` (mounts, hidden paths, PATH shims, uid) and runs it with `docker run`. The command gate lives in `Plan.Run`, so a plan cannot be run without checking the command. |
| `internal/audit` | Appends decisions to JSONL (mode 0600) and summarizes them. Hooked into the engine as an observer, so every evaluation is logged. |
| `internal/config` | Finds the workspace by walking up to `.agentguard/` and loads `config.yaml` and policies. Never falls back to built-in policies. |
| `internal/demo` | The self-checking demo. |

**How `run` works**

1. Load the role policy and check that the command is allowed. A denied
   command never reaches Docker.
2. Build the image if missing, and probe it (in a locked-down container) for
   the absolute path of each allowed command. The result is cached per image
   ID.
3. Plan the mounts:
   - Each allow pattern is reduced to its literal directory prefix (`src/**`
     → `src/`), read-only unless writable.
   - Mount sources that are symlinks, or that do not exist, are skipped.
   - The mounted trees are walked, and every entry a deny, sensitive or
     protected rule covers is covered by a read-only, mode-0000
     placeholder. Sockets and other special files are covered the same way.
     `.git/config` is replaced by a sanitized copy (git cannot run without
     one), and any `.git` inside a writable mount is re-mounted read-only.
4. Start the container with the command as its entrypoint (the image's own
   entrypoint never runs). PATH contains only symlinks to the allowed
   commands, and no host environment variables are passed in.

The design keeps future features additive. A task-scoped policy is just
another `Policy` with `metadata` (`expires_at` is already enforced), and a
different backend (gVisor, Firecracker, a remote host) would produce its
own plan from the same engine.

## Security model

AgentGuard assumes the agent, and anything it reads, may be hostile. It
trusts you, your Docker daemon, the Linux kernel and the sandbox image.

| Boundary | Mechanism | Strength |
|---|---|---|
| Files outside allowed paths | Not mounted at all; they do not exist in the container | **Strong** (kernel mount namespace) |
| Denied files inside allowed dirs | Read-only bind of a mode-0000 placeholder; no `CAP_DAC_OVERRIDE` to bypass it, read-only mount stops `chmod` | **Strong** for files present when the sandbox starts |
| Read-only paths | `readonly` bind mounts → `EROFS` | **Strong** |
| Path traversal / absolute paths / symlinks | Mount namespace: `../` and symlinks resolve inside the container, where only allowed paths exist. Engine: kernel-order resolution plus boundary check | **Strong** |
| Network | `--network none`: only loopback exists | **Strong** (on/off only) |
| Privilege | Non-root uid, `--cap-drop ALL`, `no-new-privileges`, setuid bits stripped in image, default seccomp, read-only root fs, `noexec` `/tmp` and home | **Strong**, at Docker's level |
| Host credentials | No host env vars, no home dir, no `~/.ssh`, no Docker socket; sockets in the workspace are hidden; `.git/config` sanitized | **Strong** for the listed sources |
| Agent tampering with policy/logs | `.agentguard/` never mounted, protected at any depth; nested `.agentguard/` refused | **Strong** |
| Command allowlist | Launch gate (hard) + PATH containing only allowed commands (soft) | **Partial**, see below |
| Resource exhaustion | `--pids-limit`, `--memory`, `--cpus` | **Basic** |

## Known limitations

These are real gaps in v0.1. Each is a design choice for the MVP, not an
oversight we are hiding.

1. **The command allowlist is not a hard boundary inside the container.**
   The *first* process must be allowed, and only allowed commands are on
   `PATH`. But an allowed interpreter (`node`, `npm`, `git`) can start any
   binary in the image by absolute path, and `npm` runs package scripts
   through `/bin/sh`. The hard limits are the filesystem, network and
   privilege boundaries above, which apply to every process. Keep the image
   minimal. A seccomp or LSM-based exec filter is on the roadmap.
2. **Mounts are per directory, not per pattern.** `src/**/*.js` mounts all of
   `src/`. Deny rules are still enforced through placeholders, but
   non-matching files that no rule denies become visible (or writable, for
   write patterns). AgentGuard prints a warning, and `agentguard check`
   stays precise.
3. **Hiding is decided at startup.** Files are inspected when the sandbox
   starts. A file *created during the run* in a writable directory (say a
   new `src/.env`) is visible to the agent, because it was written there,
   from inside or by you. Files the host adds mid-run under an allowed
   directory are visible too.
4. **Git history is readable when `git` is allowed.** `.git/objects` holds
   every committed version of every file, including secrets that were
   committed and later deleted. Do not allow `git` in repositories whose
   history contains secrets.
5. **The audit log records AgentGuard's decisions, not every syscall:**
   `check` calls, the command gate, network, and each mount and hidden path.
   Individual file reads inside the container are not logged; that would
   need FUSE or fanotify.
6. **Network is all-or-nothing.** There is no domain allowlist yet. A role
   with `network.enabled: true` can reach anything the host can, including
   LAN services and cloud metadata endpoints.
7. **Writes are trusted later.** Code an agent writes into `src/` may run on
   your host afterwards (tests, builds, `package.json` scripts, IDE tasks).
   AgentGuard limits *where* an agent writes, not *what*. Review changes
   before running them outside the sandbox.
8. **Docker is the isolation layer.** Container escapes via kernel or runtime
   bugs are out of scope, and access to the Docker daemon is itself
   root-equivalent on the host. Rootless Docker or gVisor (`runsc`) make the
   boundary stronger.
9. **Pre-existing hard links** inside an allowed directory to a denied file
   expose that file's contents. AgentGuard cannot tell them apart from the
   original. The sandbox itself cannot create such links.
10. **Time-of-check gaps.** The host filesystem can change between planning
    and container start, for example if another host process swaps a
    directory for a symlink.
11. **Running AgentGuard as root.** The sandbox then runs as uid 1000 (or
    `sandbox.user`), so writable directories must be writable by that uid.
12. **Only Linux and macOS** are supported. Windows paths are not handled.

## Roadmap

**v0.2 (next)**
- Network domain allowlist through an egress proxy in a sidecar container.
- Exec filtering inside the container (seccomp user notification or
  Landlock), making the command allowlist a hard boundary.
- File-level audit of reads and writes inside the sandbox (fanotify).
- Agent integrations: a `PreToolUse` hook for Claude Code and similar hooks
  for other agents that call `agentguard check`, plus images that ship an
  agent CLI.
- `agentguard policy lint` and `agentguard policy explain <path>`.
- Copy-in/copy-out mode for repositories with complex deny rules.

**Later**
- **Task-scoped permissions:** task → AI suggests a minimal policy → a human
  approves → a temporary policy with automatic expiry → sandbox. The
  `metadata` block and `expires_at` enforcement are the first piece.
- gVisor and microVM backends, and remote hosts.
- GitHub, Kubernetes and cloud IAM integrations that issue short-lived,
  scoped credentials instead of mounting long-lived ones.

## Development

```sh
make lint          # gofmt + go vet
make test-short    # unit tests, no Docker
make test          # everything; Docker tests run when a daemon is available
make test-docker   # just the container tests, verbose
AGENTGUARD_TEST_IMAGE=node:22 make test-docker   # reuse an existing image
```

The tests cover allowed and denied reads, writes and commands, wildcards,
path traversal, absolute paths, symlink escapes (including `link/..`),
`.env` and `secrets/**` protection, case-insensitive deny rules, expired
policies, and in real containers: unreadable placeholders, read-only mounts,
no network, non-root uid, no host environment, sanitized git config, a
read-only `.git` under broad write access, and the command gate.

Security reports and design critiques are very welcome. Please open an issue.

## License

[MIT](LICENSE)
