# Example policies

Copy any of these into `.agentguard/policies/` to use it. The file name
must match the `role:` field.

| File | Shows |
|---|---|
| `policies/docs-writer.yaml` | Anchored single files (`./README.md`), read-only source access |
| `policies/dependency-installer.yaml` | A short-lived role with network access |
| `policies/fix-issue-142.yaml` | Task-scoped permissions with `metadata.expires_at` |

Check a policy before using it:

```sh
cp examples/policies/docs-writer.yaml .agentguard/policies/
agentguard check --role docs-writer write docs/intro.md   # ALLOW
agentguard check --role docs-writer write src/app.js      # DENY
agentguard run --role docs-writer --dry-run -- node build-docs.js
```
