# fenced-obsidian-sync-mcp

A **deny-by-default, finely fenced** [MCP](https://modelcontextprotocol.io) server
over an Obsidian vault. The operator declares exactly which capabilities (`list`,
`read`, `create`, …) an agent gets, each scoped by path globs — and everything
else is *impossible by construction*, not merely guarded.

Other Obsidian MCP servers hand an agent broad read/write/search/delete. Here
**the fence is the product**: you can run it so an agent may *only* create notes
under `Inbox/`, or *only* see note titles, or touch nothing at all — and prove
the rest is impossible because the tools are never registered.

> Full design brief: [`docs/SPEC.md`](docs/SPEC.md). The "Core principles
> (security invariants)" there are requirements, and each is backed by a test.

## Install

```sh
pip install -e ".[http,dev]"     # http extra for remote serving; dev for tests
```

Requires Python ≥ 3.10.

## Run

```sh
fenced-obsidian-sync-mcp --config examples/create-only.yaml
# or
python -m fenced_obsidian_sync_mcp --config examples/create-only.yaml
```

By default this speaks **stdio** (for a local MCP client). Set
`transport.type: http` for remote serving (see below).

## The three canonical postures

Each is a complete, runnable config (full files in [`examples/`](examples/)).

### 1. Deny-all — a dark vault

The server runs but exposes **no tools at all**.

```yaml
mode: local
vault: /path/to/your/vault
capabilities: {}
```

### 2. Create-only — file, never read

The agent can drop new notes into `Inbox/` and do nothing else. No
`read`/`list`/`update`/`delete` tool is registered. Collisions never overwrite.

```yaml
mode: local
vault: /path/to/your/vault
collision: suffix          # fail | suffix
capabilities:
  create:
    enabled: true
    allow: ["Inbox/**"]
```

### 3. Titles-only — see names, not bodies

The agent learns which notes exist (to suggest links) but **no registered tool
can open their contents**. `read` and `read_metadata` are absent.

```yaml
mode: local
vault: /path/to/your/vault
capabilities:
  list:
    enabled: true
    allow: ["**/*.md"]
    deny:  ["Private/**", "Journal/**"]
```

## Capabilities

Every capability is **off by default** and independently path-scoped. Enabling
one registers exactly one tool; disabling it means the tool is **absent** from
the MCP tool list.

| Capability | Tool | Exposes | Opens file contents? |
|---|---|---|---|
| `list` | `list_notes` | enumerate paths / filenames | no — `readdir` only |
| `read_metadata` | `read_metadata` | frontmatter, tags, stat | frontmatter only |
| `read` | `read_note` | full note contents | yes |
| `search` | `search_notes` | content search (**implies `read`**) | yes |
| `create` | `create_note` | new files only, never overwrite | no |
| `update` | `update_note` | modify / append existing files | n/a |
| `delete` | `delete_note` | remove files | n/a |
| `move` | `move_note` | rename / relocate, never overwrite | n/a |

`search` implies `read`: enabling `search` without `read` is a config error,
because returning snippets while `read` is off would be a content oracle.

### Glob semantics

Globs use [`wcmatch`](https://facelessuser.github.io/wcmatch/) with `GLOBSTAR`,
evaluated against vault-relative POSIX paths:

- `**` spans directories (`**/*.md` matches at any depth); `*` matches within a
  single segment.
- **Case-sensitive.**
- Dotfiles are not matched unless a pattern names the leading dot, so `.obsidian/`
  stays out of `**/*.md`.
- **`deny` always beats `allow`** on every capability.

## Modes

- **`mode: local`** — point `vault` at a directory you already keep current
  (Syncthing, iCloud, git, or nothing). No sync subprocess, no `obsidian-headless`
  dependency. Works anywhere, including a phone via Termux.
- **`mode: sync`** — `vault` is your remote Obsidian Sync vault name and
  `vault_dir` is the local directory the official `obsidian-headless` client
  (`ob sync --continuous`) mirrors into. The server supervises that process.

The fence is identical in both modes; only how the directory stays current differs.

> ⚠️ **Sync-mode write warning:** in `sync` mode, `update`/`delete`/`move`
> propagate to **every** device on your Obsidian Sync. Create-only is the
> conflict-free default; enable writes deliberately.

## Transports

- **stdio** (default) — for a local MCP client.
- **HTTP** (`transport.type: http`) — streamable-http behind a **bearer token**
  (required) and **TLS**. Terminate TLS in-process (`transport.tls.certfile` /
  `keyfile`) or at a reverse proxy such as Caddy. Full OAuth is a future
  extension; bearer + TLS is the supported remote posture today.

```yaml
transport:
  type: http
  host: 0.0.0.0
  port: 8080
  auth: { bearer_token: "a-long-random-secret" }
  tls:  { certfile: /etc/ssl/certs/server.crt, keyfile: /etc/ssl/private/server.key }
```

## Audit log

Optional structured JSONL of every allowed and denied call (capability, path,
decision, and — for denials — an internal reason never shown to the client):

```yaml
audit:
  enabled: true
  path: /var/log/fenced-obsidian-sync-mcp/audit.jsonl   # omit -> stderr
```

## Security invariants

These are guaranteed and tested (`tests/`):

1. **Deny by default** — a disabled capability's tool is *not registered*.
2. **Capabilities are independent** — knowing a note exists (`list`) is separate
   from its metadata (`read_metadata`) is separate from its body (`read`).
3. **Path confinement** — `..`, absolute paths, escaping symlinks, and
   percent-/double-encoded separators are all rejected.
4. **No silent overwrite** — `create` uses `O_EXCL`; collisions `fail` or `suffix`.
5. **Glob-scoped, deny-wins** — `deny` always beats `allow`.
6. **No existence oracle** — denied paths return a uniform `not permitted`.
7. **Auditable** — optional structured log; a small, readable codebase.

## Development

```sh
pip install -e ".[http,dev]"
pytest        # full invariant + acceptance suite
ruff check .
```

## License

MIT
