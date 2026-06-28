# fenced-obsidian-sync-mcp — Mini-Spec

> Source-of-truth spec for the `fenced-obsidian-sync-mcp` project. Intended to be handed to a coding agent as the build brief. The security invariants are requirements, not suggestions.

## Purpose

An MCP server that exposes a **deny-by-default, finely fenced** interface to an Obsidian vault. The operator declares exactly which capabilities (`list`, `read`, `create`, …) are allowed, each scoped by path globs. Every other Obsidian MCP grants broad read/write/search/delete; here the **fence is the product**. You can run it so an agent may *only* create notes under `Inbox/`, or *only* see note titles, or touch nothing at all — and prove the rest is impossible by construction.

Runs self-hosted on a box or locally (including a phone via Termux). Two vault-population modes, configurable:

- **sync** — wraps the official `obsidian-headless` client (`ob sync --continuous`) so the box mirrors your vault over Obsidian Sync.
- **local** — points at any vault directory you already keep current yourself (Syncthing, iCloud, git, or nothing).

The fence is identical in both modes; only how the directory stays current differs.

## Core principles (security invariants — non-negotiable)

1. **Deny by default.** No capability is active unless explicitly enabled. A disabled capability's tool is *not registered* at all — there is no surface to guard, rather than a guarded surface.
2. **Capabilities are independent.** Knowing a note *exists* (`list`) is separate from reading its *frontmatter* (`read_metadata`) is separate from reading its *contents* (`read`). "Titles/paths only" means `list` on and everything else off.
3. **Path confinement.** Every resolved path must stay inside the vault root. Reject `..`, absolute paths, symlinks escaping the root, and percent-/double-encoded separators (this exact traversal class has been a real CVE in comparable Obsidian tools — include a regression test for it).
4. **No silent overwrite.** `create` uses atomic exclusive create (`O_EXCL` / `open(path, 'x')`). An existing file is never clobbered. Collision behaviour (`fail` | `suffix`) is configurable.
5. **Glob-scoped, deny-wins.** Each capability carries `allow`/`deny` glob lists; `deny` always beats `allow`.
6. **No existence oracle.** Operations on denied paths return a uniform "not permitted" that does not reveal whether the file exists.
7. **Auditable.** Optional structured audit log of every allowed and denied call (path + capability + decision). A small, readable codebase is itself a goal.

## Permission model

Capability flags, each **off by default**, each independently path-scoped:

| Capability | Exposes | Reads file contents? |
|---|---|---|
| `list` | enumerate paths / filenames (titles) | no — `readdir` only |
| `read_metadata` | frontmatter, tags, stat | opens file, parses frontmatter only |
| `read` | full note contents | yes |
| `search` | content/metadata search (implies `read`) | yes |
| `create` | new files only, never overwrite | no |
| `update` | modify / append / patch existing files | n/a |
| `delete` | remove files | n/a |
| `move` | rename / relocate | n/a |

Illustrative config (agent may refine the exact format):

```yaml
mode: sync            # sync | local
vault: "My Vault"     # remote vault name (sync) or directory path (local)
collision: suffix     # fail | suffix

capabilities:
  list:
    enabled: true
    allow: ["**/*.md"]
    deny:  ["Private/**", "Journal/**"]
  create:
    enabled: true
    allow: ["Inbox/**"]
  read:    { enabled: false }
  update:  { enabled: false }
  delete:  { enabled: false }
```

The three canonical postures expressed in this model:

- **Deny everything** — every capability `enabled: false`. The server runs but exposes no tools (a dark vault).
- **Create-only** — only `create.enabled: true`, scoped to e.g. `Inbox/**`.
- **Titles/paths only** — only `list.enabled: true`; `read` and `read_metadata` off.

## User stories

### A — Privacy-conscious note-taker (create-only)
**As** someone who wants an AI to file notes into my vault without ever reading it, **I want** to enable only `create` scoped to `Inbox/`, **so that** the agent can drop new notes but cannot see or alter anything existing.

Acceptance criteria:
- With only `create` enabled, no `read`/`list`/`update`/`delete` tools appear in the MCP tool list.
- Creating a note in an allowed path succeeds; creating outside the `allow` globs is refused.
- A create whose path already exists never overwrites: `collision: suffix` lands a new file, `fail` errors out.
- The agent cannot retrieve contents or even filenames of existing notes.

### B — Read-only researcher
**As** a user who wants an AI to search and reference my notes but never change them, **I want** `list` + `read` + `search` on and all write capabilities off, **so that** my vault is strictly read-only to the agent.

Acceptance criteria:
- No `create`/`update`/`delete`/`move` tools are registered.
- `read`/`search` return only files matching `allow` globs; denied subtrees (e.g. `Private/**`) never surface in results.
- Any write attempt returns a permission error with no side effects.

### C — Titles-only linker
**As** a user who wants the agent to know what notes exist (to suggest links) without reading their contents, **I want** `list` only, **so that** it sees paths/titles but no bodies.

Acceptance criteria:
- `list` returns paths/filenames within `allow` globs; no registered tool can open file contents.
- `read_metadata` and `read` tools are absent.

### D — Self-hoster / operator
**As** an operator running this on a box, **I want** a single declarative config with deny-by-default, **so that** I can see at a glance exactly what the agent may touch and trust the rest is impossible.

Acceptance criteria:
- A minimal/empty config yields a server that exposes nothing.
- Every enabled capability and its globs live in one file; changing policy needs no code edits.
- An optional audit log records allowed and denied calls with path + capability.
- Remote deployment supports HTTP transport behind bearer-token/OAuth auth and TLS; local deployment supports stdio.

### E — Local / Termux / phone operator
**As** someone running it locally (including on Android via Termux), **I want** `mode: local` pointed at my on-device vault folder, **so that** the fence and the vault both stay on my device with no server holding either.

Acceptance criteria:
- `mode: local` runs against a given directory with no sync subprocess and no `obsidian-headless` dependency.
- Capability/glob semantics are identical to sync mode.

### F — Sync operator
**As** a user who wants the box kept mirrored with my other devices, **I want** `mode: sync` to manage the official `obsidian-headless` client, **so that** notes created through the MCP propagate via Obsidian Sync.

Acceptance criteria:
- In sync mode the server runs and monitors `ob sync --continuous` against the vault directory.
- Notes created through the MCP appear on other Sync devices.
- If `update`/`delete` are enabled in sync mode, the docs warn that changes propagate to every device; create-only is the conflict-free default.

## Non-goals

- Not a general-purpose filesystem MCP — strictly vault-scoped.
- Not a sync engine — it wraps Obsidian's official headless client or relies on your existing sync; it does not reimplement syncing.
- Not a full Obsidian bridge — no command palette, plugin execution, rendering, or graph access.
- No built-in LLM, embeddings, or semantic indexing in core (`search` is plain content/metadata search).
- Not multi-tenant — one vault and one operator-defined policy per instance.
- Does not encrypt the vault at rest — that is the operator's responsibility (e.g. LUKS).

## Open questions for the implementing agent

- Language/SDK: Python MCP SDK vs TypeScript MCP SDK (maintainer preference).
- Config format: YAML vs TOML.
- Whether `read_metadata` is its own capability or folded into `read`.
- Whether `search` may return matching paths/snippets when `read` is off, or strictly implies full `read`.
- Glob engine semantics (`**` behaviour, case sensitivity) — pick one library and document it.
