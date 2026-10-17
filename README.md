# MCP Tool Definition Pinning Checker

Pin an MCP server's tool definitions, then diff a later listing for silent changes. One read-only Python script. No third-party packages.

Use it on servers you own or are explicitly allowed to assess.

## Why it matters

[OWASP's description of MCP tool poisoning](https://owasp.org/www-community/attacks/MCP_Tool_Poisoning) calls out a trust gap: tool descriptions are reviewed once, when an agent first connects, and later server behavior is not checked the same way. A listing can still change after that review. This checker stores a normalized copy and a SHA-256 hash of each tool so you can diff a later `tools/list` export before you keep treating the server as unchanged.

## Quickstart

Requires Python 3.9 or newer. The standard library is enough.

This program does not connect to a server. From an MCP client you already use against a server you are authorized to assess, save the `tools/list` response to a file. The file can be any of these:

- a JSON-RPC response with `result.tools`
- an object with a `tools` array
- a bare list of tools

Pin that file, then check a later export against the lockfile:

```bash
python3 mcp_tool_pin_check.py pin \
  --listing tools-list.json \
  --lock mcp-tools.lock.json \
  --source my-notes-server

python3 mcp_tool_pin_check.py check \
  --listing tools-list.json \
  --lock mcp-tools.lock.json
```

`--source` is a label stored in the lockfile. If you omit it, the listing path is stored. `--pinned-at` sets the timestamp; if you omit it, the checker uses the current UTC time. `--json` prints the same result as JSON.

The examples are a small notes server. `examples/tools-list.changed.json` adds `create_note`, rewords `get_note`, and changes `list_notes` by adding an optional `limit` property and dropping `query` from `required`. `examples/tools-list.output.json` adds an `outputSchema` to each of those tools, and `examples/tools-list.output-enum-widened.json` adds `deleted` to the `get_note` output `status` enum. `examples/tools-list.identity.json` is the same tools plus an MCP initialize result. `examples/tools-list.identity-version.json`, `examples/tools-list.identity-protocol.json`, and `examples/tools-list.identity-name.json` change only `serverInfo.version`, `protocolVersion`, or `serverInfo.name`. The sample below sets `--pinned-at` so the timestamp is reproducible:

```bash
python3 mcp_tool_pin_check.py pin \
  --listing examples/tools-list.json \
  --lock /tmp/notes.lock.json \
  --source local-notes \
  --pinned-at 2026-10-08T00:00:00Z

python3 mcp_tool_pin_check.py check \
  --listing examples/tools-list.changed.json \
  --lock /tmp/notes.lock.json
```

`pin` prints:

```text
Pinned 2 tools to /tmp/notes.lock.json
source: local-notes
pinned_at: 2026-10-08T00:00:00Z
  get_note 1550f3326897f328ef901e418c632b3aad519ab9126415e51d63a82cb930e6b6
  list_notes 10fb955592a3ea05a96f15c689e5a8f52450c83a9d72b57bd98a42a20d35b758
```

`check` prints:

```text
MCP tool pin check
lock source: local-notes
pinned_at: 2026-10-08T00:00:00Z
result: drift

server identity:
  note: identity was not pinned

added (1):
  + create_note
removed (0):
  (none)
changed (2):
  ~ get_note
    description:
    --- description (pinned)
    +++ description (current)
    @@ -1 +1 @@
    -Return one note by its identifier.
    +Fetch a single saved note using its identifier.

  ~ list_notes
    schema:
    [widened] property added: properties.limit (optional)
    [widened] required removed: query
    schema widened: yes
unchanged (0): (none)
```

That check exits `1`.

## Exit codes

| Code | Meaning |
| --- | --- |
| `0` | The normalized tool listing matches the lockfile, and the pinned server name matches when identity was pinned. A server version change, a `protocolVersion` change, or identity added or removed does not by itself change this code. |
| `1` | Drift: a tool was added, removed, or its definition changed, including an output-schema change, or the pinned server name changed. |
| `2` | The listing or lockfile could not be read (missing file, invalid JSON, duplicate names, a lockfile hash that does not match its stored definition, or server identity that is present but not usable). |

## GitHub Actions

Commit the lockfile. Produce a fresh `tools/list` file in an earlier step you control, then fail the job when the listing has drifted:

```yaml
- name: Check pinned MCP tool definitions
  run: python3 mcp_tool_pin_check.py check --listing tools-list.json --lock mcp-tools.lock.json
```

This repository's own workflow runs the unit tests only. It does not contact an MCP server.

## What it does

Each tool is reduced to `name`, `description`, `inputSchema`, `outputSchema`, and `annotations` when annotations are present. Tools are sorted by name. `pin` writes a JSON lockfile (`lockfile_version` 1) with `pinned_at`, a source label, and one SHA-256 per normalized tool, plus the normalized definition. The hash is SHA-256 of the canonical JSON, with keys sorted, so `outputSchema` is covered by the same hash as `inputSchema`. A tool with no output schema stores `outputSchema: null`. `check` reports added tools, removed tools, a short unified diff when a description changed, input-schema changes, and output-schema changes on separate lines.

A schema line marked `[widened]` means the input schema accepts more than the pin:

- a new property
- a `required` name removed
- `enum` removed or given new values
- `maxLength` removed or increased
- `pattern` removed
- `additionalProperties` moving from `false` or a subschema to `true` or absent

Other input-schema edits are still drift. They are printed without `[widened]`. A tighter `maxLength`, for example, is a change and not a widening.

Output-schema findings are printed under `output schema:`, not in the input `schema:` block and not as `schema widened`. A new enum value anywhere in `outputSchema` is a line of its own:

```text
    output widened: properties.status.enum (added "deleted"); a new output enum value can break downstream exhaustive switches
```

That note is there because a caller with an exhaustive switch on the pinned enum can break when the server adds a value. Other output edits are `output changed` lines. Those include added or removed properties, type changes, and removed enum values. Output drift exits `1`.

A v0.1 lockfile has no `outputSchema` field. `check` still exits `0` when the current listing also has no output schema, so upgrading the checker does not fail that pin. Re-pinning the same listing writes a new hash, because the stored definition now includes `outputSchema: null`. If the listing has an `outputSchema` the old lock never pinned, `check` prints `output changed: outputSchema added (not present in the pin)` and exits `1`. That counts as drift: an output contract the pin never recorded is a definition change. Re-pin after you have reviewed the new schema.

## Server identity

`pin` can record which server produced the listing. Put the MCP `initialize` result in the same JSON file as the tools. The lock stores `serverInfo.name`, `serverInfo.version`, and `protocolVersion` when that field is present. Identity is not part of the tool hash. A listing with no identity writes the same tools-only lock as v0.2.0.

Either of these shapes works:

- `serverInfo` and optional `protocolVersion` on the same object as `tools`, or inside `result` next to `tools`
- an `initialize` object next to the tools. That object may be the initialize result itself, or a JSON-RPC response whose `result` is the initialize result

`examples/tools-list.identity.json` uses the `initialize` envelope. A later check against `examples/tools-list.identity-version.json` exits `0` and prints `server version changed`.

`check` prints a `server identity` section:

- `server version changed` is informational. A version bump on the same server name does not change the exit code.
- `protocol version changed` is informational, including when `protocolVersion` was added or dropped. It does not change the exit code.
- `server name changed` is drift and exits `1`, even when every tool still matches. A different `serverInfo.name` behind the same pin is a substitution signal: the listing may be from a different server than the one you reviewed.
- `identity added` and `identity removed` are reported on their own lines. They do not by themselves change the exit code. A tools-only export after an identity pin prints `identity removed` and still exits `0` when the tools and, if present, the server name are otherwise unchanged.

A v0.1 or v0.2.0 lock has no server identity. `check` still exits `0` when the tools match, and it prints `note: identity was not pinned`. If that later listing also includes an initialize result, the note is kept and `identity added` is printed. That added line is informational. Re-pin once you want the name and version stored.

```bash
python3 mcp_tool_pin_check.py pin \
  --listing examples/tools-list.identity.json \
  --lock /tmp/notes.lock.json \
  --source local-notes \
  --pinned-at 2026-10-08T00:00:00Z

python3 mcp_tool_pin_check.py check \
  --listing examples/tools-list.identity-version.json \
  --lock /tmp/notes.lock.json
```

## What it does not do

- It does not open a network connection, call `initialize` or `tools/list`, start a server, or modify an MCP server. You save those responses yourself.
- It does not execute text from descriptions or schemas. It only reads the files you name and writes the lockfile path you pass to `pin`.
- It does not decide that a description is safe or unsafe. It shows whether the stored definition changed.
- It does not pin tool fields other than name, description, input schema, output schema, and annotations. Server identity is only `serverInfo.name`, `serverInfo.version`, and `protocolVersion`.
- A clean check is not a full review of the server. It means the normalized tool definitions match and, when identity was pinned, the server name matches. A version or `protocolVersion` difference can still be printed as information.

## Authorized use

This repository is [MIT licensed](LICENSE). It is for **defensive checks only**.

- Pin and check tool listings from MCP servers you own or are authorized to assess.
- Save those listings from clients you are allowed to use.
- Do not point it at servers you are not allowed to review.

## Tests

From this directory:

```bash
python3 -m unittest tests.test_pin_check -v
python3 -m unittest discover -s tests -v
```

## Changelog

### v0.2.1

- `pin` records server identity from an MCP `initialize` result included in the listing JSON: `serverInfo.name`, `serverInfo.version`, and `protocolVersion` when it is present. Identity is stored on the lock and is not part of the tool hash. Listings without identity still produce a tools-only lock.
- `check` reports identity in its own section. `server version changed` and `protocol version changed` are informational and do not change the exit code. `server name changed` is drift and exits 1, because a different server name behind the same pin is a substitution signal. `identity added` and `identity removed` are reported and do not by themselves change the exit code.
- A v0.1 or v0.2.0 lock with no identity still checks cleanly (exit 0) when the tools match, and `check` prints `note: identity was not pinned`.

### v0.2.0

- `pin` stores and hashes each tool's `outputSchema` with the same canonical-JSON SHA-256 as the rest of the definition. A missing output schema is recorded as `null`.
- `check` reports output-schema changes on their own lines. A new enum value anywhere in `outputSchema` is flagged `output widened`, with a note that it can break downstream exhaustive switches. Other output edits are reported as `output changed`.
- v0.1 lockfiles, which have no `outputSchema` data, still check cleanly (exit 0) against a listing whose tools have no output schema. An `outputSchema` the old lock never pinned is an output-added finding and counts as drift (exit 1).

### v0.1.0

- Initial public release. Pin `name`, `description`, `inputSchema`, and `annotations`, and diff a later listing for added tools, removed tools, description edits, and input-schema changes.

## Full pack

Digital Fortress publishes paid review packs for teams that want more than a lockfile diff. Prices below are the pack prices.

- **[$79 MCP & Multi-Agent Authorization Security Pack](https://fortressaudit.gumroad.com/l/wphmlq)** — the pack for MCP tool trust.
- **[$99 AI Security & Infrastructure Prompt Pack](https://fortressaudit.gumroad.com/l/myyeen)**
- **[$149 Multi-Agent Orchestration Blueprint](https://fortressaudit.gumroad.com/l/cvxfw)**
- **[$99 Agent Runtime Containment Pack](https://fortressaudit.gumroad.com/l/ngouvf)**: agent egress, identity, Kubernetes sandboxing, and tool-call authorization.

A free sibling starter, with copy-paste audit prompts and one read-only repository scan, is the [AI Security Starter Checklist](https://github.com/digitalfortressaudit/ai-security-starter-checklist).

## Sources

- [OWASP: MCP Tool Poisoning](https://owasp.org/www-community/attacks/MCP_Tool_Poisoning)
- [Model Context Protocol Threat Modeling and Analyzing Vulnerabilities to Prompt Injection with Tool Poisoning](https://arxiv.org/html/2603.22489v1)
- [A Formal Security Framework for MCP-Based AI Agents](https://arxiv.org/abs/2604.05969v1)

## License

[MIT](LICENSE) © 2026 Digital Fortress. Authorized defensive use only, as described above.
