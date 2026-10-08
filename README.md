# MCP Tool Definition Pinning Checker

Pin an MCP server's tool definitions, then diff a later listing for silent changes. One read-only Python script. No third-party packages.

**Want the review set this belongs to?** The [$79 MCP & Multi-Agent Authorization Security Pack](https://fortressaudit.gumroad.com/l/wphmlq) is the Digital Fortress pack for MCP tool trust.

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

The examples are a small notes server. `examples/tools-list.changed.json` adds `create_note`, rewords `get_note`, and changes `list_notes` by adding an optional `limit` property and dropping `query` from `required`. The sample below sets `--pinned-at` so the timestamp is reproducible:

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
  get_note a48cd105f5e429bbcccedc8e521064e99b0e7e607b5f02ac13c200550220a263
  list_notes 49084e8dae069772809569c9e629d4f186a98ae49cae5cf7572500c1319d14b6
```

`check` prints:

```text
MCP tool pin check
lock source: local-notes
pinned_at: 2026-10-08T00:00:00Z
result: drift

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
| `0` | The normalized listing matches the lockfile. |
| `1` | Drift: a tool was added, removed, or its definition changed. |
| `2` | The listing or lockfile could not be read (missing file, invalid JSON, duplicate names, or a lockfile hash that does not match its stored definition). |

## GitHub Actions

Commit the lockfile. Produce a fresh `tools/list` file in an earlier step you control, then fail the job when the listing has drifted:

```yaml
- name: Check pinned MCP tool definitions
  run: python3 mcp_tool_pin_check.py check --listing tools-list.json --lock mcp-tools.lock.json
```

This repository's own workflow runs the unit tests only. It does not contact an MCP server.

## What it does

Each tool is reduced to `name`, `description`, `inputSchema`, and `annotations` when annotations are present. Tools are sorted by name. `pin` writes a JSON lockfile with `pinned_at`, a source label, and one SHA-256 per normalized tool, plus the normalized definition. `check` reports added tools, removed tools, a short unified diff when a description changed, and schema changes.

A schema line marked `[widened]` means the schema accepts more than the pin:

- a new property
- a `required` name removed
- `enum` removed or given new values
- `maxLength` removed or increased
- `pattern` removed
- `additionalProperties` moving from `false` or a subschema to `true` or absent

Other schema edits are still drift. They are printed without `[widened]`. A tighter `maxLength`, for example, is a change and not a widening.

## What it does not do

- It does not open a network connection, call tools, start a server, or modify an MCP server.
- It does not execute text from descriptions or schemas. It only reads the files you name and writes the lockfile path you pass to `pin`.
- It does not decide that a description is safe or unsafe. It shows whether the stored definition changed.
- It does not pin `outputSchema` or any field other than name, description, input schema, and annotations.
- A clean check is not a full review of the server. It means the normalized definition matches the lockfile.

## Authorized use

This repository is [MIT licensed](LICENSE). It is for **defensive checks only**.

- Pin and check tool listings from MCP servers you own or are authorized to assess.
- Save those listings from clients you are allowed to use.
- Do not point it at servers you are not allowed to review.

## Tests

From this directory:

```bash
python3 -m unittest tests.test_pin_check -v
```

## Full pack

Digital Fortress publishes paid review packs for teams that want more than a lockfile diff. Prices below are the pack prices.

- **[$79 MCP & Multi-Agent Authorization Security Pack](https://fortressaudit.gumroad.com/l/wphmlq)** — the pack for MCP tool trust.
- **[$99 AI Security & Infrastructure Prompt Pack](https://fortressaudit.gumroad.com/l/myyeen)**
- **[$149 Multi-Agent Orchestration Blueprint](https://fortressaudit.gumroad.com/l/cvxfw)**

A free sibling starter, with copy-paste audit prompts and one read-only repository scan, is the [AI Security Starter Checklist](https://github.com/digitalfortressaudit/ai-security-starter-checklist).

## Sources

- [OWASP: MCP Tool Poisoning](https://owasp.org/www-community/attacks/MCP_Tool_Poisoning)
- [Model Context Protocol Threat Modeling and Analyzing Vulnerabilities to Prompt Injection with Tool Poisoning](https://arxiv.org/html/2603.22489v1)
- [A Formal Security Framework for MCP-Based AI Agents](https://arxiv.org/abs/2604.05969v1)

## License

[MIT](LICENSE) © 2026 Digital Fortress. Authorized defensive use only, as described above.
