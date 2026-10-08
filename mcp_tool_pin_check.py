#!/usr/bin/env python3
# Pin MCP tool definitions and diff a later listing for silent changes.
# Read-only. No network, no tool calls. Authorized defensive use only.
# Digital Fortress — MCP Tool Definition Pinning Checker
# https://fortressaudit.gumroad.com/l/wphmlq

"""Pin MCP tool definitions and compare a later tools/list export.

Reads a local JSON file only. Writes only the lockfile path passed to ``pin``.
Does not connect to a server, call tools, or execute listing text. Use only
on servers you own or are authorized to assess.
"""

from __future__ import annotations

import argparse
import difflib
import hashlib
import json
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

EXIT_OK = 0
EXIT_DRIFT = 1
EXIT_ERROR = 2
_MAX_DEPTH = 32
_HANDLED = {"additionalProperties", "enum", "maxLength", "pattern", "properties", "required"}


class InputError(Exception):
    """The listing or lockfile cannot be used."""


def canonical(value: Any) -> str:
    """Stable JSON used for hashes and for comparing schema values."""
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"), sort_keys=True)


def _digest(value: Any) -> str:
    return hashlib.sha256(canonical(value).encode("utf-8")).hexdigest()


def _loc(base: str, key: str) -> str:
    return f"{base}.{key}" if base else key


def _number(value: Any) -> bool:
    return isinstance(value, (int, float)) and not isinstance(value, bool)


def _names(value: Any) -> set[str]:
    if not isinstance(value, list):
        return set()
    return {item for item in value if isinstance(item, str)}


def _label(value: str, flag: str) -> str:
    if any(ord(char) < 32 for char in value):
        raise InputError(f"{flag} must be a single-line label")
    return value


def _change(path: str, kind: str, detail: str, widened: bool) -> dict[str, Any]:
    return {"detail": detail, "kind": kind, "path": path, "widened": widened}


def load_json(path: Path) -> Any:
    """Read one JSON document. Raise InputError instead of a traceback."""
    try:
        raw = path.read_text(encoding="utf-8-sig")
    except OSError as exc:
        raise InputError(f"cannot read {path}: {exc.strerror or exc}") from exc
    try:
        return json.loads(raw)
    except json.JSONDecodeError as exc:
        raise InputError(f"{path} is not valid JSON: {exc.msg} (line {exc.lineno})") from exc


def extract_tools(payload: Any) -> list[Any]:
    """Accept a JSON-RPC result, ``{"tools": [...]}``, or a bare list."""
    if isinstance(payload, list):
        return payload
    if not isinstance(payload, dict):
        raise InputError("listing must be a JSON object or a list of tools")
    result = payload.get("result")
    if isinstance(result, dict) and "tools" in result:
        tools = result["tools"]
    elif "tools" in payload:
        tools = payload["tools"]
    else:
        raise InputError("listing has no tools array (expected result.tools, tools, or a bare list)")
    if not isinstance(tools, list):
        raise InputError("tools must be a JSON array")
    return tools


def normalize_tool(tool: Any) -> dict[str, Any]:
    """Keep name, description, inputSchema, and annotations when present."""
    if not isinstance(tool, dict):
        raise InputError("each tool must be a JSON object")
    name = tool.get("name")
    if not isinstance(name, str) or not name.strip():
        raise InputError("each tool needs a non-empty string name")
    description = tool.get("description", "")
    if description is None:
        description = ""
    if not isinstance(description, str):
        raise InputError(f"tool {name!r} description must be a string")
    schema = {} if tool.get("inputSchema") is None else tool.get("inputSchema", {})
    if not isinstance(schema, dict):
        raise InputError(f"tool {name!r} inputSchema must be a JSON object")
    definition: dict[str, Any] = {"description": description, "inputSchema": schema, "name": name}
    if "annotations" in tool and tool["annotations"] is not None:
        annotations = tool["annotations"]
        if not isinstance(annotations, dict):
            raise InputError(f"tool {name!r} annotations must be a JSON object")
        definition["annotations"] = annotations
    return definition


def normalize_listing(payload: Any) -> list[dict[str, Any]]:
    """Return tools sorted by name. Duplicate names are an input error."""
    tools = [normalize_tool(item) for item in extract_tools(payload)]
    names = [item["name"] for item in tools]
    duplicates = sorted({name for name in names if names.count(name) > 1})
    if duplicates:
        raise InputError("duplicate tool names: " + ", ".join(duplicates))
    tools.sort(key=lambda item: item["name"])
    return tools


def build_lock(tools: list[dict[str, Any]], source: str, pinned_at: str) -> dict[str, Any]:
    """Build a deterministic lock document. ``tools`` must already be sorted."""
    entries = [{"definition": item, "name": item["name"], "sha256": _digest(item)} for item in tools]
    return {"lockfile_version": 1, "pinned_at": pinned_at, "source": source, "tools": entries}


def write_lock(path: Path, lock: dict[str, Any]) -> None:
    text = json.dumps(lock, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
    try:
        path.write_text(text, encoding="utf-8")
    except OSError as exc:
        raise InputError(f"cannot write {path}: {exc.strerror or exc}") from exc


def parse_lock(payload: Any, path: Path) -> dict[str, Any]:
    """Load a lockfile and reject entries whose stored hash does not match."""
    if not isinstance(payload, dict) or payload.get("lockfile_version", 1) != 1:
        raise InputError(f"{path} is not a version-1 tool pin lockfile")
    entries = payload.get("tools")
    if not isinstance(entries, list):
        raise InputError(f"{path} is not a tool pin lockfile")
    pinned: dict[str, Any] = {}
    for item in entries:
        if not isinstance(item, dict):
            raise InputError(f"{path} has a non-object tool entry")
        definition, name, digest = item.get("definition"), item.get("name"), item.get("sha256")
        if not isinstance(definition, dict) or not isinstance(name, str) or not isinstance(digest, str):
            raise InputError(f"{path} has an incomplete tool entry")
        if definition.get("name") != name or _digest(definition) != digest:
            raise InputError(f"{path} hash mismatch for tool {name!r}")
        if name in pinned:
            raise InputError(f"{path} lists tool {name!r} more than once")
        pinned[name] = item
    return {"pinned_at": payload.get("pinned_at", ""), "source": payload.get("source", ""), "tools": pinned}


def compare_schemas(old: Any, new: Any, path: str = "", depth: int = 0) -> list[dict[str, Any]]:
    """Diff two JSON Schemas. ``widened`` marks a looser acceptance rule.

    A schema is widened when it gains a property, drops a ``required`` name,
    removes or loosens ``enum`` / ``maxLength`` / ``pattern``, or lets
    ``additionalProperties`` become true or absent.
    """
    if old == new:
        return []
    if depth > _MAX_DEPTH:
        return [_change(path or "$", "value_changed", "schema nesting limit reached", False)]
    if not isinstance(old, dict) or not isinstance(new, dict):
        return [_change(path or "$", "value_changed", "schema value replaced", False)]
    changes: list[dict[str, Any]] = []
    changes.extend(_properties(old, new, path, depth))
    changes.extend(_required(old, new, path))
    changes.extend(_enum(old, new, path))
    changes.extend(_max_length(old, new, path))
    changes.extend(_pattern(old, new, path))
    changes.extend(_additional(old, new, path, depth))
    changes.extend(_nested(old, new, path, depth))
    return changes


def _properties(old: dict[str, Any], new: dict[str, Any], path: str, depth: int) -> list[dict[str, Any]]:
    old_props, new_props = old.get("properties", {}), new.get("properties", {})
    if not isinstance(old_props, dict) or not isinstance(new_props, dict):
        if old_props != new_props:
            return [_change(_loc(path, "properties"), "keyword_changed", "properties", False)]
        return []
    required = _names(new.get("required"))
    changes: list[dict[str, Any]] = []
    for name in sorted(set(new_props) - set(old_props)):
        detail = "optional" if name not in required else "required"
        changes.append(_change(_loc(path, f"properties.{name}"), "property_added", detail, True))
    for name in sorted(set(old_props) - set(new_props)):
        changes.append(_change(_loc(path, f"properties.{name}"), "property_removed", name, False))
    for name in sorted(set(old_props) & set(new_props)):
        changes.extend(compare_schemas(old_props[name], new_props[name], _loc(path, f"properties.{name}"), depth + 1))
    return changes


def _required(old: dict[str, Any], new: dict[str, Any], path: str) -> list[dict[str, Any]]:
    loc = _loc(path, "required")
    before, after = _names(old.get("required")), _names(new.get("required"))
    removed = [_change(loc, "required_removed", name, True) for name in sorted(before - after)]
    added = [_change(loc, "required_added", name, False) for name in sorted(after - before)]
    return removed + added


def _enum(old: dict[str, Any], new: dict[str, Any], path: str) -> list[dict[str, Any]]:
    if "enum" not in old and "enum" not in new:
        return []
    loc, old_enum, new_enum = _loc(path, "enum"), old.get("enum"), new.get("enum")
    if isinstance(old_enum, list) and isinstance(new_enum, list):
        old_set = {canonical(item) for item in old_enum}
        new_set = {canonical(item) for item in new_enum}
        changes = []
        if new_set - old_set:
            changes.append(_change(loc, "enum_loosened", "added " + ", ".join(sorted(new_set - old_set)), True))
        if old_set - new_set:
            changes.append(_change(loc, "enum_tightened", "removed " + ", ".join(sorted(old_set - new_set)), False))
        return changes
    if isinstance(old_enum, list) and "enum" not in new:
        return [_change(loc, "enum_removed", "enum removed", True)]
    if "enum" not in old and isinstance(new_enum, list):
        return [_change(loc, "enum_added", "enum added", False)]
    return [_change(loc, "enum_changed", "enum changed", False)]


def _max_length(old: dict[str, Any], new: dict[str, Any], path: str) -> list[dict[str, Any]]:
    if "maxLength" not in old and "maxLength" not in new:
        return []
    loc, before, after = _loc(path, "maxLength"), old.get("maxLength"), new.get("maxLength")
    if before == after:
        return []
    if _number(before) and "maxLength" not in new:
        return [_change(loc, "maxLength_removed", str(before), True)]
    if _number(before) and _number(after):
        loosened = after > before
        kind = "maxLength_loosened" if loosened else "maxLength_tightened"
        return [_change(loc, kind, f"{before} -> {after}", loosened)]
    if "maxLength" not in old:
        return [_change(loc, "maxLength_added", str(after), False)]
    return [_change(loc, "maxLength_changed", f"{before!r} -> {after!r}", False)]


def _pattern(old: dict[str, Any], new: dict[str, Any], path: str) -> list[dict[str, Any]]:
    if "pattern" not in old and "pattern" not in new or old.get("pattern") == new.get("pattern"):
        return []
    loc = _loc(path, "pattern")
    if isinstance(old.get("pattern"), str) and "pattern" not in new:
        return [_change(loc, "pattern_removed", "pattern removed", True)]
    if "pattern" not in old:
        return [_change(loc, "pattern_added", "pattern added", False)]
    return [_change(loc, "pattern_changed", "pattern replaced", False)]


def _ap_kind(schema: dict[str, Any]) -> str:
    if "additionalProperties" not in schema:
        return "absent"
    value = schema["additionalProperties"]
    if value is True or value is False:
        return "true" if value else "false"
    return "schema" if isinstance(value, dict) else "other"


def _additional(old: dict[str, Any], new: dict[str, Any], path: str, depth: int) -> list[dict[str, Any]]:
    old_kind, new_kind = _ap_kind(old), _ap_kind(new)
    loc = _loc(path, "additionalProperties")
    if old_kind == new_kind == "schema":
        return compare_schemas(old["additionalProperties"], new["additionalProperties"], loc, depth + 1)
    if old_kind == new_kind and old.get("additionalProperties") == new.get("additionalProperties"):
        return []
    widened = old_kind in {"false", "schema"} and new_kind in {"true", "absent"}
    kind = "additionalProperties_widened" if widened else "additionalProperties_changed"
    return [_change(loc, kind, f"{old_kind} -> {new_kind}", widened)]


def _nested(old: dict[str, Any], new: dict[str, Any], path: str, depth: int) -> list[dict[str, Any]]:
    """Walk schema keywords other than the widening rules handled above."""
    changes: list[dict[str, Any]] = []
    for key in sorted((set(old) | set(new)) - _HANDLED):
        before, after = old.get(key), new.get(key)
        if before == after:
            continue
        loc = _loc(path, key)
        if isinstance(before, dict) and isinstance(after, dict):
            changes.extend(compare_schemas(before, after, loc, depth + 1))
        elif isinstance(before, list) and isinstance(after, list) and before and isinstance(before[0], dict):
            for index in range(max(len(before), len(after))):
                branch = f"{loc}[{index}]"
                if index >= len(before) or index >= len(after):
                    changes.append(_change(branch, "keyword_changed", "branch added or removed", False))
                elif isinstance(before[index], dict) and isinstance(after[index], dict):
                    changes.extend(compare_schemas(before[index], after[index], branch, depth + 1))
                elif before[index] != after[index]:
                    changes.append(_change(branch, "keyword_changed", key, False))
        else:
            changes.append(_change(loc, "keyword_changed", key, False))
    return changes


def description_diff(old: str, new: str) -> str:
    """Return a short unified diff of two tool descriptions."""
    def lines(text: str) -> list[str]:
        return [line + "\n" for line in (text.splitlines() or [""])]

    diff = difflib.unified_diff(lines(old), lines(new), fromfile="description (pinned)", tofile="description (current)", n=1)
    return "".join(diff).rstrip("\n")


def diff_tool(old_def: dict[str, Any], new_def: dict[str, Any]) -> dict[str, Any]:
    schema_changes = compare_schemas(old_def.get("inputSchema", {}), new_def.get("inputSchema", {}))
    description_changed = old_def.get("description", "") != new_def.get("description", "")
    return {
        "annotations_changed": old_def.get("annotations") != new_def.get("annotations"),
        "description_changed": description_changed,
        "description_diff": description_diff(old_def.get("description", ""), new_def.get("description", "")) if description_changed else "",
        "name": new_def["name"],
        "schema_changes": schema_changes,
        "widened": any(change["widened"] for change in schema_changes),
    }


def compare_listings(pinned: dict[str, Any], current: list[dict[str, Any]]) -> dict[str, Any]:
    """Compare normalized tools with a parsed lockfile."""
    by_name = {item["name"]: item for item in current}
    locked = pinned["tools"]
    added = sorted(set(by_name) - set(locked))
    removed = sorted(set(locked) - set(by_name))
    changed, unchanged = [], []
    for name in sorted(set(by_name) & set(locked)):
        if _digest(by_name[name]) == locked[name]["sha256"]:
            unchanged.append(name)
        else:
            changed.append(diff_tool(locked[name]["definition"], by_name[name]))
    return {
        "added": added,
        "changed": changed,
        "lock_source": pinned.get("source", ""),
        "ok": not added and not removed and not changed,
        "pinned_at": pinned.get("pinned_at", ""),
        "removed": removed,
        "unchanged": unchanged,
    }


def format_schema_change(change: dict[str, Any]) -> str:
    """One schema finding, with a ``[widened]`` marker when acceptance grew."""
    path, detail, kind = change["path"], change["detail"], change["kind"]
    if kind == "property_added":
        text = f"property added: {path}" + (" (optional)" if detail == "optional" else "")
    elif kind == "property_removed":
        text = f"property removed: {path}"
    elif kind in {"required_removed", "required_added"}:
        action = "removed" if kind == "required_removed" else "added"
        where = "" if path == "required" else f" ({path})"
        text = f"required {action}: {detail}{where}"
    elif kind in {"enum_loosened", "enum_tightened", "maxLength_loosened", "maxLength_removed", "maxLength_tightened"}:
        label = kind.replace("_", " ")
        text = f"{label}: {path} ({detail})"
    elif kind == "enum_removed":
        text = f"enum removed: {path}"
    elif kind == "pattern_removed":
        text = f"pattern removed: {path}"
    elif kind == "additionalProperties_widened":
        text = f"additionalProperties widened: {path} ({detail})"
    else:
        text = f"{kind}: {path}" + (f" ({detail})" if detail else "")
    flag = "[widened] " if change["widened"] else ""
    return f"    {flag}{text}"


def _section(title: str, names: list[str], prefix: str) -> list[str]:
    lines = [f"{title} ({len(names)}):"]
    lines.extend(f"  {prefix} {name}" for name in names)
    if not names:
        lines.append("  (none)")
    return lines


def format_text(report: dict[str, Any]) -> str:
    """Render a check report for a terminal."""
    lines = [
        "MCP tool pin check",
        f"lock source: {report['lock_source'] or '(none)'}",
        f"pinned_at: {report['pinned_at'] or '(none)'}",
        "result: unchanged" if report["ok"] else "result: drift",
        "",
    ]
    lines.extend(_section("added", report["added"], "+"))
    lines.extend(_section("removed", report["removed"], "-"))
    lines.append(f"changed ({len(report['changed'])}):")
    if not report["changed"]:
        lines.append("  (none)")
    for index, item in enumerate(report["changed"]):
        if index:
            lines.append("")
        lines.append(f"  ~ {item['name']}")
        if item["description_changed"]:
            lines.append("    description:")
            lines.extend(f"    {line}" for line in item["description_diff"].splitlines())
        if item["schema_changes"]:
            lines.append("    schema:")
            lines.extend(format_schema_change(change) for change in item["schema_changes"])
        if item["annotations_changed"]:
            lines.append("    annotations changed")
        if item["widened"]:
            lines.append("    schema widened: yes")
    unchanged = ", ".join(report["unchanged"]) or "(none)"
    lines.append(f"unchanged ({len(report['unchanged'])}): {unchanged}")
    return "\n".join(lines) + "\n"


def format_pin(lock_path: Path, lock: dict[str, Any]) -> str:
    lines = [
        f"Pinned {len(lock['tools'])} tools to {lock_path}",
        f"source: {lock['source']}",
        f"pinned_at: {lock['pinned_at']}",
    ]
    lines.extend(f"  {item['name']} {item['sha256']}" for item in lock["tools"])
    return "\n".join(lines) + "\n"


def _emit(payload: dict[str, Any], as_json: bool, text: str) -> None:
    if as_json:
        json.dump(payload, sys.stdout, indent=2, sort_keys=True)
        sys.stdout.write("\n")
    else:
        sys.stdout.write(text)


def cmd_pin(args: argparse.Namespace) -> int:
    tools = normalize_listing(load_json(Path(args.listing)))
    source = _label(args.source, "--source") if args.source is not None else args.listing
    pinned_at = _label(args.pinned_at, "--pinned-at") if args.pinned_at else datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    lock = build_lock(tools, source, pinned_at)
    write_lock(Path(args.lock), lock)
    summary = {
        "lock": args.lock,
        "pinned_at": lock["pinned_at"],
        "source": lock["source"],
        "tool_count": len(lock["tools"]),
        "tools": [{"name": item["name"], "sha256": item["sha256"]} for item in lock["tools"]],
    }
    _emit(summary, args.json, format_pin(Path(args.lock), lock))
    return EXIT_OK


def cmd_check(args: argparse.Namespace) -> int:
    current = normalize_listing(load_json(Path(args.listing)))
    lock_path = Path(args.lock)
    report = compare_listings(parse_lock(load_json(lock_path), lock_path), current)
    _emit(report, args.json, format_text(report))
    return EXIT_OK if report["ok"] else EXIT_DRIFT


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Pin MCP tool definitions from a local tools/list JSON file and "
            "diff a later listing. Read-only: no network and no tool calls. "
            "Authorized defensive use only."
        )
    )
    sub = parser.add_subparsers(dest="command", required=True)
    pin = sub.add_parser("pin", help="Write a lockfile for a tools/list JSON file")
    check = sub.add_parser("check", help="Compare a tools/list JSON file to a lockfile")
    for command in (pin, check):
        command.add_argument("--listing", required=True, help="Path to a tools/list JSON file")
        command.add_argument("--lock", required=True, help="Lockfile path to write (pin) or read (check)")
        command.add_argument("--json", action="store_true", help="Print machine-readable JSON")
    pin.add_argument("--source", help="Label stored in the lockfile (default: the listing path)")
    pin.add_argument("--pinned-at", help="Timestamp stored in the lockfile (default: current UTC)")
    return parser


def main(argv: list[str] | None = None) -> int:
    """Run pin or check. Exit 0 when unchanged, 1 on drift, 2 on input errors."""
    args = build_parser().parse_args(argv)
    try:
        return cmd_pin(args) if args.command == "pin" else cmd_check(args)
    except InputError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_ERROR


if __name__ == "__main__":
    sys.exit(main())
