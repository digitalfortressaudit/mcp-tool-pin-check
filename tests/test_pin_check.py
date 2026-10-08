#!/usr/bin/env python3
"""Unit tests for the MCP tool definition pinning checker."""

from __future__ import annotations

import contextlib
import io
import json
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import mcp_tool_pin_check as pin  # noqa: E402

EXAMPLES = ROOT / "examples"
PINNED_AT = "2026-10-08T00:00:00Z"


def _schema() -> dict:
    return {
        "additionalProperties": False,
        "properties": {
            "status": {
                "enum": ["open", "closed"],
                "maxLength": 16,
                "pattern": "^[a-z]+$",
                "type": "string",
            }
        },
        "required": ["status"],
        "type": "object",
    }


def _listing(schema: dict, description: str = "Look up a note.") -> dict:
    return {
        "tools": [
            {
                "description": description,
                "inputSchema": schema,
                "name": "lookup_note",
            }
        ]
    }


class PinCheckTests(unittest.TestCase):
    def _run(self, argv: list[str]) -> tuple[int, str, str]:
        stdout = io.StringIO()
        stderr = io.StringIO()
        with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            code = pin.main(argv)
        return code, stdout.getvalue(), stderr.getvalue()

    def _write(self, directory: Path, name: str, payload: object) -> Path:
        path = directory / name
        path.write_text(json.dumps(payload), encoding="utf-8")
        return path

    def test_pin_is_deterministic(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            first = root / "a.lock.json"
            second = root / "b.lock.json"
            argv = [
                "pin",
                "--listing",
                str(EXAMPLES / "tools-list.json"),
                "--source",
                "local-notes",
                "--pinned-at",
                PINNED_AT,
            ]
            code_a, _, err_a = self._run([*argv, "--lock", str(first)])
            code_b, _, err_b = self._run([*argv, "--lock", str(second)])
            self.assertEqual((code_a, err_a), (0, ""))
            self.assertEqual((code_b, err_b), (0, ""))
            self.assertEqual(first.read_bytes(), second.read_bytes())

            reordered = {
                "id": 1,
                "jsonrpc": "2.0",
                "result": {"tools": list(reversed(json.loads((EXAMPLES / "tools-list.json").read_text())["result"]["tools"]))},
            }
            other = self._write(root, "reordered.json", reordered)
            third = root / "c.lock.json"
            code_c, _, _ = self._run(
                ["pin", "--listing", str(other), "--lock", str(third), "--source", "local-notes", "--pinned-at", PINNED_AT]
            )
            self.assertEqual(code_c, 0)
            locked_a = json.loads(first.read_text(encoding="utf-8"))
            locked_c = json.loads(third.read_text(encoding="utf-8"))
            self.assertEqual(
                [item["sha256"] for item in locked_a["tools"]],
                [item["sha256"] for item in locked_c["tools"]],
            )
            self.assertEqual([item["name"] for item in locked_a["tools"]], ["get_note", "list_notes"])
            self.assertTrue(all(len(item["sha256"]) == 64 for item in locked_a["tools"]))

            tools = json.loads((EXAMPLES / "tools-list.json").read_text(encoding="utf-8"))["result"]["tools"]
            bare = self._write(root, "bare.json", tools)
            wrapped = self._write(root, "wrapped.json", {"tools": tools})
            bare_lock = root / "bare.lock.json"
            wrapped_lock = root / "wrapped.lock.json"
            self.assertEqual(self._run(["pin", "--listing", str(bare), "--lock", str(bare_lock), "--pinned-at", PINNED_AT])[0], 0)
            self.assertEqual(
                self._run(["pin", "--listing", str(wrapped), "--lock", str(wrapped_lock), "--pinned-at", PINNED_AT])[0],
                0,
            )
            bare_hashes = [item["sha256"] for item in json.loads(bare_lock.read_text(encoding="utf-8"))["tools"]]
            wrapped_hashes = [item["sha256"] for item in json.loads(wrapped_lock.read_text(encoding="utf-8"))["tools"]]
            self.assertEqual(bare_hashes, [item["sha256"] for item in locked_a["tools"]])
            self.assertEqual(wrapped_hashes, bare_hashes)

    def test_no_drift_exits_0(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            lock = Path(tmp) / "tools.lock.json"
            listing = str(EXAMPLES / "tools-list.json")
            pin_code, _, pin_err = self._run(
                ["pin", "--listing", listing, "--lock", str(lock), "--source", "local-notes", "--pinned-at", PINNED_AT]
            )
            check_code, out, check_err = self._run(["check", "--listing", listing, "--lock", str(lock)])
            self.assertEqual(pin_code, 0)
            self.assertEqual(pin_err, "")
            self.assertEqual(check_code, 0)
            self.assertEqual(check_err, "")
            self.assertIn("result: unchanged", out)
            json_code, json_out, _ = self._run(["check", "--listing", listing, "--lock", str(lock), "--json"])
            self.assertEqual(json_code, 0)
            self.assertTrue(json.loads(json_out)["ok"])

    def test_drift_exits_1(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            lock = Path(tmp) / "tools.lock.json"
            self._run(
                [
                    "pin",
                    "--listing",
                    str(EXAMPLES / "tools-list.json"),
                    "--lock",
                    str(lock),
                    "--source",
                    "local-notes",
                    "--pinned-at",
                    PINNED_AT,
                ]
            )
            code, out, err = self._run(
                ["check", "--listing", str(EXAMPLES / "tools-list.changed.json"), "--lock", str(lock)]
            )
            self.assertEqual(code, 1)
            self.assertEqual(err, "")
            self.assertIn("result: drift", out)
            self.assertIn("+ create_note", out)
            self.assertIn("~ get_note", out)
            self.assertIn("description (pinned)", out)
            self.assertIn("~ list_notes", out)
            self.assertIn("[widened] property added: properties.limit (optional)", out)
            self.assertIn("[widened] required removed: query", out)
            self.assertIn("schema widened: yes", out)

    def test_widened_schema_flags(self) -> None:
        base = _schema()
        cases = {
            "property": (
                {**base, "properties": {**base["properties"], "limit": {"type": "integer"}}},
                "[widened] property added: properties.limit (optional)",
            ),
            "required": (
                {key: value for key, value in base.items() if key != "required"},
                "[widened] required removed: status",
            ),
            "enum": (
                {
                    **base,
                    "properties": {
                        "status": {**base["properties"]["status"], "enum": ["open", "closed", "archived"]}
                    },
                },
                '[widened] enum loosened: properties.status.enum (added "archived")',
            ),
            "maxLength": (
                {
                    **base,
                    "properties": {"status": {**base["properties"]["status"], "maxLength": 64}},
                },
                "[widened] maxLength loosened: properties.status.maxLength (16 -> 64)",
            ),
            "pattern": (
                {
                    **base,
                    "properties": {
                        "status": {key: value for key, value in base["properties"]["status"].items() if key != "pattern"}
                    },
                },
                "[widened] pattern removed: properties.status.pattern",
            ),
            "additional_true": (
                {**base, "additionalProperties": True},
                "[widened] additionalProperties widened: additionalProperties (false -> true)",
            ),
            "additional_absent": (
                {key: value for key, value in base.items() if key != "additionalProperties"},
                "[widened] additionalProperties widened: additionalProperties (false -> absent)",
            ),
        }
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            original = self._write(root, "base.json", _listing(base))
            lock = root / "tools.lock.json"
            pin_code, _, _ = self._run(
                ["pin", "--listing", str(original), "--lock", str(lock), "--pinned-at", PINNED_AT]
            )
            self.assertEqual(pin_code, 0)
            for name, (schema, expected) in cases.items():
                current = self._write(root, f"{name}.json", _listing(schema))
                code, out, err = self._run(["check", "--listing", str(current), "--lock", str(lock)])
                self.assertEqual(code, 1, name)
                self.assertEqual(err, "", name)
                self.assertIn(expected, out, name)
                self.assertIn("schema widened: yes", out, name)

            tighter = {
                **base,
                "properties": {"status": {**base["properties"]["status"], "maxLength": 8}},
            }
            current = self._write(root, "tighter.json", _listing(tighter))
            code, out, _ = self._run(["check", "--listing", str(current), "--lock", str(lock)])
            self.assertEqual(code, 1)
            self.assertIn("maxLength tightened: properties.status.maxLength (16 -> 8)", out)
            self.assertNotIn("[widened]", out)

    def test_bad_input_exits_2(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            lock = root / "tools.lock.json"
            missing = root / "missing.json"
            code, _, err = self._run(["pin", "--listing", str(missing), "--lock", str(lock)])
            self.assertEqual(code, 2)
            self.assertIn("error:", err)
            self.assertFalse(lock.exists())

            bad = self._write(root, "bad.json", None)
            bad.write_text("{", encoding="utf-8")
            code, _, err = self._run(["pin", "--listing", str(bad), "--lock", str(lock)])
            self.assertEqual(code, 2)
            self.assertIn("not valid JSON", err)

            unnamed = self._write(root, "unnamed.json", {"tools": [{"description": "Hello"}]})
            code, _, err = self._run(["pin", "--listing", str(unnamed), "--lock", str(lock)])
            self.assertEqual(code, 2)
            self.assertIn("name", err)

            duplicate = self._write(
                root,
                "duplicate.json",
                {"tools": [{"name": "get_note", "inputSchema": {}}, {"name": "get_note", "inputSchema": {}}]},
            )
            code, _, err = self._run(["pin", "--listing", str(duplicate), "--lock", str(lock)])
            self.assertEqual(code, 2)
            self.assertIn("duplicate", err)

            empty = self._write(root, "empty.json", {"ok": True})
            code, _, err = self._run(["check", "--listing", str(empty), "--lock", str(lock)])
            self.assertEqual(code, 2)
            self.assertIn("no tools", err)

            good = self._write(root, "good.json", _listing(_schema()))
            code, _, err = self._run(["check", "--listing", str(good), "--lock", str(root / "absent.lock.json")])
            self.assertEqual(code, 2)
            self.assertIn("error:", err)


if __name__ == "__main__":
    unittest.main()
