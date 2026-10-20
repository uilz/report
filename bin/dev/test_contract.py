#!/usr/bin/env python3
"""Contract test for the platform `report` integration (contract 0.1).

Covers requirement §2.5 (5 items) plus: --no-sync→pending, exit codes,
max-bytes, FILE_NOT_FOUND, and stdout-is-single-JSON. Local temp dirs only.
Prints PASS/FAIL, exits 0/1.
"""
from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import tempfile

BIN = os.path.dirname(os.path.abspath(__file__))
REPORT = os.path.join(os.path.dirname(BIN), "report")
PASSWORD = "test-password"


class CheckFailure(Exception):
    pass


def check(cond: bool, msg: str) -> None:
    if not cond:
        raise CheckFailure(msg)


def run(root: str, *args: str) -> subprocess.CompletedProcess:
    env = dict(os.environ)
    env["UZR_PASSWORD"] = PASSWORD
    env["UZR_SYNC_LOCK"] = os.path.join(root, "sync.lock")
    return subprocess.run([sys.executable, REPORT, *args], capture_output=True, env=env)


def parse(proc: subprocess.CompletedProcess) -> dict:
    text = proc.stdout.decode("utf-8", "replace").strip()
    check("\n" not in text, f"stdout must be a single JSON line, got: {text!r}")
    try:
        return json.loads(text)
    except ValueError as exc:
        raise CheckFailure(f"stdout is not JSON: {text!r} (stderr={proc.stderr.decode(errors='replace')!r})") from exc


def main() -> int:
    root = tempfile.mkdtemp(prefix="uzr-contract-")
    outputs: list[bytes] = []
    try:
        origin = os.path.join(root, "origin.git")
        os.makedirs(origin)
        subprocess.run(["git", "init", "--bare", "-q", "-b", "main", origin], check=True)
        repo = os.path.join(root, "repo")
        master = os.path.join(root, "master")
        mk_file = os.path.join(root, "mk.key")
        subprocess.run(["git", "clone", "-q", origin, repo], check=True)
        subprocess.run(["git", "-C", repo, "config", "user.email", "t@t"], check=True)
        subprocess.run(["git", "-C", repo, "config", "user.name", "t"], check=True)

        base = ["--repo-dir", repo, "--master-dir", master, "--mk-file", mk_file]
        p = run(root, *base, "init", "--yes")
        check(p.returncode == 0, f"init failed: {p.stderr.decode(errors='replace')}")

        # --version
        p = run(root, "--version")
        outputs.append(p.stdout)
        doc = parse(p)
        check(p.returncode == 0, "version exit code must be 0")
        check(
            doc == {"tool_version": "0.2.0", "contract_version": "0.1"},
            f"unexpected version: {doc}",
        )

        # §2.5.1 publish --no-sync -> ok + publish_id + pending
        sample = os.path.join(root, "summary.md")
        with open(sample, "w", encoding="utf-8") as fh:
            fh.write("# demo\n\nhello\n")
        p = run(root, *base, "publish", "--file", sample, "--no-sync", "--json")
        outputs.append(p.stdout)
        doc = parse(p)
        check(p.returncode == 0, f"publish failed: {doc}")
        check(doc["ok"] is True, "publish ok must be true")
        pid = doc["result"]["publish_id"]
        check(isinstance(pid, str) and pid.startswith("pub_"), f"bad publish_id: {pid}")
        check(doc["result"]["status"] == "pending", f"--no-sync must be pending, got {doc['result']['status']}")

        # §2.5.2 status --id pending, then --sync -> published; idempotent
        p = run(root, *base, "status", "--id", pid, "--json")
        outputs.append(p.stdout)
        check(parse(p)["result"]["status"] == "pending", "status must be pending before sync")

        p = run(root, *base, "publish", "--file", sample, "--sync", "--json")
        outputs.append(p.stdout)
        doc = parse(p)
        check(p.returncode == 0 and doc["ok"] is True, f"publish --sync failed: {doc}")
        check(doc["result"]["publish_id"] == pid, "publish_id must be stable")
        check(doc["result"]["version"] == 1, "version must stay 1 for same content")
        check(doc["result"]["status"] == "published", f"expected published, got {doc['result']['status']}")

        p = run(root, *base, "status", "--id", pid, "--json")
        outputs.append(p.stdout)
        check(parse(p)["result"]["status"] == "published", "status must be published after sync")

        p = run(root, *base, "publish", "--file", sample, "--json")
        outputs.append(p.stdout)
        doc = parse(p)
        check(doc["result"]["publish_id"] == pid and doc["result"]["version"] == 1,
              "repeat publish must be idempotent (same id/version)")

        # §2.5.4 list contains it
        p = run(root, *base, "list", "--json")
        outputs.append(p.stdout)
        items = parse(p)["result"]["items"]
        check(any(item["publish_id"] == pid for item in items), "list must include the published item")

        # §2.5.3 health ok + required fields
        p = run(root, *base, "health", "--json")
        outputs.append(p.stdout)
        h = parse(p)
        check(h["ok"] is True, "health ok must be true")
        check(h["tool_version"] == "0.2.0" and h["contract_version"] == "0.1", "health version fields")
        check(h["result"]["vault_writable"] is True, "health.vault_writable must be present/true")

        # health failure: read-only vault -> VAULT_UNAVAILABLE (exit 1)
        os.chmod(repo, 0o555)
        try:
            p = run(root, *base, "publish", "--file", sample, "--json")
            outputs.append(p.stdout)
            ro = parse(p)
            check(p.returncode == 1, f"read-only vault exit must be 1, got {p.returncode}")
            check(ro["code"] == "VAULT_UNAVAILABLE", f"expected VAULT_UNAVAILABLE, got {ro.get('code')}")
        finally:
            os.chmod(repo, 0o755)

        # max-bytes -> INVALID_INPUT, exit 2, non-retryable
        big = os.path.join(root, "big.bin")
        with open(big, "wb") as fh:
            fh.write(b"x" * 2048)
        p = run(root, *base, "publish", "--file", big, "--max-bytes", "1024", "--json")
        outputs.append(p.stdout)
        doc = parse(p)
        check(p.returncode == 2, f"max-bytes exit must be 2, got {p.returncode}")
        check(doc["code"] == "INVALID_INPUT" and doc["retryable"] is False, "max-bytes must be INVALID_INPUT/non-retryable")

        # FILE_NOT_FOUND -> exit 2
        p = run(root, *base, "publish", "--file", os.path.join(root, "nope.md"), "--json")
        outputs.append(p.stdout)
        doc = parse(p)
        check(p.returncode == 2 and doc["code"] == "FILE_NOT_FOUND", "missing file must be FILE_NOT_FOUND/exit 2")

        # §2.5.5 no credentials in any stdout
        with open(mk_file, encoding="ascii") as fh:
            mk_text = fh.read().strip()
        for blob in outputs:
            check(mk_text not in blob.decode("utf-8", "replace"), "master key leaked to stdout")

        print(
            "PASS: contract 0.1 — publish/status/list/health/version, "
            "pending->published, idempotent, exit 0/2/1, no secret leak"
        )
        return 0
    except CheckFailure as exc:
        print(f"FAIL: {exc}")
        return 1
    finally:
        shutil.rmtree(root, ignore_errors=True)


if __name__ == "__main__":
    raise SystemExit(main())