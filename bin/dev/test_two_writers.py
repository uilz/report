#!/usr/bin/env python3
"""Two-writer prototype: offline edit + delete + concurrent push.

Simulates two writer machines against two local clones of one bare repo:
  * A and B both sync initially (X and Y published by A).
  * B edits X (rev+1) and deletes Y, then pushes.
  * A concurrently edits X differently and keeps Y, then syncs (fetch + merge).
  * B syncs again to pick up A's conflict copy.

Asserts: no data loss, both X versions preserved (conflict copy), Y tombstoned.
Local bare repo only -- no network. Prints PASS/FAIL, exits 0/1.
"""
from __future__ import annotations

import glob
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile

BIN = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(BIN))

import uzrlib as U  # noqa: E402

REPORT = os.path.join(os.path.dirname(BIN), "report")
PASSWORD = "test-password"
X_B = "X from writer B\n"
X_A = "X from writer A\n"
Y_V1 = "Y original\n"


class CheckFailure(Exception):
    pass


def check(cond: bool, msg: str) -> None:
    if not cond:
        raise CheckFailure(msg)


def git(*args: str, cwd: str | None = None) -> subprocess.CompletedProcess:
    proc = subprocess.run(["git", *args], cwd=cwd, capture_output=True)
    if proc.returncode != 0:
        raise CheckFailure(f"git {' '.join(args)} failed: {proc.stderr.decode(errors='replace')}")
    return proc


def run(env_lock: str, *args: str) -> subprocess.CompletedProcess:
    env = dict(os.environ)
    env["UZR_PASSWORD"] = PASSWORD
    env["UZR_SYNC_LOCK"] = env_lock
    proc = subprocess.run([sys.executable, REPORT, *args], capture_output=True, env=env)
    if proc.returncode != 0:
        raise CheckFailure(
            f"command failed ({proc.returncode}): {' '.join(args)}\n"
            f"stdout: {proc.stdout.decode(errors='replace')}\n"
            f"stderr: {proc.stderr.decode(errors='replace')}"
        )
    return proc


def read(path: str) -> str:
    with open(path, encoding="utf-8") as fh:
        return fh.read()


def writer(root: str, name: str) -> dict:
    return {
        "repo": os.path.join(root, name, "repo"),
        "master": os.path.join(root, name, "master"),
        "config": os.path.join(root, name, "config.json"),
    }


def main() -> int:
    root = tempfile.mkdtemp(prefix="uzr-two-writers-")
    try:
        bare = os.path.join(root, "origin.git")
        os.makedirs(bare)
        git("init", "--bare", "-q", "-b", "main", bare)
        lock = os.path.join(root, "sync.lock")

        mk_file = os.path.join(root, "mk.key")
        a = writer(root, "A")
        os.makedirs(a["repo"])
        os.makedirs(a["master"])

        # A starts as a clone of the (empty) bare repo so `origin` exists.
        git("clone", "-q", bare, a["repo"])
        git("-C", a["repo"], "config", "user.email", "a@example.com")
        git("-C", a["repo"], "config", "user.name", "Writer A")

        with open(os.path.join(a["master"], "X.md"), "w", encoding="utf-8") as fh:
            fh.write("X original\n")
        with open(os.path.join(a["master"], "Y.md"), "w", encoding="utf-8") as fh:
            fh.write(Y_V1)

        run(lock, "--repo-dir", a["repo"], "--master-dir", a["master"], "--config", a["config"],
            "--mk-file", mk_file, "init", "--yes")
        for name in ("X.md", "Y.md"):
            run(lock, "--repo-dir", a["repo"], "--master-dir", a["master"], "--config", a["config"],
                "--mk-file", mk_file, "add", os.path.join(a["master"], name))
        run(lock, "--repo-dir", a["repo"], "--master-dir", a["master"], "--config", a["config"],
            "--mk-file", mk_file, "sync")

        # B clones the published repo and pulls the plaintext + baseline.
        b = writer(root, "B")
        os.makedirs(b["repo"])
        os.makedirs(b["master"])
        git("clone", "-q", bare, b["repo"])
        git("-C", b["repo"], "config", "user.email", "b@example.com")
        git("-C", b["repo"], "config", "user.name", "Writer B")
        run(lock, "--repo-dir", b["repo"], "--master-dir", b["master"], "--config", b["config"],
            "--mk-file", mk_file, "pull")
        check(read(os.path.join(b["master"], "X.md")) == "X original\n", "B did not materialize X")
        check(read(os.path.join(b["master"], "Y.md")) == Y_V1, "B did not materialize Y")

        # B goes offline: edits X, deletes Y, then pushes its change.
        with open(os.path.join(b["master"], "X.md"), "w", encoding="utf-8") as fh:
            fh.write(X_B)
        os.remove(os.path.join(b["master"], "Y.md"))
        run(lock, "--repo-dir", b["repo"], "--master-dir", b["master"], "--config", b["config"],
            "--mk-file", mk_file, "sync")

        # A concurrently edits X differently and keeps Y, then syncs.
        with open(os.path.join(a["master"], "X.md"), "w", encoding="utf-8") as fh:
            fh.write(X_A)
        run(lock, "--repo-dir", a["repo"], "--master-dir", a["master"], "--config", a["config"],
            "--mk-file", mk_file, "sync")
        # B syncs to receive A's conflict copy.
        run(lock, "--repo-dir", b["repo"], "--master-dir", b["master"], "--config", b["config"],
            "--mk-file", mk_file, "sync")

        mk = U.b64d(open(mk_file, encoding="ascii").read().strip())
        remote_manifest = U.decrypt_manifest(
            mk, git("-C", a["repo"], "show", "origin/main:manifest.enc").stdout
        )
        by_path = {e["path"]: e for e in remote_manifest["reports"]}
        x_entry = by_path["X.md"]

        for label, w in (("A", a), ("B", b)):
            x_path = os.path.join(w["master"], "X.md")
            check(os.path.exists(x_path), f"writer {label}: X missing")
            check(read(x_path) == X_B, f"writer {label}: X must hold writer B's version")
            check(not os.path.exists(os.path.join(w["master"], "Y.md")), f"writer {label}: Y must be deleted")
            conflicts = glob.glob(os.path.join(w["master"], "X.md.conflict-*"))
            check(len(conflicts) == 1, f"writer {label}: expected exactly 1 conflict copy, got {len(conflicts)}")
            check(read(conflicts[0]) == X_A, f"writer {label}: conflict copy must hold writer A's version")

        conflict_name = os.path.basename(glob.glob(os.path.join(a["master"], "X.md.conflict-*"))[0])
        check(re.match(r"^X\.md\.conflict-[0-9a-f]{8}-\d+$", conflict_name), f"bad conflict name {conflict_name}")

        y_entry = by_path.get("Y.md")
        check(y_entry is not None, "Y tombstone missing from remote manifest")
        check(y_entry["deleted"] is True, "Y must be a tombstone")
        check(y_entry["rev"] > 1, "Y tombstone must bump rev")

        check(x_entry["deleted"] is False, "X must stay live")
        check(x_entry["rev"] == 2, f"X rev must be 2 (writer B's edit), got {x_entry['rev']}")
        check(x_entry["sha256"] == U.sha256_hex(X_B.encode()), "X sha must match writer B's content")

        conflict_entry = by_path.get(conflict_name)
        check(conflict_entry is not None, "conflict copy must be a manifest entry")
        check(conflict_entry["sha256"] == U.sha256_hex(X_A.encode()), "conflict sha must match writer A's content")
        check(conflict_entry["rev"] == 1, "conflict copy is a new id at rev 1")

        live = [e for e in remote_manifest["reports"] if not e.get("deleted")]
        for e in live:
            check(len(e["sha256"]) == 64 and e["sha256"] == e["sha256"].lower(), f"live sha not 64-hex: {e['id']}")

        contents = {read(os.path.join(a["master"], "X.md")), read(glob.glob(os.path.join(a["master"], "X.md.conflict-*"))[0])}
        check(contents == {X_A, X_B}, "both X versions must survive (no silent loss)")

        print("PASS: no data loss; conflict copy preserved both versions; Y tombstoned correctly")
        return 0
    except CheckFailure as exc:
        print(f"FAIL: {exc}")
        return 1
    finally:
        shutil.rmtree(root, ignore_errors=True)


if __name__ == "__main__":
    raise SystemExit(main())