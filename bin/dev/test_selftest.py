#!/usr/bin/env python3
"""Self-test: init -> add -> sync --no-push -> decrypt and verify integrity.

Runs entirely against temp dirs with a local repo (no network, no remote).
Prints PASS/FAIL and exits 0/1.
"""
from __future__ import annotations

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
ISO_RE = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")
PASSWORD = "test-password"


class CheckFailure(Exception):
    pass


def check(cond: bool, msg: str) -> None:
    if not cond:
        raise CheckFailure(msg)


def run(*args: str, env: dict | None = None) -> subprocess.CompletedProcess:
    full_env = dict(os.environ)
    full_env["UZR_PASSWORD"] = PASSWORD
    if env:
        full_env.update(env)
    proc = subprocess.run([sys.executable, REPORT, *args], capture_output=True, env=full_env)
    if proc.returncode != 0:
        raise CheckFailure(
            f"command failed ({proc.returncode}): {' '.join(args)}\n"
            f"stdout: {proc.stdout.decode(errors='replace')}\n"
            f"stderr: {proc.stderr.decode(errors='replace')}"
        )
    return proc


def main() -> int:
    root = tempfile.mkdtemp(prefix="uzr-selftest-")
    try:
        repo = os.path.join(root, "repo")
        master = os.path.join(root, "master")
        cfg = os.path.join(root, "config.json")
        mk_file = os.path.join(root, "mk.key")
        os.makedirs(repo)
        os.makedirs(master)

        subprocess.run(["git", "init", "-q", "-b", "main", repo], check=True)
        subprocess.run(["git", "-C", repo, "config", "user.email", "t@example.com"], check=True)
        subprocess.run(["git", "-C", repo, "config", "user.name", "Tester"], check=True)

        sample = os.path.join(root, "hello.md")
        with open(sample, "w", encoding="utf-8") as fh:
            fh.write("# Hello\n\nnon-ascii: \u4f60\u597d\n")
        sample_bytes = open(sample, "rb").read()

        base_args = ["--repo-dir", repo, "--master-dir", master, "--config", cfg, "--mk-file", mk_file]
        run(*base_args, "init", "--yes")
        run(*base_args, "add", sample)

        manifest_before = open(os.path.join(repo, U.MANIFEST_NAME), "rb").read()
        state_before = os.path.exists(os.path.join(master, U.STATE_NAME))
        run(*base_args, "sync", "--dry-run")
        check(open(os.path.join(repo, U.MANIFEST_NAME), "rb").read() == manifest_before, "dry-run altered manifest")
        check(os.path.exists(os.path.join(master, U.STATE_NAME)) == state_before, "dry-run wrote baseline")
        check(not os.listdir(os.path.join(repo, U.BLOBS_DIR)), "dry-run wrote a blob")

        run(*base_args, "sync", "--no-push")

        mk = U.b64d(open(mk_file, encoding="ascii").read().strip())
        check(len(mk) == 32, "MK must be 32 bytes")

        manifest_path = os.path.join(repo, U.MANIFEST_NAME)
        check(os.path.exists(manifest_path), "manifest.enc missing")
        manifest = U.decrypt_manifest(mk, open(manifest_path, "rb").read())
        check(manifest["v"] == 1, "manifest.v must be 1")
        check(ISO_RE.match(manifest["updatedAt"]), f"bad updatedAt: {manifest['updatedAt']}")
        check(len(manifest["reports"]) == 1, f"expected 1 report, got {len(manifest['reports'])}")
        entry = manifest["reports"][0]

        check(len(entry["id"]) == 32 and all(c in "0123456789abcdef" for c in entry["id"]), "bad id")
        check(entry["path"] == "hello.md", f"bad path {entry['path']}")
        check(entry["rev"] == 1, "rev must be 1")
        check(entry["deleted"] is False, "entry must be live")
        check(entry["sha256"] == U.sha256_hex(sample_bytes), "sha256 mismatch")
        check(len(entry["sha256"]) == 64 and entry["sha256"] == entry["sha256"].lower(), "sha not 64-hex")
        check(entry["size"] == len(sample_bytes), "size must be utf-8 byte length")
        check(ISO_RE.match(entry["updatedAt"]), f"bad entry updatedAt: {entry['updatedAt']}")

        blob_path = os.path.join(repo, U.BLOBS_DIR, f"{entry['id']}-{entry['rev']}.enc")
        check(os.path.exists(blob_path), "blob missing")
        blob = open(blob_path, "rb").read()
        check(blob[:4] == U.BLOB_MAGIC, "blob magic missing")
        check(U.decrypt_blob(mk, entry["id"], entry["rev"], blob) == sample_bytes, "blob plaintext mismatch")

        key_doc = json.load(open(os.path.join(repo, U.KEY_ENC_NAME), encoding="utf-8"))
        check(key_doc["kdf"]["algo"] == "argon2id", "kdf algo must be argon2id")
        check(key_doc["kdf"]["t"] == 3 and key_doc["kdf"]["m"] == 65536 and key_doc["kdf"]["p"] == 1, "argon2 params")
        check(key_doc["kdf"]["version"] == 19 and key_doc["kdf"]["hashLen"] == 32, "argon2 version/hashLen")
        recovered = U.unwrap_key_enc(PASSWORD, key_doc)
        check(recovered == mk, "password unwrap must recover the machine key")

        state = json.load(open(os.path.join(master, U.STATE_NAME), encoding="utf-8"))
        check(entry["id"] in state["entries"], "baseline must record the synced id")
        check(state["entries"][entry["id"]]["sha256"] == entry["sha256"], "baseline sha mismatch")

        check(not os.path.exists(os.path.join(repo, U.STATE_NAME)), "baseline must not live in the repo")
        check(not os.path.exists(os.path.join(repo, "mk.key")), "mk.key must not live in the repo")

        print("PASS: init/add/sync --no-push; manifest, blob, key.enc and baseline verified")
        return 0
    except CheckFailure as exc:
        print(f"FAIL: {exc}")
        return 1
    finally:
        shutil.rmtree(root, ignore_errors=True)


if __name__ == "__main__":
    raise SystemExit(main())