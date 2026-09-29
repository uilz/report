#!/usr/bin/env python3
"""Multi-format support: kinds, office->pdf conversion and idempotent re-sync.

Builds fixtures (txt/md/pdf/docx) in temp dirs, runs init/add/sync --no-push
against a local repo, then decrypts the manifest and asserts:
  * .txt/.md/.pdf carry kinds text/md/pdf;
  * the .docx is converted to a published ``deck.pdf`` (kind pdf) and the
    docx source itself is NOT a manifest entry, and no "office" kind appears;
  * a second sync is a no-op ("no local changes") and does not reconvert;
  * editing the docx triggers exactly one reconversion (rev+1).
Local tools only (pandoc, soffice/libreoffice); no network. Prints PASS/FAIL.
"""
from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import tempfile

BIN = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(BIN))

import uzrlib as U  # noqa: E402

REPORT = os.path.join(os.path.dirname(BIN), "report")
PASSWORD = "test-password"


class CheckFailure(Exception):
    pass


def check(cond: bool, msg: str) -> None:
    if not cond:
        raise CheckFailure(msg)


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


def write_minimal_pdf(path: str) -> None:
    content = b"BT /F1 12 Tf 36 96 Td (uilz report fixture) Tj ET\n"
    objs = [
        b"<< /Type /Catalog /Pages 2 0 R >>",
        b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
        b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 300 200] "
        b"/Resources << /Font << /F1 5 0 R >> >> /Contents 4 0 R >>",
        b"<< /Length %d >>\nstream\n" % len(content) + content + b"endstream",
        b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>",
    ]
    out = bytearray(b"%PDF-1.4\n")
    offsets = []
    for i, body in enumerate(objs, 1):
        offsets.append(len(out))
        out += b"%d 0 obj\n" % i + body + b"\nendobj\n"
    xref = len(out)
    out += b"xref\n0 %d\n" % (len(objs) + 1)
    out += b"0000000000 65535 f \n"
    for off in offsets:
        out += b"%010d 00000 n \n" % off
    out += b"trailer\n<< /Size %d /Root 1 0 R >>\nstartxref\n%d\n%%%%EOF\n" % (
        len(objs) + 1,
        xref,
    )
    with open(path, "wb") as fh:
        fh.write(bytes(out))


def write_docx(docx_path: str, markdown: str) -> None:
    md_path = docx_path + ".src.md"
    with open(md_path, "w", encoding="utf-8") as fh:
        fh.write(markdown)
    proc = subprocess.run(["pandoc", "-o", docx_path, md_path], capture_output=True)
    if proc.returncode != 0:
        raise CheckFailure(f"pandoc failed: {proc.stderr.decode(errors='replace')}")


def read_bytes(path: str) -> bytes:
    with open(path, "rb") as fh:
        return fh.read()


def load_manifest(repo: str, mk_file: str) -> dict:
    mk = U.b64d(open(mk_file, encoding="ascii").read().strip())
    return U.decrypt_manifest(mk, read_bytes(os.path.join(repo, U.MANIFEST_NAME)))


def by_path(manifest: dict) -> dict:
    return {e["path"]: e for e in manifest["reports"]}


def main() -> int:
    root = tempfile.mkdtemp(prefix="uzr-formats-")
    try:
        repo = os.path.join(root, "repo")
        master = os.path.join(root, "master")
        cfg = os.path.join(root, "config.json")
        mk_file = os.path.join(root, "mk.key")
        lock = os.path.join(root, "sync.lock")
        os.makedirs(repo)
        os.makedirs(master)

        subprocess.run(["git", "init", "-q", "-b", "main", repo], check=True)
        subprocess.run(["git", "-C", repo, "config", "user.email", "t@example.com"], check=True)
        subprocess.run(["git", "-C", repo, "config", "user.name", "Tester"], check=True)

        fixtures = {
            "notes.txt": b"plain text body\n",
            "guide.md": b"# Guide\n\nbody text\n",
            "paper.pdf": None,
            "deck.docx": None,
        }
        for name in ("notes.txt", "guide.md"):
            with open(os.path.join(root, name), "wb") as fh:
                fh.write(fixtures[name])
        write_minimal_pdf(os.path.join(root, "paper.pdf"))
        write_docx(os.path.join(root, "deck.docx"), "# Deck\n\nslide one\n")

        base = ["--repo-dir", repo, "--master-dir", master, "--config", cfg, "--mk-file", mk_file]
        run(lock, *base, "init", "--yes")
        for name in fixtures:
            run(lock, *base, "add", os.path.join(root, name))

        run(lock, *base, "sync", "--no-push")

        manifest = load_manifest(repo, mk_file)
        entries = by_path(manifest)
        paths = set(entries)

        check(paths == {"notes.txt", "guide.md", "paper.pdf", "deck.pdf"},
              f"unexpected manifest paths: {sorted(paths)}")
        check(entries["notes.txt"]["kind"] == "text", "notes.txt must be kind text")
        check(entries["guide.md"]["kind"] == "md", "guide.md must be kind md")
        check(entries["paper.pdf"]["kind"] == "pdf", "paper.pdf must be kind pdf")
        check(entries["deck.pdf"]["kind"] == "pdf", "converted deck must be kind pdf")
        check(entries["deck.pdf"]["title"] == "deck", "converted pdf title must be the source stem")
        check("deck.docx" not in paths, "office source must never be a manifest entry")
        check(all(e["kind"] in ("md", "html", "pdf", "text") for e in manifest["reports"]),
              "manifest may only contain kinds md/html/pdf/text")

        check(os.path.exists(os.path.join(master, "deck.docx")), "docx source must remain on disk")
        check(os.path.exists(os.path.join(master, "deck.pdf")), "generated deck.pdf missing")

        # Second sync: idempotent, no LibreOffice re-run, no manifest rewrite.
        generated_pdf = os.path.join(master, "deck.pdf")
        pdf_before = read_bytes(generated_pdf)
        manifest_before = read_bytes(os.path.join(repo, U.MANIFEST_NAME))
        sidecar_before = read_bytes(os.path.join(master, U.CONVERT_STATE_NAME))
        second = run(lock, *base, "sync", "--no-push")
        second_out = second.stdout.decode(errors="replace")
        check("no local changes" in second_out, f"second sync not idempotent: {second_out!r}")
        check(read_bytes(generated_pdf) == pdf_before, "second sync must not reconvert deck.pdf")
        check(read_bytes(os.path.join(repo, U.MANIFEST_NAME)) == manifest_before,
              "second sync must not rewrite manifest.enc")
        check(read_bytes(os.path.join(master, U.CONVERT_STATE_NAME)) == sidecar_before,
              "second sync must not rewrite the conversion sidecar")

        # Editing the source triggers exactly one reconversion (rev+1).
        write_docx(os.path.join(master, "deck.docx"), "# Deck v2\n\nslide two, different\n")
        third = run(lock, *base, "sync", "--no-push")
        third_out = third.stdout.decode(errors="replace")
        check("converted deck.docx -> deck.pdf" in third_out, f"edit did not reconvert: {third_out!r}")
        check(read_bytes(generated_pdf) != pdf_before, "reconverted pdf must differ")
        manifest2 = load_manifest(repo, mk_file)
        deck2 = by_path(manifest2)["deck.pdf"]
        check(deck2["rev"] == 2, f"edited office source must bump rev to 2, got {deck2['rev']}")
        check(deck2["sha256"] == U.sha256_hex(read_bytes(generated_pdf)),
              "deck.pdf sha must match reconverted bytes")

        sidecar = json.load(open(os.path.join(master, U.CONVERT_STATE_NAME), encoding="utf-8"))
        check(sidecar.get("deck.docx") == U.sha256_hex(read_bytes(os.path.join(master, "deck.docx"))),
              "sidecar must record the current source sha")

        print("PASS: kinds text/md/pdf + docx->pdf publish; idempotent re-sync; edit reconverts (rev 2)")
        return 0
    except CheckFailure as exc:
        print(f"FAIL: {exc}")
        return 1
    finally:
        shutil.rmtree(root, ignore_errors=True)


if __name__ == "__main__":
    raise SystemExit(main())