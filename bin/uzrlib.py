"""uilz-report v1 library: crypto, formats, state and the sync engine.

Implements SPEC.md v1.1 §2, §3, §5 and §6 literally. Pure stdlib plus
``cryptography`` (AESGCM/HKDF) and ``argon2-cffi``.
"""
from __future__ import annotations

import base64
import fcntl
import hashlib
import json
import os
import re
import secrets
import shutil
import subprocess
import time
import unicodedata
from contextlib import contextmanager
from datetime import datetime, timezone

from argon2.low_level import Type, hash_secret_raw
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

# --------------------------------------------------------------------------
# Frozen constants (SPEC §2 / §3)
# --------------------------------------------------------------------------
BLOB_MAGIC = b"UZR1"
KEY_INFO = b"uilz-report/v1/key"
MANIFEST_INFO = b"uilz-report/v1/manifest"
BLOB_INFO_PREFIX = b"uilz-report/v1/blob:"

ARGON2_T = 3
ARGON2_M = 65536
ARGON2_P = 1
ARGON2_HASH_LEN = 32
ARGON2_VERSION = 19
PBKDF2_ITERATIONS = 600000

SALT_LEN = 16
MK_LEN = 32
IV_LEN = 12
ID_HEX_LEN = 32
SHA_HEX_LEN = 64

STATE_NAME = ".report-state.json"
META_NAME = ".report-meta.json"
CONVERT_STATE_NAME = ".report-convert.json"
MANIFEST_NAME = "manifest.enc"
KEY_ENC_NAME = "key.enc"
BLOBS_DIR = "blobs"

DEFAULT_REMOTE = "origin"
DEFAULT_BRANCH = "main"
COMMIT_IDENTITY = ["-c", "user.name=uilz-report", "-c", "user.email=uilz-report@localhost"]

CONVERT_TIMEOUT = 120


class SyrError(Exception):
    """Any expected, user-facing failure."""


class Abort(SyrError):
    """A mutation-step failure that must abort without writing a tombstone."""


# --------------------------------------------------------------------------
# Small helpers
# --------------------------------------------------------------------------
def now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def b64e(data: bytes) -> str:
    return base64.standard_b64encode(data).decode("ascii")


def b64d(text: str) -> bytes:
    return base64.standard_b64decode(text.encode("ascii"))


def password_bytes(password: str) -> bytes:
    return unicodedata.normalize("NFC", password).encode("utf-8")


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def info_blob(report_id: str, rev: int) -> bytes:
    return BLOB_INFO_PREFIX + report_id.encode("ascii") + b":" + str(rev).encode("ascii")


MD_EXTS = frozenset({".md", ".markdown"})
HTML_EXTS = frozenset({".html", ".htm"})
PDF_EXTS = frozenset({".pdf"})
TEXT_EXTS = frozenset(
    {".txt", ".csv", ".log", ".json", ".xml", ".yaml", ".yml", ".ini", ".conf", ".tsv"}
)
OFFICE_EXTS = frozenset(
    {".docx", ".doc", ".odt", ".rtf", ".xlsx", ".xls", ".ods", ".pptx", ".ppt", ".odp"}
)


def kind_for(path: str) -> str:
    base = re.sub(r"\.conflict-[0-9a-f]{8}-\d+$", "", path)
    ext = os.path.splitext(base)[1].lower()
    if ext in MD_EXTS:
        return "md"
    if ext in HTML_EXTS:
        return "html"
    if ext in PDF_EXTS:
        return "pdf"
    if ext in OFFICE_EXTS:
        return "office"
    return "text"


def is_office_path(path: str) -> bool:
    return os.path.splitext(path)[1].lower() in OFFICE_EXTS


def stem_for(path: str) -> str:
    return os.path.splitext(os.path.basename(path))[0]


def conflict_path(path: str, report_id: str, rev: int) -> str:
    return f"{path}.conflict-{report_id[:8]}-{rev}"


def read_stable(path: str) -> bytes:
    """Read a file, re-reading if it changed mid-read (SPEC §6 consistency)."""
    data = b""
    for _ in range(8):
        with open(path, "rb") as fh:
            data = fh.read()
        with open(path, "rb") as fh:
            again = fh.read()
        if again == data:
            return data
        data = again
    return data


# --------------------------------------------------------------------------
# Key derivation / envelope (SPEC §2, §3.1)
# --------------------------------------------------------------------------
def argon2id(
    pw: bytes,
    salt: bytes,
    t: int = ARGON2_T,
    m: int = ARGON2_M,
    p: int = ARGON2_P,
    hash_len: int = ARGON2_HASH_LEN,
    version: int = ARGON2_VERSION,
) -> bytes:
    return hash_secret_raw(
        secret=pw,
        salt=salt,
        time_cost=t,
        memory_cost=m,
        parallelism=p,
        hash_len=hash_len,
        type=Type.ID,
        version=version,
    )


def pbkdf2(pw: bytes, salt: bytes, iterations: int, hash_name: str, hash_len: int) -> bytes:
    return hashlib.pbkdf2_hmac(hash_name, pw, salt, iterations, dklen=hash_len)


def hkdf(mk: bytes, info: bytes, length: int = 32) -> bytes:
    return HKDF(algorithm=hashes.SHA256(), length=length, salt=b"", info=info).derive(mk)


def kek_from_kdf(pw: bytes, kdf: dict) -> bytes:
    algo = kdf.get("algo")
    salt = b64d(kdf["salt"])
    if algo == "argon2id":
        return argon2id(
            pw,
            salt,
            t=int(kdf.get("t", ARGON2_T)),
            m=int(kdf.get("m", ARGON2_M)),
            p=int(kdf.get("p", ARGON2_P)),
            hash_len=int(kdf.get("hashLen", ARGON2_HASH_LEN)),
            version=int(kdf.get("version", ARGON2_VERSION)),
        )
    if algo == "pbkdf2-sha256":
        return pbkdf2(
            pw,
            salt,
            int(kdf["iterations"]),
            str(kdf.get("hash", "sha256")),
            int(kdf.get("hashLen", 32)),
        )
    raise SyrError(f"unsupported kdf algo: {algo!r}")


def build_key_enc(password: str, mk: bytes, algo: str = "argon2id") -> dict:
    pw = password_bytes(password)
    salt = secrets.token_bytes(SALT_LEN)
    if algo == "argon2id":
        kek = argon2id(pw, salt)
        kdf = {
            "algo": "argon2id",
            "version": ARGON2_VERSION,
            "t": ARGON2_T,
            "m": ARGON2_M,
            "p": ARGON2_P,
            "hashLen": ARGON2_HASH_LEN,
            "salt": b64e(salt),
        }
    elif algo == "pbkdf2-sha256":
        iters = PBKDF2_ITERATIONS
        kek = pbkdf2(pw, salt, iters, "sha256", 32)
        kdf = {
            "algo": "pbkdf2-sha256",
            "iterations": iters,
            "hash": "sha256",
            "hashLen": 32,
            "salt": b64e(salt),
        }
    else:
        raise SyrError(f"unsupported key.enc algo: {algo!r}")
    iv = secrets.token_bytes(IV_LEN)
    ct = AESGCM(kek).encrypt(iv, mk, KEY_INFO)
    return {"v": 1, "kdf": kdf, "wrapped": {"iv": b64e(iv), "ct": b64e(ct)}}


def unwrap_key_enc(password: str, doc: dict) -> bytes:
    kek = kek_from_kdf(password_bytes(password), doc["kdf"])
    iv = b64d(doc["wrapped"]["iv"])
    ct = b64d(doc["wrapped"]["ct"])
    try:
        return AESGCM(kek).decrypt(iv, ct, KEY_INFO)
    except Exception as exc:  # InvalidTag
        raise SyrError("wrong password (key.enc authentication failed)") from exc


# --------------------------------------------------------------------------
# Blob / manifest crypto (SPEC §3.2, §3.3)
# --------------------------------------------------------------------------
def encrypt_blob(mk: bytes, report_id: str, rev: int, plaintext: bytes) -> bytes:
    ck = hkdf(mk, info_blob(report_id, rev))
    iv = secrets.token_bytes(IV_LEN)
    return BLOB_MAGIC + iv + AESGCM(ck).encrypt(iv, plaintext, info_blob(report_id, rev))


def decrypt_blob(mk: bytes, report_id: str, rev: int, blob: bytes) -> bytes:
    if len(blob) < len(BLOB_MAGIC) + IV_LEN + 16:
        raise Abort(f"blob {report_id}-{rev} too short")
    if blob[:4] != BLOB_MAGIC:
        raise Abort(f"blob {report_id}-{rev} bad magic")
    iv = blob[4 : 4 + IV_LEN]
    ct = blob[4 + IV_LEN :]
    ck = hkdf(mk, info_blob(report_id, rev))
    try:
        return AESGCM(ck).decrypt(iv, ct, info_blob(report_id, rev))
    except Exception as exc:
        raise Abort(f"blob {report_id}-{rev} decrypt failed") from exc


def manifest_json_bytes(obj: dict) -> bytes:
    return json.dumps(obj, ensure_ascii=False, separators=(",", ":"), sort_keys=True).encode("utf-8")


def encrypt_manifest(mk: bytes, obj: dict) -> bytes:
    key = hkdf(mk, MANIFEST_INFO)
    iv = secrets.token_bytes(IV_LEN)
    return iv + AESGCM(key).encrypt(iv, manifest_json_bytes(obj), MANIFEST_INFO)


def decrypt_manifest(mk: bytes, data: bytes) -> dict:
    if len(data) < IV_LEN + 16:
        raise Abort("manifest.enc too short")
    key = hkdf(mk, MANIFEST_INFO)
    try:
        pt = AESGCM(key).decrypt(data[:IV_LEN], data[IV_LEN:], MANIFEST_INFO)
    except Exception as exc:
        raise Abort("manifest.enc decrypt failed") from exc
    return json.loads(pt.decode("utf-8"))


def new_manifest(now: str | None = None) -> dict:
    return {"v": 1, "updatedAt": now or now_iso(), "reports": []}


def index_reports(manifest: dict) -> dict:
    return {r["id"]: r for r in manifest.get("reports", [])}


def make_entry(
    report_id: str,
    path: str,
    meta: dict | None,
    *,
    rev: int,
    sha: str,
    size: int,
    updated_at: str,
    deleted: bool = False,
) -> dict:
    meta = meta or {}
    return {
        "id": report_id,
        "path": path,
        "title": meta.get("title") or stem_for(path),
        "kind": meta.get("kind") or kind_for(path),
        "rev": rev,
        "sha256": sha,
        "size": size,
        "updatedAt": updated_at,
        "deleted": deleted,
    }


def make_tombstone(report_id: str, path: str, *, rev: int, prev: dict | None, updated_at: str) -> dict:
    prev = prev or {}
    return {
        "id": report_id,
        "path": path,
        "title": prev.get("title") or stem_for(path),
        "kind": prev.get("kind") or kind_for(path),
        "rev": rev,
        "sha256": prev.get("sha256", ""),
        "size": prev.get("size", 0),
        "updatedAt": updated_at,
        "deleted": True,
    }


# --------------------------------------------------------------------------
# Settings / paths / config (SPEC §5)
# --------------------------------------------------------------------------
def _repo_root_from_module() -> str:
    return os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


class Settings:
    def __init__(
        self,
        repo_dir: str,
        master_dir: str,
        *,
        config_path: str,
        mk_path: str,
        lock_path: str,
        remote: str,
        branch: str,
    ) -> None:
        self.repo_dir = os.path.abspath(repo_dir)
        self.master_dir = os.path.abspath(master_dir)
        self.config_path = os.path.abspath(config_path)
        self.mk_path = os.path.abspath(mk_path)
        self.lock_path = os.path.abspath(lock_path)
        self.remote = remote
        self.branch = branch

    @property
    def state_path(self) -> str:
        return os.path.join(self.master_dir, STATE_NAME)

    @property
    def remote_ref(self) -> str:
        return f"{self.remote}/{self.branch}"


def default_config_path() -> str:
    return os.path.expanduser("~/.config/uilz-report/config.json")


def default_mk_path() -> str:
    return os.path.expanduser("~/.config/uilz-report/mk.key")


def default_lock_path() -> str:
    return os.environ.get("UZR_SYNC_LOCK") or os.path.expanduser("~/.cache/uzr-sync.lock")


def load_settings(
    *,
    config_path: str | None = None,
    repo_dir: str | None = None,
    master_dir: str | None = None,
    remote: str | None = None,
    branch: str | None = None,
    mk_file: str | None = None,
) -> Settings:
    cfg_path = config_path or os.environ.get("UZR_CONFIG") or default_config_path()
    file_cfg: dict = {}
    if os.path.exists(cfg_path):
        try:
            with open(cfg_path, encoding="utf-8") as fh:
                file_cfg = json.load(fh)
        except (OSError, ValueError) as exc:
            raise SyrError(f"cannot read config {cfg_path}: {exc}") from exc
    values = {
        "repo_dir": repo_dir or file_cfg.get("repo_dir") or _repo_root_from_module(),
        "master_dir": master_dir
        or file_cfg.get("master_dir")
        or os.path.expanduser("~/develop/githubio-sharing-report"),
        "remote": remote or file_cfg.get("remote") or DEFAULT_REMOTE,
        "branch": branch or file_cfg.get("branch") or DEFAULT_BRANCH,
        "config_path": cfg_path,
        "mk_path": mk_file or file_cfg.get("mk_file") or default_mk_path(),
        "lock_path": file_cfg.get("lock_file") or default_lock_path(),
    }
    return Settings(
        values["repo_dir"],
        values["master_dir"],
        config_path=values["config_path"],
        mk_path=values["mk_path"],
        lock_path=values["lock_path"],
        remote=values["remote"],
        branch=values["branch"],
    )


def save_config(settings: Settings) -> None:
    os.makedirs(os.path.dirname(settings.config_path), exist_ok=True)
    doc = {
        "repo_dir": settings.repo_dir,
        "master_dir": settings.master_dir,
        "remote": settings.remote,
        "branch": settings.branch,
    }
    with open(settings.config_path, "w", encoding="utf-8") as fh:
        json.dump(doc, fh, indent=2)
        fh.write("\n")


# --------------------------------------------------------------------------
# MK handling (SPEC §5)
# --------------------------------------------------------------------------
def load_mk(settings: Settings) -> bytes:
    env = os.environ.get("UZR_MK")
    source = settings.mk_path
    if env:
        raw = env.strip()
    elif os.path.exists(settings.mk_path):
        with open(settings.mk_path, encoding="ascii") as fh:
            raw = fh.read().strip()
    else:
        raise SyrError(f"no machine key: set UZR_MK or create {settings.mk_path}")
    try:
        mk = b64d(raw)
    except Exception as exc:
        raise SyrError(f"invalid MK (base64) from {source}") from exc
    if len(mk) != MK_LEN:
        raise SyrError(f"invalid MK length from {source}: {len(mk)}")
    return mk


def save_mk(settings: Settings, mk: bytes) -> None:
    os.makedirs(os.path.dirname(settings.mk_path), exist_ok=True)
    fd = os.open(settings.mk_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="ascii") as fh:
        fh.write(b64e(mk) + "\n")
    os.chmod(settings.mk_path, 0o600)


# --------------------------------------------------------------------------
# Baseline / master scan / lock (SPEC §5, §6)
# --------------------------------------------------------------------------
def read_baseline(settings: Settings) -> dict:
    path = settings.state_path
    if not os.path.exists(path):
        return {"lastSync": None, "entries": {}}
    try:
        with open(path, encoding="utf-8") as fh:
            doc = json.load(fh)
    except (OSError, ValueError):
        return {"lastSync": None, "entries": {}}
    doc.setdefault("entries", {})
    return doc


def write_baseline(settings: Settings, reports: list[dict], now: str) -> None:
    entries = {}
    for r in reports:
        entries[r["id"]] = {
            "rev": r["rev"],
            "sha256": r.get("sha256", ""),
            "path": r.get("path", ""),
            "deleted": bool(r.get("deleted")),
        }
    doc = {"lastSync": now, "entries": entries}
    os.makedirs(settings.master_dir, exist_ok=True)
    with open(settings.state_path, "w", encoding="utf-8") as fh:
        json.dump(doc, fh, indent=2)
        fh.write("\n")


def load_titles(settings: Settings) -> dict:
    path = os.path.join(settings.master_dir, META_NAME)
    if not os.path.exists(path):
        return {}
    try:
        with open(path, encoding="utf-8") as fh:
            return json.load(fh).get("titles", {})
    except (OSError, ValueError):
        return {}


def save_title(settings: Settings, rel_path: str, title: str) -> None:
    path = os.path.join(settings.master_dir, META_NAME)
    titles = load_titles(settings)
    titles[rel_path] = title
    with open(path, "w", encoding="utf-8") as fh:
        json.dump({"titles": titles}, fh, indent=2)
        fh.write("\n")


def _is_ignored(rel: str) -> bool:
    parts = rel.split(os.sep)
    if any(p.startswith(".") for p in parts):
        return True
    base = os.path.basename(rel)
    return base in (STATE_NAME, META_NAME)


def scan_master(settings: Settings) -> dict:
    """Return {relpath: {'sha':..., 'size':...}} for publishable plaintext."""
    root = settings.master_dir
    out: dict = {}
    if not os.path.isdir(root):
        return out
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if not d.startswith(".")]
        for name in filenames:
            if name.startswith("."):
                continue
            full = os.path.join(dirpath, name)
            rel = os.path.relpath(full, root)
            if _is_ignored(rel):
                continue
            data = read_stable(full)
            out[rel] = {"sha": sha256_hex(data), "size": len(data)}
    return out


# --------------------------------------------------------------------------
# Office -> PDF conversion (format contract / SPEC §5)
# --------------------------------------------------------------------------
def convert_state_path(settings: Settings) -> str:
    return os.path.join(settings.master_dir, CONVERT_STATE_NAME)


def load_convert_state(settings: Settings) -> dict:
    path = convert_state_path(settings)
    if not os.path.exists(path):
        return {}
    try:
        with open(path, encoding="utf-8") as fh:
            doc = json.load(fh)
    except (OSError, ValueError):
        return {}
    if not isinstance(doc, dict):
        return {}
    return {str(k): str(v) for k, v in doc.items()}


def save_convert_state(settings: Settings, mapping: dict) -> None:
    os.makedirs(settings.master_dir, exist_ok=True)
    with open(convert_state_path(settings), "w", encoding="utf-8") as fh:
        json.dump(mapping, fh, indent=2, sort_keys=True)
        fh.write("\n")


def list_office_sources(master_dir: str) -> list[tuple[str, str]]:
    """Return sorted (relpath, abspath) for every office input under master_dir."""
    out: list[tuple[str, str]] = []
    if not os.path.isdir(master_dir):
        return out
    for dirpath, dirnames, filenames in os.walk(master_dir):
        dirnames[:] = [d for d in dirnames if not d.startswith(".")]
        for name in filenames:
            if name.startswith(".") or not is_office_path(name):
                continue
            full = os.path.join(dirpath, name)
            out.append((os.path.relpath(full, master_dir), full))
    return sorted(out)


def _libreoffice_bin() -> str:
    for name in ("soffice", "libreoffice"):
        found = shutil.which(name)
        if found:
            return found
    raise SyrError("LibreOffice not found: install soffice/libreoffice to publish office documents")


def _convert_one(src: str) -> str:
    outdir = os.path.dirname(src) or "."
    cmd = [
        _libreoffice_bin(),
        "--headless",
        "--convert-to",
        "pdf",
        "--outdir",
        outdir,
        f"-env:UserInstallation=file:///tmp/uzr-lo-{os.getuid()}",
        src,
    ]
    try:
        proc = subprocess.run(cmd, capture_output=True, timeout=CONVERT_TIMEOUT)
    except subprocess.TimeoutExpired as exc:
        raise SyrError(
            f"libreoffice conversion timed out after {CONVERT_TIMEOUT}s: {os.path.basename(src)}"
        ) from exc
    if proc.returncode != 0:
        err = proc.stderr.decode("utf-8", "replace").strip()
        if not err:
            err = proc.stdout.decode("utf-8", "replace").strip()
        raise SyrError(f"libreoffice conversion failed for {os.path.basename(src)}: {err}")
    target = os.path.join(outdir, stem_for(src) + ".pdf")
    if not os.path.exists(target):
        raise SyrError(
            f"libreoffice produced no {os.path.basename(target)} for {os.path.basename(src)}"
        )
    return target


def convert_office(settings: Settings, published: dict | None = None, *, dry_run: bool = False) -> dict:
    """Ensure every office input has an up-to-date sibling ``<stem>.pdf``.

    A conversion is skipped when the sibling PDF already matches: either the
    local ``.report-convert.json`` records the source sha, or the published
    manifest pairs this exact source sha with the PDF's current bytes, so a
    freshly pulled machine never re-runs LibreOffice.
    """
    sources = list_office_sources(settings.master_dir)
    state = load_convert_state(settings)
    pub = published or {}
    new_state: dict = {}
    converted: dict = {}
    for rel, full in sources:
        sha = sha256_hex(read_stable(full))
        target = os.path.join(os.path.dirname(full) or settings.master_dir, stem_for(full) + ".pdf")
        target_rel = os.path.relpath(target, settings.master_dir)
        exists = os.path.exists(target)
        up_to_date = exists and (
            state.get(rel) == sha
            or (pub.get(rel) == sha and pub.get(target_rel) == sha256_hex(read_stable(target)))
        )
        if not up_to_date:
            converted[rel] = target_rel
            if not dry_run:
                _convert_one(full)
        new_state[rel] = sha
    if not dry_run and new_state != state:
        save_convert_state(settings, new_state)
    return {"converted": converted, "sources": len(sources), "state": new_state}


def safe_join(base: str, rel: str) -> str:
    if os.path.isabs(rel):
        raise SyrError(f"unsafe absolute path in manifest: {rel}")
    joined = os.path.normpath(os.path.join(base, rel))
    if joined != base and not joined.startswith(base + os.sep):
        raise SyrError(f"unsafe path escapes master dir: {rel}")
    return joined


@contextmanager
def sync_lock(settings: Settings):
    path = settings.lock_path
    os.makedirs(os.path.dirname(path), exist_ok=True)
    fd = os.open(path, os.O_RDWR | os.O_CREAT, 0o644)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX)
        yield
    finally:
        fcntl.flock(fd, fcntl.LOCK_UN)
        os.close(fd)


# --------------------------------------------------------------------------
# Git plumbing (SPEC §6)
# --------------------------------------------------------------------------
def git(repo: str, args: list[str], check: bool = True) -> subprocess.CompletedProcess:
    proc = subprocess.run(["git", "-C", repo, *args], capture_output=True)
    if check and proc.returncode != 0:
        err = proc.stderr.decode("utf-8", "replace").strip()
        raise SyrError(f"git {' '.join(args)} failed: {err}")
    return proc


def git_retry(repo: str, args: list[str], attempts: int = 3) -> subprocess.CompletedProcess:
    last = ""
    for i in range(attempts):
        proc = git(repo, args, check=False)
        if proc.returncode == 0:
            return proc
        last = proc.stderr.decode("utf-8", "replace").strip()
        if i < attempts - 1:
            time.sleep(min(2 ** i, 8))
    raise SyrError(f"git {' '.join(args)} failed after {attempts} attempts: {last}")


def is_git_repo(repo: str) -> bool:
    return git(repo, ["rev-parse", "--git-dir"], check=False).returncode == 0


def is_clean(repo: str) -> bool:
    proc = git(repo, ["status", "--porcelain", "--untracked-files=no"], check=False)
    return proc.returncode == 0 and proc.stdout.strip() == b""


def remote_configured(settings: Settings) -> bool:
    return git(settings.repo_dir, ["remote", "get-url", settings.remote], check=False).returncode == 0


def fetch(settings: Settings) -> None:
    if not remote_configured(settings):
        return
    git_retry(settings.repo_dir, ["fetch", "--prune", settings.remote])


def ref_exists(settings: Settings, ref: str | None = None) -> bool:
    ref = ref or settings.remote_ref
    return git(settings.repo_dir, ["rev-parse", "--verify", "--quiet", ref], check=False).returncode == 0


def rev_parse(settings: Settings, rev: str) -> str | None:
    proc = git(settings.repo_dir, ["rev-parse", "--verify", "--quiet", rev], check=False)
    if proc.returncode != 0:
        return None
    return proc.stdout.decode().strip() or None


def cat_file(settings: Settings, ref: str, path: str) -> bytes | None:
    proc = git(settings.repo_dir, ["show", f"{ref}:{path}"], check=False)
    if proc.returncode != 0:
        return None
    return proc.stdout


def reset_hard(settings: Settings, rev: str) -> None:
    git(settings.repo_dir, ["reset", "--hard", rev])


def commit_all(settings: Settings, message: str) -> bool:
    git(settings.repo_dir, ["add", "-A"])
    if git(settings.repo_dir, ["diff", "--cached", "--quiet"], check=False).returncode == 0:
        return False
    extra = []
    if not git(settings.repo_dir, ["config", "user.email"], check=False).stdout.strip():
        extra = list(COMMIT_IDENTITY)
    git(settings.repo_dir, [*extra, "commit", "-m", message])
    return True


def read_remote_manifest(settings: Settings, mk: bytes) -> dict:
    if not ref_exists(settings):
        return new_manifest()
    data = cat_file(settings, settings.remote_ref, MANIFEST_NAME)
    if data is None:
        return new_manifest()
    return decrypt_manifest(mk, data)


def read_local_manifest(settings: Settings, mk: bytes) -> dict:
    path = os.path.join(settings.repo_dir, MANIFEST_NAME)
    if not os.path.exists(path):
        return new_manifest()
    with open(path, "rb") as fh:
        return decrypt_manifest(mk, fh.read())


# --------------------------------------------------------------------------
# Merge engine (SPEC §6.1 step 4)
# --------------------------------------------------------------------------
def plan_merge(
    baseline: dict,
    local_map: dict,
    remote_map: dict,
    snapshot: dict,
    now: str,
    new_id,
    titles: dict | None = None,
) -> tuple[dict, list]:
    """Three-way merge. Returns (reports_by_id, ops).

    ops are ("move", src, dst), ("materialize", id, rev, path), ("delete", path, expected_sha).
    """
    reports: dict = {}
    ops: list = []
    consumed: set = set()

    def snap(path):
        return snapshot.get(path)

    def entry_from_meta(report_id, path, meta, rev, sha, size, updated_at, deleted=False):
        return make_entry(
            report_id, path, meta, rev=rev, sha=sha, size=size, updated_at=updated_at, deleted=deleted
        )

    ids = sorted(set(baseline) | set(local_map) | set(remote_map))
    for rid in ids:
        base = baseline.get(rid)
        le = local_map.get(rid)
        re_ = remote_map.get(rid)
        path = None
        for src in (base, le, re_):
            if src and src.get("path"):
                path = src["path"]
                break
        if not path:
            continue
        consumed.add(path)
        info = snap(path)
        lsha = info["sha"] if info else None
        lsize = info["size"] if info else 0
        bsha = base.get("sha256") if base else None
        brev = base.get("rev") if base else None
        bdel = bool(base.get("deleted")) if base else False
        rp = re_ is not None
        rsha = re_.get("sha256") if rp else None
        rrev = re_.get("rev") if rp else None
        rdel = bool(re_.get("deleted")) if rp else False
        meta = le or re_ or base

        if base is None:
            if rp:
                if rdel:
                    reports[rid] = re_
                elif lsha is None:
                    reports[rid] = re_
                    ops.append(("materialize", rid, rrev, path))
                elif lsha == rsha:
                    reports[rid] = re_
                else:
                    cpath = conflict_path(path, rid, max(1, rrev or 1))
                    ops.append(("move", path, cpath))
                    nid = new_id()
                    reports[nid] = entry_from_meta(nid, cpath, meta, 1, lsha, lsize, now)
                    reports[rid] = re_
                    ops.append(("materialize", rid, rrev, path))
            elif lsha is not None:
                if le and le.get("sha256") == lsha:
                    reports[rid] = le
                else:
                    rev = (int(le.get("rev", 1)) + 1) if le else 1
                    reports[rid] = entry_from_meta(rid, path, meta, rev, lsha, lsize, now)
            continue

        remote_changed = rp and not (rrev == brev and rsha == bsha and rdel == bdel)
        local_deleted = lsha is None and not bdel
        local_changed = lsha is not None and lsha != bsha

        if remote_changed and local_changed:
            if rdel:
                reports[rid] = entry_from_meta(rid, path, meta, int(brev) + 1, lsha, lsize, now)
            else:
                cpath = conflict_path(path, rid, brev)
                ops.append(("move", path, cpath))
                nid = new_id()
                reports[nid] = entry_from_meta(nid, cpath, meta, 1, lsha, lsize, now)
                reports[rid] = re_
                ops.append(("materialize", rid, rrev, path))
        elif remote_changed and local_deleted:
            reports[rid] = re_
            if not rdel:
                ops.append(("materialize", rid, rrev, path))
        elif remote_changed:
            if rdel:
                ops.append(("delete", path, bsha))
                reports[rid] = re_
            else:
                reports[rid] = re_
                ops.append(("materialize", rid, rrev, path))
        elif local_changed:
            reports[rid] = entry_from_meta(rid, path, meta, int(brev) + 1, lsha, lsize, now)
        elif local_deleted:
            if bdel:
                reports[rid] = le or re_ or make_tombstone(rid, path, rev=brev, prev=meta, updated_at=now)
            else:
                rev = max(int(brev), int(rrev) if rrev else int(brev)) + 1
                reports[rid] = make_tombstone(rid, path, rev=rev, prev=meta, updated_at=now)
        else:
            reports[rid] = le or re_ or entry_from_meta(rid, path, meta, int(brev), bsha, 0, now)

    for path, info in sorted(snapshot.items()):
        if path in consumed:
            continue
        nid = new_id()
        title = (titles or {}).get(path)
        reports[nid] = entry_from_meta(
            nid, path, {"title": title} if title else None, 1, info["sha"], info["size"], now
        )

    for entry in reports.values():
        entry["kind"] = kind_for(entry["path"])
    return reports, ops


# --------------------------------------------------------------------------
# Applying a plan
# --------------------------------------------------------------------------
def _decrypt_remote_blob(settings: Settings, mk: bytes, rid: str, rev: int, path: str) -> bytes:
    blob = cat_file(settings, settings.remote_ref, f"{BLOBS_DIR}/{rid}-{rev}.enc")
    if blob is None:
        raise Abort(f"remote blob missing: blobs/{rid}-{rev}.enc")
    pt = decrypt_blob(mk, rid, rev, blob)
    return pt


def apply_plan(settings: Settings, mk: bytes, reports: dict, ops: list) -> None:
    """Validate all remote materializations first, then mutate the master dir."""
    decoded: dict = {}
    for op in ops:
        if op[0] == "materialize":
            _, rid, rev, path = op
            pt = _decrypt_remote_blob(settings, mk, rid, rev, path)
            entry = reports[rid]
            if sha256_hex(pt) != entry.get("sha256"):
                raise Abort(f"remote blob sha mismatch for {rid} rev {rev}")
            decoded[path] = pt

    for op in ops:
        if op[0] == "move":
            src = safe_join(settings.master_dir, op[1])
            dst = safe_join(settings.master_dir, op[2])
            if os.path.exists(src):
                os.makedirs(os.path.dirname(dst) or settings.master_dir, exist_ok=True)
                os.replace(src, dst)
    for path, pt in decoded.items():
        full = safe_join(settings.master_dir, path)
        os.makedirs(os.path.dirname(full) or settings.master_dir, exist_ok=True)
        with open(full, "wb") as fh:
            fh.write(pt)
    for op in ops:
        if op[0] == "delete":
            _, path, expected = op
            full = safe_join(settings.master_dir, path)
            if not os.path.exists(full):
                continue
            if expected:
                data = read_stable(full)
                if sha256_hex(data) != expected:
                    raise Abort(f"refusing to delete locally-modified {path}")
            os.remove(full)


def ensure_blobs(settings: Settings, mk: bytes, reports: dict) -> None:
    for rid, entry in reports.items():
        if entry.get("deleted"):
            continue
        blob_rel = f"{BLOBS_DIR}/{rid}-{entry['rev']}.enc"
        blob_full = os.path.join(settings.repo_dir, blob_rel)
        if os.path.exists(blob_full):
            continue
        path_full = safe_join(settings.master_dir, entry["path"])
        if not os.path.exists(path_full):
            raise Abort(f"cannot rebuild blob for {rid}: {entry['path']} missing")
        data = read_stable(path_full)
        if sha256_hex(data) != entry.get("sha256"):
            raise Abort(f"plaintext changed during sync for {entry['path']}")
        os.makedirs(os.path.dirname(blob_full), exist_ok=True)
        with open(blob_full, "wb") as fh:
            fh.write(encrypt_blob(mk, rid, int(entry["rev"]), data))


def save_manifest(settings: Settings, mk: bytes, reports: dict, now: str) -> dict:
    manifest = {"v": 1, "updatedAt": now, "reports": [reports[k] for k in sorted(reports)]}
    data = encrypt_manifest(mk, manifest)
    path = os.path.join(settings.repo_dir, MANIFEST_NAME)
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "wb") as fh:
        fh.write(data)
    return manifest


# --------------------------------------------------------------------------
# High-level operations
# --------------------------------------------------------------------------
def _prepare_repo(settings: Settings) -> None:
    if not is_git_repo(settings.repo_dir):
        raise SyrError(f"not a git repository: {settings.repo_dir}")
    if not is_clean(settings.repo_dir):
        raise SyrError("working tree is dirty; commit or stash before syncing")


def sync(settings: Settings, mk: bytes, *, dry_run: bool = False, no_push: bool = False) -> dict:
    with sync_lock(settings):
        _prepare_repo(settings)
        fetch(settings)
        remote_map = index_reports(read_remote_manifest(settings, mk))
        local_map = index_reports(read_local_manifest(settings, mk))
        baseline = read_baseline(settings)["entries"]
        published: dict = {}
        for entry in local_map.values():
            published[entry["path"]] = entry.get("sha256")
        for entry in remote_map.values():
            published[entry["path"]] = entry.get("sha256")
        conversions = convert_office(settings, published, dry_run=dry_run)
        snapshot = scan_master(settings)
        titles = load_titles(settings)
        now = now_iso()
        reports, ops = plan_merge(
            baseline, local_map, remote_map, snapshot, now, lambda: secrets.token_hex(16), titles
        )

        if dry_run:
            return {
                "dry_run": True,
                "local": set(local_map),
                "remote": set(remote_map),
                "baseline": set(baseline),
                "planned": set(reports),
                "ops": ops,
                "conversions": conversions["converted"],
            }

        apply_plan(settings, mk, reports, ops)

        tip = rev_parse(settings, settings.remote_ref) if ref_exists(settings) else None
        head = rev_parse(settings, "HEAD")
        if tip and tip != head:
            reset_hard(settings, tip)

        ensure_blobs(settings, mk, reports)
        # Idempotency: only rewrite manifest.enc when the logical content changed;
        # a fresh IV would otherwise dirty the tree (and commit) on every run (SPEC §6).
        try:
            prev = index_reports(read_local_manifest(settings, mk))
        except SyrError:
            prev = None
        if prev != reports:
            save_manifest(settings, mk, reports, now)
        changed = commit_all(settings, f"sync: {len(reports)} reports @ {now}")
        pushed = False
        if changed and not no_push and remote_configured(settings):
            git_retry(settings.repo_dir, ["push", settings.remote, settings.branch])
            pushed = True
        # Baseline records the committed local reality so re-syncs are idempotent.
        write_baseline(settings, [reports[k] for k in sorted(reports)], now)
        return {
            "changed": changed,
            "pushed": pushed,
            "reports": len(reports),
            "conversions": conversions["converted"],
        }


def pull(settings: Settings, mk: bytes) -> dict:
    with sync_lock(settings):
        _prepare_repo(settings)
        fetch(settings)
        if not ref_exists(settings):
            raise SyrError(f"no remote ref {settings.remote_ref}")
        remote_map = index_reports(read_remote_manifest(settings, mk))
        tip = rev_parse(settings, settings.remote_ref)
        head = rev_parse(settings, "HEAD")
        if tip and tip != head:
            reset_hard(settings, tip)
        decoded = {}
        for rid, entry in remote_map.items():
            if entry.get("deleted"):
                continue
            pt = _decrypt_remote_blob(settings, mk, rid, int(entry["rev"]), entry["path"])
            if sha256_hex(pt) != entry.get("sha256"):
                raise Abort(f"remote blob sha mismatch for {rid}")
            decoded[entry["path"]] = pt
        for rid, entry in remote_map.items():
            if entry.get("deleted"):
                full = safe_join(settings.master_dir, entry["path"])
                if os.path.exists(full):
                    os.remove(full)
        for path, pt in decoded.items():
            full = safe_join(settings.master_dir, path)
            os.makedirs(os.path.dirname(full) or settings.master_dir, exist_ok=True)
            with open(full, "wb") as fh:
                fh.write(pt)
        write_baseline(settings, list(remote_map.values()), now_iso())
        return {"reports": len(remote_map)}


def status(settings: Settings, mk: bytes) -> str:
    fetch(settings)
    local_map = index_reports(read_local_manifest(settings, mk))
    remote_map = index_reports(read_remote_manifest(settings, mk))
    baseline = read_baseline(settings)["entries"]
    snapshot = scan_master(settings)
    lines = [f"repo_dir   {settings.repo_dir}", f"master_dir {settings.master_dir}",
             f"remote     {settings.remote_ref}", "", f"{'id':<10} {'path':<32} {'base':>5} {'local':>6} {'remote':>6}  state"]
    ids = sorted(set(baseline) | set(local_map) | set(remote_map))
    for rid in ids:
        path = (baseline.get(rid) or local_map.get(rid) or remote_map.get(rid) or {}).get("path", "?")
        b = baseline.get(rid)
        l = snapshot.get(path)
        r = remote_map.get(rid)
        state = []
        if rid not in baseline:
            state.append("new")
        if l is None and b and not b.get("deleted"):
            state.append("locally-deleted")
        elif l and b and l["sha"] != b.get("sha256"):
            state.append("locally-changed")
        if r and b and r.get("rev") != b.get("rev"):
            state.append("remote-changed")
        lines.append(
            f"{rid[:10]:<10} {path:<32} {str(b.get('rev') if b else '-'):>5} "
            f"{'edit' if l else 'gone':>6} {str(r.get('rev') if r else '-'):>6}  {' '.join(state) or 'in-sync'}"
        )
    return "\n".join(lines)