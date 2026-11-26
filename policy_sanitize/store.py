"""Local reversible-map store and map-back (stdlib only)."""
from __future__ import annotations

import json
import os
import re
import secrets
import time
from pathlib import Path

_RUN_ID_RE = re.compile(r"^[0-9a-f]{16}$")
_SUFFIX = ".map.json"
# Synced-storage path components (substring, case-insensitive).
_DENY_PART = re.compile(
    r"onedrive|cloudstorage|mobile documents|dropbox|google ?drive|icloud",
    re.IGNORECASE,
)
_SECTIONS = ("ips", "fqdns", "terms", "labels")


class MapError(Exception):
    pass


def default_map_dir() -> Path:
    env = os.environ.get("FW_ANALYST_SANITIZE_DIR")
    if env:
        return Path(env)
    return Path.home() / ".local" / "share" / "4tanalyst" / "sanitize"


def new_run_id() -> str:
    return secrets.token_hex(8)


def _repo_root() -> Path | None:
    for p in Path(__file__).resolve().parents:
        if (p / ".git").exists():
            return p
    return None


def _check_run_id(run_id: str) -> None:
    if not isinstance(run_id, str) or not _RUN_ID_RE.match(run_id):
        raise MapError("invalid run id")


def check_dir_allowed(d: Path) -> None:
    resolved = d.expanduser().resolve()
    root = _repo_root()
    if root is not None and (resolved == root or root in resolved.parents):
        raise MapError("map directory must not be inside the repository")
    if any(_DENY_PART.search(part) for part in resolved.parts):
        raise MapError("map directory must not be in a synced location")


_check_dir_allowed = check_dir_allowed


def _make_private_dirs(d: Path) -> None:
    """Create d (and missing parents) mode 0700; never chmod pre-existing dirs."""
    missing = []
    p = d
    while not p.exists():
        missing.append(p)
        p = p.parent
    for p in reversed(missing):
        try:
            os.makedirs(p, mode=0o700, exist_ok=False)
        except FileExistsError:
            continue  # created concurrently: not ours, leave its mode alone
        os.chmod(p, 0o700)  # makedirs mode is subject to umask


def delete_map(run_id: str, map_dir: Path | None = None) -> None:
    """Remove the stored map for run_id (used to roll back a failed run)."""
    _check_run_id(run_id)
    d = Path(map_dir) if map_dir is not None else default_map_dir()
    try:
        (d.expanduser() / f"{run_id}{_SUFFIX}").unlink()
    except FileNotFoundError:
        pass


def write_map(run_id: str, mapping: dict, map_dir: Path | None = None) -> Path:
    _check_run_id(run_id)
    d = Path(map_dir) if map_dir is not None else default_map_dir()
    check_dir_allowed(d)
    d = d.expanduser().resolve()
    _make_private_dirs(d)
    doc = {
        "version": 1,
        "created": time.time(),
        "ips": dict(mapping.get("ips", {})),
        "fqdns": dict(mapping.get("fqdns", {})),
        "terms": dict(mapping.get("terms", {})),
        "labels": dict(mapping.get("labels", {})),
    }
    path = d / f"{run_id}{_SUFFIX}"
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as fh:
        json.dump(doc, fh)
    os.chmod(path, 0o600)
    return path


def _age_ok(path: Path, doc: dict | None, days: float) -> bool:
    now = time.time()
    try:
        ages = [now - path.stat().st_mtime]
    except OSError:
        return False
    created = doc.get("created") if isinstance(doc, dict) else None
    if isinstance(created, (int, float)) and not isinstance(created, bool):
        ages.append(now - created)
    return max(ages) <= days * 86400


def read_map(run_id: str, map_dir: Path | None = None) -> dict:
    _check_run_id(run_id)
    d = Path(map_dir) if map_dir is not None else default_map_dir()
    path = d.expanduser() / f"{run_id}{_SUFFIX}"
    if not path.is_file():
        raise MapError(f"map for run {run_id} not found")
    try:
        doc = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        raise MapError(f"map for run {run_id} is unreadable") from None
    if not isinstance(doc, dict) or "version" not in doc:
        raise MapError(f"map for run {run_id} is malformed")
    for sec in _SECTIONS:
        doc.setdefault(sec, {})
        if not isinstance(doc[sec], dict):
            raise MapError(f"map for run {run_id} is malformed")
    if not _age_ok(path, doc, 30):
        raise MapError(f"map for run {run_id} has expired")
    return doc


def map_back(text: str, mapping: dict) -> str:
    rev: dict[str, str] = {}
    ip_keys = set(mapping.get("ips", {}).values())
    for orig, fake in mapping.get("ips", {}).items():
        rev[fake] = orig
    fq: dict[str, str] = {}
    for orig in sorted(mapping.get("fqdns", {})):
        fq.setdefault(mapping["fqdns"][orig], orig)
    labels = {ph: orig for ph, orig in mapping.get("labels", {}).items()}
    taken = set(rev) | set(fq) | set(labels)
    rev.update(fq)
    rev.update(labels)
    by_ph: dict[str, set[str]] = {}
    for orig, ph in mapping.get("terms", {}).items():
        by_ph.setdefault(ph, set()).add(orig)
    for ph, origs in by_ph.items():
        if len(origs) == 1 and ph not in taken:
            rev[ph] = next(iter(origs))
    rev.pop("", None)
    if not rev:
        return text
    base_pre, base_post = r"(?<![A-Za-z0-9])", r"(?![A-Za-z0-9])"
    ip_pre, ip_post = base_pre + r"(?<![0-9]\.)", base_post + r"(?!\.[0-9])"
    v6_pre, v6_post = r"(?<![A-Za-z0-9:])", r"(?![A-Za-z0-9:])"
    parts = []
    for k in sorted(rev, key=lambda k: (-len(k), k)):
        if k in ip_keys and ":" in k and k not in fq and k not in labels:
            parts.append(v6_pre + re.escape(k) + v6_post)
        elif k in ip_keys and k not in fq and k not in labels:
            parts.append(ip_pre + re.escape(k) + ip_post)
        else:
            parts.append(base_pre + re.escape(k) + base_post)
    pat = re.compile("|".join(parts))
    return pat.sub(lambda m: rev[m.group(0)], text)


def purge_expired(map_dir: Path | None = None, days: int = 30) -> int:
    d = Path(map_dir) if map_dir is not None else default_map_dir()
    if not d.is_dir():
        return 0
    n = 0
    for p in d.glob(f"*{_SUFFIX}"):
        if not p.is_file():
            continue
        try:
            doc = json.loads(p.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            doc = None
        if not _age_ok(p, doc, days):
            try:
                p.unlink()
                n += 1
            except OSError:
                pass
    return n
