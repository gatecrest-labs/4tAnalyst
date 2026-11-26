"""CLI: sanitize / map-back / purge / render-review. Error output is fixed text plus class names."""
from __future__ import annotations

import argparse
import json
import os
import secrets
import sys
from pathlib import Path

from .engine import SanitizeError, sanitize_documents
from .ipmap import IpMapper
from .review_report import ReportError, render_review_html
from .scrub import Scrubber
from .store import (
    MapError,
    check_dir_allowed,
    delete_map,
    map_back,
    new_run_id,
    purge_expired,
    read_map,
    write_map,
)
from .terms import TermsError, load_terms
from .verify import verify

DEFAULT_TERMS = "~/.config/4tanalyst/sanitize-terms.txt"


def _err(msg: str) -> None:
    print(msg, file=sys.stderr)


class _Parser(argparse.ArgumentParser):
    def error(self, message):  # never echo message or argv values
        sub = self.prog.split()[-1] if self.prog else ""
        extra = f" ({sub})" if sub in ("sanitize", "map-back", "purge", "render-review") else ""
        print(f"error: invalid arguments{extra}", file=sys.stderr)
        raise SystemExit(2)


def _atomic_write(path: Path, data: str | bytes) -> None:
    if isinstance(data, str):
        data = data.encode("utf-8")
    tmp = path.with_name(f".{path.name}.{secrets.token_hex(4)}.tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(fd, "wb") as fh:
            fh.write(data)
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(tmp, path)
    except BaseException:
        try:
            tmp.unlink()
        except OSError:
            pass
        raise


def _build_parser() -> argparse.ArgumentParser:
    p = _Parser(prog="policy_sanitize")
    sub = p.add_subparsers(dest="cmd", required=True)
    s = sub.add_parser("sanitize")
    s.add_argument("--input", action="append", required=True, dest="inputs")
    s.add_argument("--out-dir", required=True)
    g = s.add_mutually_exclusive_group()
    g.add_argument("--terms")
    g.add_argument("--no-terms", action="store_true")
    s.add_argument("--strict", action="store_true")
    m = sub.add_parser("map-back")
    m.add_argument("--run-id", required=True)
    m.add_argument("--input", required=True)
    m.add_argument("--output", required=True)
    sub.add_parser("purge")
    r = sub.add_parser("render-review")
    r.add_argument("--input", required=True)
    r.add_argument("--out-dir", required=True)
    return p


def _sanitize(a: argparse.Namespace) -> int:
    terms: list = []
    if a.no_terms:
        _err("WARNING: running without a terms list; company/site names are NOT scrubbed")
    else:
        path = Path(a.terms if a.terms else DEFAULT_TERMS).expanduser()
        try:
            terms = load_terms(path)
        except TermsError:
            _err("error: terms file missing, unreadable or empty (TermsError); "
                 "use --terms PATH or --no-terms")
            return 2
    docs: dict[str, object] = {}
    for n, f in enumerate(a.inputs, 1):
        try:
            with open(f, encoding="utf-8") as fh:
                docs[f"doc{n}"] = json.load(fh)
        except Exception as e:  # never echo str(e): may contain file contents
            _err(f"error: cannot read input #{n} ({type(e).__name__})")
            return 2
    scrubber = Scrubber(IpMapper(secrets.token_bytes(32)), terms)
    try:
        result = sanitize_documents(docs, scrubber)
    except SanitizeError as e:
        _err(f"error: collision (SanitizeError) code={e.code} paths={', '.join(e.paths)}")
        return 2
    mapping = {"ips": scrubber.ips, "fqdns": scrubber.fqdns,
               "terms": scrubber.term_map, "labels": result.labels}
    originals = set(scrubber.ips) | set(scrubber.fqdns) | set(scrubber.term_map) \
        | set(result.labels.values()) | {t for t, _ in terms}
    violations = []
    for label, doc in result.documents.items():
        for v in verify(doc, originals):
            violations.append(f"{label}{v.path[1:]}:{v.kind}")
    if violations:
        _err(f"error: verifier found {len(violations)} violation(s); nothing written")
        for line in violations:
            _err(line)
        return 3
    if a.strict and result.unmatched_identifiers > 0:
        _err(f"error: --strict: {result.unmatched_identifiers} unmatched identifier(s); "
             "nothing written")
        return 4
    # Serialize and encode every document before anything touches disk.
    try:
        payloads = [json.dumps(result.documents[label], indent=2,
                               ensure_ascii=False).encode("utf-8")
                    for label in result.documents]
    except Exception as e:  # e.g. lone surrogate: never echo str(e)
        _err(f"error: cannot serialize output ({type(e).__name__}); nothing written")
        return 2
    run_id = new_run_id()
    try:
        write_map(run_id, mapping)
    except (MapError, OSError) as e:
        _err(f"error: cannot store map ({type(e).__name__}); nothing written")
        return 2
    out_dir = Path(a.out_dir)
    outputs = []
    try:
        out_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
        for n, data in enumerate(payloads, 1):
            p = out_dir / f"sanitized-{run_id}-{n}.json"
            _atomic_write(p, data)
            outputs.append(p)
    except Exception as e:
        for p in outputs:
            try:
                p.unlink()
            except OSError:
                pass
        try:
            delete_map(run_id)
        except Exception:
            pass
        _err(f"error: cannot write output ({type(e).__name__}); nothing written")
        return 2
    rules = sum(len(d["rules"]) for d in docs.values()
                if isinstance(d, dict) and isinstance(d.get("rules"), list))
    print(f"run-id: {run_id}")
    for p in outputs:
        print(f"output: {p}")
    print(f"rules: {rules}")
    print(f"replaced: ips={scrubber.ip_count} fqdns={scrubber.fqdn_count} "
          f"terms={scrubber.term_count}")
    print(f"unmatched-identifiers: {result.unmatched_identifiers}")
    print("verifier: clean")
    print("map: stored (not shown)")
    return 0


def _map_back(a: argparse.Namespace) -> int:
    try:
        mapping = read_map(a.run_id)
    except MapError:
        _err("error: map not found, expired or unreadable (MapError)")
        return 2
    out = Path(a.output)
    try:
        check_dir_allowed(out.parent)
    except MapError:
        _err("error: output location not allowed (MapError)")
        return 2
    try:
        text = Path(a.input).read_text(encoding="utf-8")
        out.parent.mkdir(parents=True, exist_ok=True)
        _atomic_write(out, map_back(text, mapping))
    except Exception as e:
        _err(f"error: cannot read/write file ({type(e).__name__})")
        return 2
    print(f"written: {a.output}")
    return 0


def _render_review(a: argparse.Namespace) -> int:
    try:
        with open(a.input, encoding="utf-8") as fh:
            findings = json.load(fh)
    except Exception as e:  # never echo str(e): may contain file contents
        _err(f"error: cannot read findings ({type(e).__name__})")
        return 2
    try:
        page = render_review_html(findings)
    except ReportError as e:
        _err(f"error: findings rejected (ReportError) code={e.code}")
        return 2
    out_dir = Path(a.out_dir)
    out = out_dir / f"policy-review-{findings['run_id']}.html"
    try:
        out_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
        _atomic_write(out, page)
    except Exception as e:
        _err(f"error: cannot write report ({type(e).__name__})")
        return 2
    print(f"report: {out}")
    return 0


def main(argv: list[str] | None = None) -> int:
    try:
        return _main(argv)
    except SystemExit as e:  # argparse error (2) or --help (0)
        return e.code if isinstance(e.code, int) else 2
    except Exception as e:  # never print str(e)/traceback: may hold raw data
        _err(f"error: unexpected failure ({type(e).__name__})")
        return 2


def _main(argv: list[str] | None) -> int:
    a = _build_parser().parse_args(argv)
    if a.cmd == "sanitize":
        return _sanitize(a)
    if a.cmd == "map-back":
        return _map_back(a)
    if a.cmd == "render-review":
        return _render_review(a)
    print(f"purged: {purge_expired()}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
