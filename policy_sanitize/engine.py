"""Document walker: scrubs every string value and dict key, checks injectivity."""

from __future__ import annotations

from dataclasses import dataclass, field

from .scrub import SanitizeError, Scrubber

NAME_FIELDS = ("srcaddr", "dstaddr", "service", "srcintf", "dstintf", "fsso_groups")
INTF_FIELDS = ("srcintf", "dstintf")
EPOCH = "1970-01-01T00:00:00Z"


@dataclass
class SanitizeResult:
    documents: dict[str, object]
    name_map: dict[str, str] = field(default_factory=dict)
    unmatched_identifiers: int = 0
    labels: dict[str, str] = field(default_factory=dict)


def _keys(d: dict, sc: Scrubber, path: str, bad: list[str]) -> dict:
    """Map each key of d to its scrubbed form; record path if two keys collide."""
    km = {k: (sc.text(k) if isinstance(k, str) else k) for k in d}
    if len(set(km.values())) != len(km):
        bad.append(path)
    return km


def _walk(value, sc: Scrubber, path: str, bad: list[str]):
    if isinstance(value, str):
        return sc.text(value)
    if isinstance(value, dict):
        km = _keys(value, sc, path, bad)
        return {km[k]: _walk(v, sc, f"{path}.{km[k]}", bad) for k, v in value.items()}
    if isinstance(value, list):
        return [_walk(v, sc, f"{path}[{i}]", bad) for i, v in enumerate(value)]
    return value


def sanitize_documents(docs: dict[str, object], scrubber: Scrubber) -> SanitizeResult:
    labels: dict[str, str] = {}
    by_orig: dict[str, dict[str, str]] = {"PKG": {}, "ADOM": {}}  # orig -> label
    name_map: dict[str, str] = {}
    # sanitized -> {original: [paths]}
    seen: dict[str, dict[str, list[str]]] = {}
    out_docs: dict[str, object] = {}
    key_bad: list[str] = []

    def label_for(kind: str, orig: str) -> str:
        m = by_orig[kind]
        if orig not in m:
            m[orig] = f"{kind}-{len(m) + 1}"
            labels[m[orig]] = orig
        return m[orig]

    for dlabel, doc in docs.items():
        if not isinstance(doc, dict):
            out_docs[dlabel] = _walk(doc, scrubber, f"documents.{dlabel}", key_bad)
            continue
        out: dict = {}
        dpath = f"documents.{dlabel}"
        dkm = _keys(doc, scrubber, dpath, key_bad)
        for k, v in doc.items():
            nk = dkm[k]
            if k == "package" and isinstance(v, str):
                out[nk] = label_for("PKG", v)
            elif k == "adom" and isinstance(v, str):
                out[nk] = label_for("ADOM", v)
            elif k == "generated" and isinstance(v, str):
                out[nk] = EPOCH
            elif k == "rules" and isinstance(v, list):
                rules = []
                for i, rule in enumerate(v):
                    if not isinstance(rule, dict):
                        rules.append(_walk(rule, scrubber, f"{dpath}.rules[{i}]", key_bad))
                        continue
                    nr: dict = {}
                    rpath = f"{dpath}.rules[{i}]"
                    rkm = _keys(rule, scrubber, rpath, key_bad)
                    for rk, rv in rule.items():
                        nrk = rkm[rk]
                        if rk == "comment":
                            nr[nrk] = ""
                        elif rk in NAME_FIELDS and isinstance(rv, list):
                            items = []
                            for j, s in enumerate(rv):
                                if rk in INTF_FIELDS and isinstance(s, str):
                                    # interface names: scrubbed, not counted
                                    ns = scrubber.text(s, count_unmatched=False)
                                else:
                                    ns = _walk(s, scrubber, f"{rpath}.{rk}[{j}]", key_bad)
                                items.append(ns)
                                if isinstance(s, str):
                                    name_map[s] = ns
                                    path = f"documents.{dlabel}.rules[{i}].{rk}[{j}]"
                                    seen.setdefault(ns, {}).setdefault(s, []).append(path)
                            nr[nrk] = items
                        else:
                            nr[nrk] = _walk(rv, scrubber, f"{rpath}.{nrk}", key_bad)
                    rules.append(nr)
                out[nk] = rules
            else:
                out[nk] = _walk(v, scrubber, f"{dpath}.{nk}", key_bad)
        out_docs[dlabel] = out

    bad = key_bad + [p for origs in seen.values() if len(origs) > 1
           for ps in origs.values() for p in ps]
    if bad:
        raise SanitizeError("collision", bad)
    return SanitizeResult(
        documents=out_docs,
        name_map=name_map,
        unmatched_identifiers=scrubber.unmatched_identifier_count(),
        labels=labels,
    )
