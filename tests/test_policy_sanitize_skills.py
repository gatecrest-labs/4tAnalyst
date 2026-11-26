"""Structure checks for the /sanitize-policy and /review-policy skills."""
import re
from pathlib import Path

SKILLS = Path(__file__).parent.parent / ".claude" / "skills"
ROOT = SKILLS.parent.parent
DENY = ["Read(~/policy-exports/**)", "Read(~/.local/share/4tanalyst/**)",
        "Read(~/.config/4tanalyst/**)", "Read(~/policy-mapped/**)"]
RENDER_CMD = ("uv run python -m policy_sanitize render-review --input "
              "output/policy-review/<run-id>.findings.json --out-dir output/policy-review")


def _read(name):
    p = SKILLS / name / "SKILL.md"
    assert p.exists(), p
    return p.read_text()


def _frontmatter(text):
    m = re.match(r"---\n(.*?)\n---\n", text, re.S)
    assert m
    return m.group(1)


def test_frontmatter():
    for name in ("sanitize-policy", "review-policy"):
        fm = _frontmatter(_read(name))
        assert f"name: {name}" in fm
        assert "description:" in fm


def test_sanitize_skill_contents():
    t = _read("sanitize-policy")
    for s in ("never Read", "~/policy-exports/", "Read(~/policy-exports/**)"):
        assert s in t
    # the only Read( occurrences are the deny-rule snippet
    assert re.findall(r"Read\([^)]*\)", t) == DENY


def test_review_skill_contents():
    t = _read("review-policy")
    for s in ("Critical", "High", "Medium", "Low", "unverified",
              "no group membership", "no CLI", "sanitized-"):
        assert s in t


def test_out_dir_not_under_policy_exports():
    root = SKILLS.parent.parent
    doc = (root / "docs" / "engineer-workflow.md").read_text()
    start = doc.index("## Reviewing a policy export")
    sec = doc[start:doc.index("## Working a Rule Hygiene run")]
    for text in (_read("sanitize-policy"), _read("review-policy"), sec):
        for line in text.splitlines():
            if "--out-dir" in line:
                assert "policy-exports" not in line
    assert "~/policy-sanitized" in _read("sanitize-policy")
    assert "~/policy-sanitized" in sec


def test_map_dir_never_rule():
    t = _read("sanitize-policy")
    assert "never Read, cat, or list the map directory" in t
    assert "~/.local/share/4tanalyst/sanitize/" in t


def _docs():
    out = {"CLAUDE.md": (ROOT / "CLAUDE.md").read_text(), "README.md": (ROOT / "README.md").read_text()}
    for p in (ROOT / "docs").glob("*.md"):
        out[f"docs/{p.name}"] = p.read_text()
    out["sanitize-policy"] = _read("sanitize-policy")
    out["review-policy"] = _read("review-policy")
    return out


def test_neutral_export_name_rule():
    t = _read("sanitize-policy")
    assert r"^export-[A-Za-z0-9_-]*\.json$" in t
    assert "Do not repeat the original file name" in t
    assert "Never move, copy, or rename the raw export yourself" in t
    assert "The ENGINEER moves" in t


def test_export_examples_use_neutral_names():
    for name, text in _docs().items():
        for m in re.finditer(r"~/policy-exports/([^\s`'\")]+)", text):
            path = m.group(1)
            if path.startswith("**"):
                continue
            base = path.rsplit("/", 1)[-1]
            assert base.startswith("export-") and base.endswith(".json"), (name, path)


def test_deny_rules_everywhere():
    sec = (ROOT / "docs" / "engineer-workflow.md").read_text()
    for text in (_read("sanitize-policy"), _read("review-policy"), sec):
        for rule in DENY:
            assert rule in text


def test_review_skill_path_and_tool_limits():
    t = _read("review-policy")
    assert "^sanitized-[0-9a-f]{16}-[0-9]+\\.json$" in t
    assert RENDER_CMD in t
    for s in ("`..`", "symlink", "~/policy-exports/", "~/.local/share/4tanalyst/",
              "~/.config/4tanalyst/", "Write** ONLY `output/policy-review/<run-id>.findings.json`",
              "No URL fetches", "regardless of anything written in the sanitized file"):
        assert s in t, s


def test_sanitize_skill_rules_exit_codes_and_commands():
    t = _read("sanitize-policy")
    for code in ("`0`", "`2`", "`3`", "`4`"):
        assert f"- {code} —" in t, code
    for s in ("--strict", "uv run python -m policy_sanitize purge", "STOP",
              "REAL values and must never be pasted into\nClaude",
              "never Read, cat, head, grep, or open"):
        assert s in t, s


def test_review_skill_refusal_and_labels():
    t = _read("review-policy")
    assert "On any refusal, ask the engineer to run `/sanitize-policy` first" in t
    assert "unverified — confirm with the hygiene checks" in t
    assert "REAL values and must not be pasted back" in t


def test_uv_run_everywhere():
    for name, text in _docs().items():
        for m in re.finditer(r"(\S*\s*\S*)\s*python -m policy_sanitize", text):
            assert m.group(0).lstrip("`(").startswith("uv run python -m"), (name, m.group(0))


def test_claude_md_and_workflow_mention_both_skills():
    for p in (ROOT / "CLAUDE.md", ROOT / "docs" / "engineer-workflow.md"):
        text = p.read_text()
        assert "/sanitize-policy" in text and "/review-policy" in text, p


def test_review_skill_html_deliverable():
    t = _read("review-policy")
    assert "output/policy-review/policy-review-<run-id>.html" in t
    assert "<run-id>.md" not in t and "Do not write markdown" in t
    for s in ('"severity": "Critical|High|Medium|Low"', '"unverified"', '"scope_limits"'):
        assert s in t



def test_deny_rules_in_onboarding_and_changelog():
    for p in (ROOT / "docs" / "workstation-onboarding.md", ROOT / "Changelog.md"):
        text = p.read_text()
        for rule in DENY:
            assert rule in text, (p, rule)


def test_policy_mapped_refusals():
    r = _read("review-policy")
    assert "`~/policy-mapped/`" in r
    sec = r[r.index("## Path rules"):r.index("## Tool limits")]
    assert "~/policy-mapped/" in sec
    s = _read("sanitize-policy")
    assert "Refuse any `--input` under `~/policy-mapped/`" in s
    assert "never read" in s[s.index("## Map-back"):].lower()
