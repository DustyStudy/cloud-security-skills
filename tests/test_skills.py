"""Structure checks for the marketplace, plugins and skills."""

import json
import re
import unicodedata
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
MARKETPLACE = json.loads((ROOT / ".claude-plugin" / "marketplace.json").read_text(encoding="utf-8"))
SKILLS = sorted(ROOT.glob("plugins/*/skills/*/SKILL.md"))
TECHNIQUES = ROOT / "plugins/aws-attack-paths/skills/aws-attack-paths/references/techniques.md"
FIELDS = ["Path", "Detect", "Prevent", "Respond", "NIST", "Example", "Gaps"]


def frontmatter(path: Path) -> dict:
    m = re.match(r"---\n(.*?)\n---\n", path.read_text(encoding="utf-8"), re.S)
    assert m, f"{path} has no frontmatter"
    return dict(line.split(": ", 1) for line in m.group(1).splitlines())


def test_local_plugins_match_their_manifest():
    local = [p for p in MARKETPLACE["plugins"] if isinstance(p["source"], str)]
    assert local
    for entry in local:
        manifest = ROOT / entry["source"] / ".claude-plugin" / "plugin.json"
        plugin = json.loads(manifest.read_text(encoding="utf-8"))
        assert plugin["name"] == entry["name"]
        assert plugin["version"] == entry["version"]
        assert list((ROOT / entry["source"]).glob("skills/*/SKILL.md")), entry["name"]


def test_remote_plugins_point_at_github_repos():
    remote = [p for p in MARKETPLACE["plugins"] if isinstance(p["source"], dict)]
    for entry in remote:
        assert entry["source"]["source"] == "url"
        assert re.fullmatch(r"https://github\.com/DustyStudy/[\w.-]+\.git", entry["source"]["url"])
        # Pin to a commit so installs don't follow the remote's default branch; the docs
        # only promise the sha is checked out when ref is set too.
        assert entry["source"].get("ref"), entry["name"]
        assert re.fullmatch(r"[0-9a-f]{40}", entry["source"].get("sha", "")), entry["name"]
        # Its repo has no plugin.json, so the marketplace entry must define the plugin.
        assert entry["strict"] is False


def test_plugin_names_are_unique():
    names = [p["name"] for p in MARKETPLACE["plugins"]]
    assert len(names) == len(set(names))


@pytest.mark.parametrize("skill", SKILLS, ids=lambda p: p.parent.name)
def test_skill_frontmatter(skill):
    fm = frontmatter(skill)
    assert fm["name"] == skill.parent.name
    assert 0 < len(fm["description"]) <= 1024


@pytest.mark.parametrize("doc", sorted(ROOT.glob("plugins/**/*.md")), ids=lambda p: p.name)
def test_relative_links_resolve(doc):
    for target in re.findall(r"\]\(((?!https?://|#)[^)]+)\)", doc.read_text(encoding="utf-8")):
        assert (doc.parent / target.split("#")[0]).exists(), f"{doc.name}: broken link {target}"


def test_every_technique_has_every_field():
    sections = re.split(r"(?m)^## (?=\d+\. )", TECHNIQUES.read_text(encoding="utf-8"))[1:]
    assert len(sections) >= 10
    for sec in sections:
        title = sec.splitlines()[0]
        assert re.search(r"attack\.mitre\.org/techniques/T\d{4}(/\d{3})?/", sec), title
        for field in FIELDS:
            assert f"- **{field}:**" in sec, f"{title}: missing {field}"
        nist = re.search(r"- \*\*NIST:\*\* (.+)", sec)
        assert nist, title
        for control in nist.group(1).rstrip(".").split(", "):
            assert re.fullmatch(r"[A-Z]{2}-\d+(\(\d+\))?", control), f"{title}: bad NIST ID {control}"


# Skill files land in an agent's context, so block text a reviewer can't see in a diff.
@pytest.mark.parametrize(
    "path",
    sorted(p for p in ROOT.glob("plugins/**/*") if p.is_file()) + [ROOT / ".claude-plugin" / "marketplace.json"],
    ids=lambda p: p.relative_to(ROOT).as_posix(),
)
def test_no_hidden_content(path):
    text = path.read_text(encoding="utf-8")
    texts = [text]
    if path.suffix == ".json":
        # \uXXXX escapes only become characters once decoded, so check the decoded strings too.
        texts.append("\n".join(json_strings(json.loads(text))))
    for t in texts:
        assert "<!--" not in t, f"{path.name}: HTML comment"
        for i, ch in enumerate(t):
            assert not hidden_char(ch), f"{path.name}:{t.count(chr(10), 0, i) + 1}: hidden char U+{ord(ch):04X}"


def json_strings(node):
    if isinstance(node, dict):
        for k, v in node.items():
            yield k
            yield from json_strings(v)
    elif isinstance(node, list):
        for v in node:
            yield from json_strings(v)
    elif isinstance(node, str):
        yield node


# Unicode Default_Ignorable_Code_Point ranges not already covered by the categories below,
# plus fillers that render blank (U+2800 braille blank isn't default-ignorable).
IGNORABLE = [(0x034F, 0x034F), (0x115F, 0x1160), (0x17B4, 0x17B5), (0x180B, 0x180F),
             (0x2800, 0x2800), (0x3164, 0x3164), (0xFE00, 0xFE0F), (0xFFA0, 0xFFA0),
             (0xE0000, 0xE0FFF)]


def hidden_char(ch: str) -> bool:
    # Cf: zero-width and bidi controls; Cc: control chars; Co/Cn: private use and unassigned;
    # Zl/Zp: line/paragraph separators.
    if ch in "\t\n\r":
        return False
    return (unicodedata.category(ch) in {"Cf", "Cc", "Co", "Cn", "Zl", "Zp"}
            or any(lo <= ord(ch) <= hi for lo, hi in IGNORABLE))


def test_hidden_char_catches_known_tricks():
    for cp in [0x200B, 0x202E, 0x2066, 0xE0041, 0x034F, 0xFE0F, 0xE0100, 0x2800, 0x3164,
               0x1B, 0x08, 0x2028, 0xFEFF, 0x00AD]:
        assert hidden_char(chr(cp)), f"U+{cp:04X}"
    for ch in "aé→—–“”’ \t\n":
        assert not hidden_char(ch), ch
