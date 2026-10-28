"""Structure checks for the marketplace, plugins and skills."""

import json
import re
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
