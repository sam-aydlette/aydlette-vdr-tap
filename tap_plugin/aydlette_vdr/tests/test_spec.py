"""The spec and the tests agree: the traceability rules TAP applies to its own tree, applied to this repo.

TAP's accounting scans only core's tree, so an extracted plugin checks itself (CONTRIBUTING.md):

* every `@pytest.mark.spec` names an acceptance criterion the spec defines;
* an `Implemented` criterion has a test citing it, and a criterion without one is not `Implemented`;
* a requirement is `Implemented` only when all its criteria are.
"""

from __future__ import annotations

import ast
import re
from pathlib import Path

TESTS = Path(__file__).resolve().parent
SPECS = TESTS.parents[2] / "specs"

RID = re.compile(r"^RID: `(req-[a-z0-9-]+)`\s*\n\s*\nStatus: `([A-Za-z ]+)`", re.MULTILINE)
ACID = re.compile(r"^\| (req-[a-z0-9-]+-\d+) \| [^|]*(?:\\\|[^|]*)* \| ([A-Za-z ]+) \|", re.MULTILINE)


def spec() -> tuple[dict[str, str], dict[str, str]]:
    text = "\n".join(p.read_text() for p in sorted(SPECS.glob("spec-*.md")))
    return dict(RID.findall(text)), dict(ACID.findall(text))


def cited() -> set[str]:
    out: set[str] = set()
    for p in TESTS.glob("test_*.py"):
        for node in ast.walk(ast.parse(p.read_text())):
            if (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr == "spec"
                    and isinstance(node.func.value, ast.Attribute) and node.func.value.attr == "mark"):  # fmt: skip
                out |= {a.value for a in node.args if isinstance(a, ast.Constant) and isinstance(a.value, str)}
    return out


def test_the_spec_parses():
    rids, acids = spec()
    assert rids and acids
    assert all(any(a.startswith(r + "-") for r in rids) for a in acids)


def test_every_citation_names_a_defined_criterion():
    _, acids = spec()
    assert sorted(cited() - set(acids)) == []


def test_implemented_criteria_are_exactly_the_cited_ones():
    _, acids = spec()
    marked = cited()
    assert sorted(a for a, s in acids.items() if s == "Implemented" and a not in marked) == []
    assert sorted(a for a, s in acids.items() if s != "Implemented" and a in marked) == []


def test_a_requirement_is_implemented_only_when_all_its_criteria_are():
    rids, acids = spec()
    for rid, status in rids.items():
        mine = [s for a, s in acids.items() if a.rsplit("-", 1)[0] == rid]
        assert (status == "Implemented") == (bool(mine) and all(s == "Implemented" for s in mine)), rid


def test_the_paper_coverage_table_matches_the_criteria():
    """The Paper Coverage section (core spec only) lists each Appendix B test's criteria with their statuses, and counts
    each test once at its best status. Both must match the requirement tables."""
    text = "\n".join(p.read_text() for p in sorted(SPECS.glob("spec-*.md")))
    if "## Paper Coverage" not in text:
        return
    _, acids = spec()
    order = ["Implemented", "In Development", "Proposed", "Backlog"]
    best: dict[str, int] = dict.fromkeys(order, 0)
    rows = re.findall(r"^\| T(\d+) \| (.+) \|$", text, re.MULTILINE)
    assert len(rows) == 74
    for _, cell in rows:
        listed = re.findall(r"(req-[a-z0-9-]+-\d+) \(([A-Za-z ]+)\)", cell)
        assert listed and all(acids[a] == s for a, s in listed), cell
        best[min((s for _, s in listed), key=order.index)] += 1
    counts = dict(re.findall(r"^\| (Implemented|In Development|Proposed|Backlog) \| (\d+) \|$", text, re.MULTILINE))
    assert {k: int(v) for k, v in counts.items()} == best
