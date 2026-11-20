"""Coverage: does the environment give the method what it needs? Pure and Django-free.

The method never guesses. Where a prerequisite is missing it takes the worst case (a fail-safe), fails a gate, or queues a
decision, and the result is correct but pessimistic. Coverage says, for each prerequisite, how much of what it applies to
has it, which items do not, and what the method does without it. It is the to-do list that turns fail-safes into
evidence.

The inventory is every component the grid shows the method: each node an observer looked at, a declaration names, or a
finding is carried by. An adapter decides which platform resources are in scope by observing them (for AWS,
aydlette-vdr-aws-tap observes every resource type it has a rule for), so this module needs no platform knowledge.

| Area | Prerequisite | Applies to | Without it |
|---|---|---|---|
| declarations | declared | the inventory | its findings are unresolved: IRV, fail-safe classification |
| declarations | exposure intent, data classification | declared components | G5; IRV; fail-safe data |
| declarations | who classified, who judged criticality | declared components | published as not recorded (T54) |
| declarations | agency scope | declared components | rated as multi-agency (T44) |
| declarations | no contradictions | declared components | G5 |
| observers | fresh inside-out observation | declared components | G7 |
| observers | fresh outside-in observation | public-edge components | G7 |
| observers | no undeclared exposure | declared components | G4 |
| flows | a declared flow from a public component | public-backed components | over-declared, queued, IRV |
| flows | declared | observed flows | queued; G4 into internal; PII/CUI inherited |
| flows | carries stated | declared flows | G5 |
| findings | resolved to a component | open findings | unresolved |
| findings | IRV, LEV, impact, needs decided on evidence | finding rows | the fail-safe for that factor |
| advisories | CVSS vector, KEV status, EPSS, SSVC | rows with an advisory (CVE, GHSA, ...) | High impact; LEV fail-safe; no overlay |
| checks | a CVSS vector (on the record or a governed check vector) | rows with a check or no record | High impact |
"""

from __future__ import annotations

import re
from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass
from typing import Any

from .evaluate import EXPOSURE_ORDER, Declaration
from .reconcile import FLOW, OUTSIDE_IN, ComponentState, Flow, Observation

#: Identifiers of published advisories, which KEV, EPSS, Vulnrichment (SSVC) and NVD (CVSS) key on. Anything else (a
#: Checkov or ZAP rule, a scanner's own ID) is a check: those feeds say nothing about it.
ADVISORY = re.compile(
    r"^(CVE-\d{4}-\d{4,}|GHSA(-[23456789cfghjmpqrvwx]{4}){3}|PYSEC-\d{4}-\d+|GO-\d{4}-\d+|RUSTSEC-\d{4}-\d+|OSV-\d{4}-\d+)$",
    re.IGNORECASE,
)
IRV_FAIL_SAFE = ("unresolved (fail-safe)", "no exposure_intent (G5)")
LEV_FAIL_SAFE = (
    "no prediction score (fail-safe)",
    "floor: access unknown, read as the worst case",
)
AREAS = ("declarations", "observers", "flows", "findings", "advisories", "checks")


@dataclass(frozen=True)
class Check:
    key: str
    area: str
    label: str
    applies_to: str  # what the share is of
    without: str  # what the method does when the prerequisite is missing
    total: int
    covered: int
    missing: tuple[str, ...]

    @property
    def share(self) -> float | None:
        return None if self.total == 0 else self.covered / self.total

    def as_row(self) -> dict[str, Any]:
        return {**self.__dict__, "missing": list(self.missing), "share": self.share}


def is_advisory(vuln_id: str | None) -> bool:
    return bool(vuln_id) and ADVISORY.match(vuln_id or "") is not None


def coverage(
    *,
    inventory: Iterable[str],
    declarations: Mapping[str, Declaration],
    states: Mapping[str, ComponentState],
    observations: Iterable[Observation],
    flows: Iterable[Flow],
    rows: Iterable[Mapping[str, Any]],
    vulns: Mapping[str, Mapping[str, Any]],
    name: Callable[[str], str] = str,
) -> list[Check]:
    """Every prerequisite's coverage. `declarations` are the merged declarations by component id, `states` their
    reconciliation, `rows` the evaluated finding rows, and `vulns` the vulnerability records by vuln_id."""
    checks: list[Check] = []

    def add(
        key: str,
        area: str,
        label: str,
        applies_to: str,
        without: str,
        items: Iterable[tuple[str, bool]],
    ) -> None:
        items = list(items)
        missing = tuple(sorted(n for n, ok in items if not ok))
        checks.append(
            Check(
                key,
                area,
                label,
                applies_to,
                without,
                len(items),
                len(items) - len(missing),
                missing,
            )
        )

    components = set(inventory) | set(declarations)
    decl = dict(declarations)

    # ---------------------------------------------------------------------------------------------------- declarations
    add("declared", "declarations", "Components with a declaration", "components on the grid",
        "Its findings are unresolved: IRV, the fail-safe classification (PII, CUI, Mission Critical, multi-agency), "
        "queued.", ((name(c), c in decl) for c in components))  # fmt: skip
    add("exposure_intent", "declarations", "Exposure intent declared", "declared components",
        "G5 fails and its findings are IRV.",
        ((name(c), d.exposure_intent in EXPOSURE_ORDER) for c, d in decl.items()))  # fmt: skip
    add("data_classification", "declarations", "Data classification declared", "declared components",
        "G5 fails and its findings are rated at the fail-safe data (PII, CUI).",
        ((name(c), bool(d.data)) for c, d in decl.items()))  # fmt: skip
    add("classified_by", "declarations", "Who classified the data is recorded", "declared components",
        "The classification is published as not recorded (T54).",
        ((name(c), bool(d.classified_by)) for c, d in decl.items()))  # fmt: skip
    add("criticality_judged_by", "declarations", "Who judged Mission Critical is recorded", "declared components",
        "Mission Critical is published as judged by no one (T54).",
        ((name(c), bool(d.criticality_judged_by)) for c, d in decl.items()))  # fmt: skip
    add(
        "agency_scope",
        "declarations",
        "Agency scope declared",
        "declared components",
        "Rated as multi-agency (T44).",
        ((name(c), d.agency_scope in ("single", "multi")) for c, d in decl.items()),
    )
    add("no_conflicts", "declarations", "Declarations agree with each other (G5)", "declared components",
        "G5 fails.", ((name(c), not states[c].g5) for c in decl if c in states))  # fmt: skip

    # ------------------------------------------------------------------------------------------------------- observers
    add("inside_out", "observers", "A fresh inside-out observation (G7)", "declared components",
        "G7 fails: a detection failure.",
        ((name(c), not any("inside-out" in g for g in states[c].g7)) for c in decl if c in states))  # fmt: skip
    public_edge = [c for c, d in decl.items() if d.exposure_intent == "public-edge"]
    add("outside_in", "observers", "A fresh outside-in observation (G7)", "public-edge components",
        "G7 fails: a detection failure.",
        ((name(c), c in states and not any(OUTSIDE_IN in g for g in states[c].g7)) for c in public_edge))  # fmt: skip
    add("no_undeclared_exposure", "observers", "No undeclared exposure (G4)", "declared components",
        "G4 fails: its findings are IRV, and no disposition closes it.",
        ((name(c), not states[c].g4) for c in decl if c in states))  # fmt: skip

    # ----------------------------------------------------------------------------------------------------------- flows
    flows = list(flows)
    public = {c for c, d in decl.items() if d.exposure_intent in ("public-edge", "public-backed")}
    fed = {f.target for f in flows if f.source in public}
    add("public_backed_fed", "flows", "Public-backed and fed by a declared flow from a public component",
        "public-backed components", "Over-declared: queued, and its findings stay IRV.",
        ((name(c), c in fed) for c, d in decl.items() if d.exposure_intent == "public-backed"))  # fmt: skip
    pairs = {(f.source, f.target) for f in flows}
    seen = {(o.source, o.target) for o in observations if o.kind == FLOW and o.path_found and o.source}
    add("observed_flows_declared", "flows", "Observed flows that are declared", "observed flows",
        "Queued; G4 when it carries public traffic into an internal component; the receiver inherits the sender's PII "
        "and CUI (REQ-PAI-5).", ((f"{name(s)} -> {name(t)}", (s, t) in pairs) for s, t in seen))  # fmt: skip
    add("flows_state_carries", "flows", "Declared flows that say what they carry", "declared flows",
        "G5 fails (REQ-PAI-5).",
        ((f"{name(f.source)} -> {name(f.target)}", bool(f.carries or f.metadata_reason)) for f in flows))  # fmt: skip

    # -------------------------------------------------------------------------------------------------------- findings
    rows = list(rows)

    def label(r: Mapping[str, Any]) -> str:
        return f"{r.get('finding') or r['finding_id']}" + (f" [{r['vuln_id']}]" if r.get("vuln_id") else "")

    resolved: dict[str, tuple[str, bool]] = {}
    for r in rows:
        prev = resolved.get(r["finding_id"], (label(r), False))
        resolved[r["finding_id"]] = (prev[0], prev[1] or bool(r["resolved"]))
    add("findings_resolved", "findings", "Findings resolved to a declared component", "open findings",
        "IRV, the fail-safe classification, queued.", resolved.values())  # fmt: skip
    add("irv_on_evidence", "findings", "IRV decided on a declaration", "finding rows",
        "IRV, the worst case.", ((label(r), r["irv_basis"] not in IRV_FAIL_SAFE) for r in rows))  # fmt: skip
    add("lev_on_evidence", "findings", "LEV decided on evidence (KEV, exploitation, access, a prediction or a governed "
        "decision)", "finding rows", "LEV, the worst case.",
        ((label(r), r["lev_basis"] not in LEV_FAIL_SAFE) for r in rows))  # fmt: skip
    add("impact_vector", "findings", "Impact from a CVSS vector", "finding rows",
        "Impact read as High on confidentiality, integrity and availability.",
        ((label(r), bool(r.get("vector_source"))) for r in rows))  # fmt: skip
    add("needs_declared", "findings", "Needs from a declared classification", "finding rows",
        "Rated at the fail-safe classification.",
        ((label(r), not str(r.get("needs_basis", "")).startswith("fail-safe")) for r in rows))  # fmt: skip

    # ------------------------------------------------------------------------------------------- advisories and checks
    adv = [r for r in rows if is_advisory(r.get("vuln_id"))]
    rec = {r["vuln_id"]: vulns.get(r["vuln_id"], {}) for r in adv}
    add("advisory_cvss", "advisories", "A CVSS vector on the record (NVD, the CNA or CISA Vulnrichment)",
        "rows with an advisory", "Impact read as High on C, I and A.",
        ((label(r), bool(rec[r["vuln_id"]].get("cvss_vector"))) for r in adv))  # fmt: skip
    add("advisory_kev", "advisories", "KEV status known", "rows with an advisory",
        "A known-exploited flaw is not recognized as one; LEV falls to the later checks.",
        ((label(r), rec[r["vuln_id"]].get("kev") is not None) for r in adv))  # fmt: skip
    add("advisory_epss", "advisories", "A prediction score (EPSS)", "rows with an advisory",
        "No prediction: LEV is the worst case unless a floor or a governed decision applies.",
        ((label(r), rec[r["vuln_id"]].get("epss_score") is not None) for r in adv))  # fmt: skip
    add("advisory_ssvc", "advisories", "SSVC decision points (CISA Vulnrichment)", "rows with an advisory",
        "The SSVC overlay has nothing to read: no Exploitation, Automatable or Technical Impact.",
        ((label(r), bool(rec[r["vuln_id"]].get("ssvc_exploitation"))) for r in adv))  # fmt: skip
    chk = [r for r in rows if not is_advisory(r.get("vuln_id"))]
    add("check_vector", "checks", "A CVSS vector (on the record or a governed check vector)",
        "rows with a check or no vulnerability record",
        "Impact read as High on C, I and A. A governed check vector (aydlette_vdr__check_vector) supplies one per check.",
        ((label(r), bool(r.get("vector_source"))) for r in chk))  # fmt: skip
    return checks


def summary(checks: list[Check]) -> dict[str, Any]:
    """Per area, the prerequisites fully met, and the ones with gaps, worst first."""
    gaps = sorted(
        (c for c in checks if c.total and c.covered < c.total),
        key=lambda c: (c.share or 0, c.key),
    )
    return {
        "checks": len(checks),
        "met": sum(1 for c in checks if c.total and c.covered == c.total),
        "not_applicable": sum(1 for c in checks if not c.total),
        "gaps": [f"{c.key}: {c.covered}/{c.total}" for c in gaps],
        "by_area": {
            a: {
                "met": sum(1 for c in checks if c.area == a and c.total and c.covered == c.total),
                "checks": sum(1 for c in checks if c.area == a),
            }
            for a in AREAS
        },  # fmt: skip
    }
