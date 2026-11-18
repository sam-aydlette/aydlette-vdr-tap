"""aydlette_vdr's results as fedramp_20x_vdr evaluations (scheme `aydlette`). Pure: rows in, a GRIFT batch out.

fedramp_20x_vdr keeps one `vdr_evaluation` per finding per scheme, and reads a factor as the worst case unless evidence
backs it (`backed_factors`). Writing this method's results there puts them on the same grid as VDR-max and any other
method, such as stackarmor_vdr, which can read them by evaluation scheme.

What is written, per finding (several CVEs on one finding combine to the worst):

* `internet_reachable` and `likely_exploitable`, this method's IRV and LEV.
* `pain` stays null: fedramp_20x_vdr v0 refuses a value because no basis for lowering PAIN exists. This method's rating is
  in `rationale`, with the bases of all three.
* `evaluator` names the method and the governed profile, with its digest.

What is backed, and so read as false by other methods: only `internet_reachable = false` when reconciliation supports
it. The component is declared internal, Figure 6 finds it consistent, a fresh observation found no path, and G4, G5 and G7
pass. The evidence node holds the observers' results, and the basis is `protected_at_perimeter`. Nothing else is backed.
LEV false is a prediction (Figure 7), not one of the nine CycloneDX justifications, and narrowing and deflection are this
method's own dispositions. Those values are recorded, and other methods still read them as the worst case.
"""

from __future__ import annotations

import uuid
from collections import defaultdict
from datetime import datetime
from typing import Any

from .method.reconcile import ComponentState

SCHEME = "aydlette"
SOURCE = "aydlette_vdr"
EVALUATION = "fedramp_20x_vdr__vdr_evaluation"
EVIDENCE = "compliance_core__compliance_evidence"
EVALUATES = "EVALUATES_COMPLIANCE_FINDING__fedramp_20x_vdr"
FACTOR_EVIDENCE = "CITES_FACTOR_EVIDENCE__fedramp_20x_vdr"
FINDING_EVIDENCE = "CITES_COMPLIANCE_EVIDENCE__compliance_core"
DIMS = {"fedramp.rule": "vdr", "vdr.scheme": SCHEME}
BASIS = "protected_at_perimeter"
LEVELS = ("N0", "N1", "N2", "N3", "N4", "N5")


def backs_unreachable(row: dict[str, Any], state: ComponentState | None) -> bool:
    """Whether reconciliation supports `internet_reachable = false` for this row's component."""
    return (
        state is not None
        and not row["irv"]
        and row["irv_basis"] == "declared internal"
        and state.intent == "internal"
        and state.cell == "consistent"
        and state.observed_path is False
        and not (state.g4 or state.g5 or state.g7)
    )


def _evidence_text(state: ComponentState) -> str:
    lines = [f"Declared internal; Figure 6 cell {state.cell}; no fresh observation found a path from the internet."]
    for e in state.evidence:
        lines.append(
            f"- {e['observer']} at {e['observed_at']}: path_found={e['path_found']}, fresh={e['fresh']}, "
            f"allowlisted={e['allowlisted']}; {e['evidence']}"
        )
    return "\n".join(lines)


def build_evaluations(
    rows: list[dict[str, Any]],
    states: dict[str, ComponentState],
    profile_block: dict[str, Any],
    now: datetime,
    names: dict[str, str] | None = None,
) -> tuple[dict[str, Any], dict[str, int]]:
    by_finding: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for r in rows:
        by_finding[r["finding_id"]].append(r)
    evaluator = (
        f"aydlette_vdr ({profile_block['profile_id']} {profile_block['version']}, "
        f"sha256 {str(profile_block['sha256'])[:12]})"
    )[:255]
    nodes: list[dict[str, Any]] = []
    edges: list[dict[str, Any]] = []
    evidence_keys: dict[str, dict[str, Any]] = {}
    counts = {"evaluations": 0, "backed_unreachable": 0, "irv": 0, "lev": 0}

    def edge(etype: str, frm: dict[str, Any], to: dict[str, Any], properties: dict[str, Any] | None = None) -> None:
        edges.append({
            "entity": {"ref": f"e{len(edges)}", "entity_type": "edge", "name": etype, "dimensions": dict(DIMS)},
            "edge": {**frm, **to, "edge_type": etype, "properties": properties or {}},
        })  # fmt: skip

    for fid, rs in sorted(by_finding.items()):
        irv, lev = any(r["irv"] for r in rs), any(r["lev"] for r in rs)
        pain = max((r["pain"] for r in rs), key=LEVELS.index)
        first = rs[0]
        key = {"finding_source": first["finding_source"], "finding_source_key": first["source_key"], "scheme": SCHEME}
        rationale = (
            f"PAIN {pain} (not stored: vdr_evaluation v0 holds no PAIN). "
            + " ".join(
                f"[{r.get('vuln_id') or 'no CVE'}] IRV {r['irv']}: {r['irv_basis']}. LEV {r['lev']}: "
                f"{r['lev_basis']}. PAIN {r['pain']}: needs {r['needs_basis']}."
                for r in rs
            )  # fmt: skip
        )
        nodes.append({
            "entity": {"ref": f"v{len(nodes)}", "entity_type": EVALUATION, "dimensions": dict(DIMS),
                       "name": f"aydlette evaluation {first['source_key']}"[:255]},
            "node": {**key, "likely_exploitable": lev, "internet_reachable": irv, "pain": None,
                     "evaluator": evaluator, "evaluated_at": now.isoformat(), "rationale": rationale},
        })  # fmt: skip
        ev_ref = {"from_key": {"entity_type": EVALUATION, "key": key}}
        edge(EVALUATES, ev_ref, {"to_entity_id": fid})
        counts["evaluations"] += 1
        counts["irv"] += irv
        counts["lev"] += lev

        cid = first.get("component_id")
        state = states.get(cid) if cid else None
        if not irv and all(backs_unreachable(r, state) for r in rs) and state is not None and cid is not None:
            ekey = {"source": SOURCE, "source_key": f"reconcile:{cid}"}
            if cid not in evidence_keys:
                evidence_keys[cid] = ekey
                nodes.append({
                    "entity": {"ref": f"x{len(nodes)}", "entity_type": EVIDENCE, "dimensions": {"fedramp.rule": "vdr"},
                               "name": f"No internet path: {(names or {}).get(cid) or cid}"[:255]},
                    "node": {**ekey, "name": f"No internet path: {(names or {}).get(cid) or cid}"[:255],
                             "kind": "scanner_output", "description": _evidence_text(state)},
                })  # fmt: skip
            to_evidence = {"to_key": {"entity_type": EVIDENCE, "key": ekey}}
            edge(FACTOR_EVIDENCE, ev_ref, to_evidence,
                 {"factor": "internet_reachable", "basis": BASIS,
                  "note": "aydlette_vdr reconciliation: declared internal, observed no path (Figure 6)."})  # fmt: skip
            # informational, not passing: the evidence lowers one factor; it does not make the finding pass.
            edge(FINDING_EVIDENCE, {"from_entity_id": fid}, to_evidence,
                 {"support_kind": "informational", "note": "Supports internet_reachable = false (aydlette_vdr)."})  # fmt: skip
            counts["backed_unreachable"] += 1

    title = f"aydlette_vdr evaluations ({counts['evaluations']} findings, {counts['backed_unreachable']} backed)"
    doc = {"metadata": {"grift_version": "0"}, "_reserved": {}, "batches": [{
        "batch_entity": {"entity_id": str(uuid.uuid4()), "entity_type": "batch", "name": title, "dimensions": {}},
        "batch_node": {"source": "plugins.aydlette_vdr.collectors.vdr_evaluations", "name": title,
                       "description": "This method's IRV and LEV as fedramp_20x_vdr evaluations of scheme aydlette; "
                                      "unreachability backed only by reconciliation evidence."},
        "nodes": nodes, "edges": edges}]}  # fmt: skip
    return doc, counts
