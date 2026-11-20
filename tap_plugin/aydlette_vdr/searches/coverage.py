"""`aydlette-coverage`: whether the environment gives the method what it needs (method/coverage.py).

One row per prerequisite: what it applies to, how much has it, the items missing it and what the method does without it.
Reads through `read_scope` with the caller's `db_alias` and writes nothing.
"""

from __future__ import annotations

from collections import Counter
from typing import Any

from tap_plugin.compliance_core.models.compliance_vulnerability import (
    ComplianceVulnerability,
)

from tap_grid.gryphon import read_scope
from tap_grid.models import Entity, Search

from ..method import coverage as cov
from ..method import reconcile as rc
from .pain import CARRIES, _as_of, _inputs, _pairs, evaluate_rows, load_reconcile_inputs
from .schema import COVERAGE_INPUT_SCHEMA

VULN_FIELDS = ("vuln_id", "cvss_vector", "kev", "epss_score", "ssvc_exploitation")


def aydlette_coverage(search: Search, inputs: dict[str, Any], *, db_alias: str, layer: str = "full") -> dict[str, Any]:
    """One row per prerequisite, worst share first within each area; the summary and profile block in `info`."""
    p = _inputs(inputs, COVERAGE_INPUT_SCHEMA)
    now = _as_of(p.get("now"))
    states: dict[str, rc.ComponentState] = {}
    passed = {k: p[k] for k in ("profile_id", "declaration_source", "now", "finding_source") if p.get(k)}
    rows, block = evaluate_rows({**passed, "now": now.isoformat()}, db_alias=db_alias, deadlines=False,
                                states_sink=states)  # fmt: skip
    merged, observations, flows = load_reconcile_inputs(p, db_alias=db_alias)

    open_ids = sorted({r["finding_id"] for r in rows})
    carriers = {c for c, _ in _pairs(CARRIES, db_alias=db_alias, to_entity_id__in=open_ids)}
    observed = {o.target for o in observations} | {o.source for o in observations if o.source}
    inventory = observed | set(merged) | carriers

    vuln_ids = sorted({r["vuln_id"] for r in rows if r.get("vuln_id")})
    vulns = {
        v["vuln_id"]: v
        for v in read_scope.node_relation(read_scope.DEFAULT_SCOPE, ComplianceVulnerability, db_alias=db_alias)
        .filter(vuln_id__in=vuln_ids)
        .values(*VULN_FIELDS)
    }
    named = Entity.objects.using(db_alias).filter(pk__in=sorted(inventory)).values_list("pk", "name", "entity_type")
    taken = Counter(n for _, n, _ in named)
    # Resources often share a name (an API, its Lambda and the rule that invokes it): add the type when one is ambiguous.
    names = {str(k): n if taken[n] == 1 else f"{n} ({t.split('__', 1)[-1]})" for k, n, t in named}
    checks = cov.coverage(
        inventory=inventory, declarations=merged, states=states, observations=observations, flows=flows, rows=rows,
        vulns=vulns, name=lambda i: names.get(i) or i,
    )  # fmt: skip
    limit = p["max_results"]
    out = []
    warnings: dict[str, Any] = {}
    for c in checks:
        row = c.as_row()
        if len(row["missing"]) > limit:
            warnings.setdefault("missing_truncated", []).append(
                f"{c.key}: {len(row['missing'])} missing, {limit} shown"
            )
            row["missing"] = row["missing"][:limit]
        out.append(row)
    return {
        "nodes": [],
        "edges": [],
        "rows": out,
        "info": {
            "summary": cov.summary(checks),
            "inventory": len(inventory),
            "open_findings": len(open_ids),
            "profile": block["profile"],
            "evaluated_at": now.isoformat(),
            "inventory_basis": "every node an observer looked at, a declaration names, or an open finding is carried by",
        },
        "warnings": warnings,
    }
