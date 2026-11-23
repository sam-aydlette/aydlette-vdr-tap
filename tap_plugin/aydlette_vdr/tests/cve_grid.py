"""The CVE grid fixture: findings with advisory records on a real grid, enriched the way vuln_mosaic enriches them.

The scenario (components are computing_core nodes, which this plugin's dependency closure already installs):

| Component | Declared | Observed | Findings |
|---|---|---|---|
| `www` (web host) | public-edge, public data | path, inside-out and outside-in | F1 Log4Shell (CVE-2021-44228) |
| `api` (program) | public-backed, PII, Mission Critical, multi-agency; a declared flow from `www` carrying PII | no path | F3 CVE-2022-0179, F6 GHSA-fmf4-pr35-46c2 |
| `db` (host) | internal, PII and CUI, single agency | no path | F2 CVE-2022-0001, F4 CVE-2022-0303, F7 a configuration check (no record) |
| `stray` (host) | nothing | nothing | F5 CVE-2026-12345, held by no dataset |

The environmental-vector tests add F8 to `api`: CVE-2019-9514, the HTTP/2 Reset Flood (network, no privileges, no user
interaction, availability only), not KEV-listed and scored low. With and without an observation that every ingress into
`api` requires authentication (`add_reset_flood`).

The advisory records are real (CVE List and GitHub advisory records from vuln_mosaic's test corpus; see
`fixtures/cve_grid/README.md`). The KEV catalog and EPSS scores are illustrative: Log4Shell is listed, three CVEs are
scored, and the catalog is fresh, so a CVE it does not list reads as not known exploited.

Vulnerability nodes start bare (only `vuln_id`). vuln_mosaic's own `enrich_grid` fills them through the grid, from a
vuln_mosaic home seeded with those records and the illustrative catalogs, the way vuln_mosaic's tests seed one. Nothing
is stubbed: the grid read, `plan_patch` and the batched patch writes are vuln_mosaic's. vuln_mosaic is not a dependency of
this plugin, so the tests that use this fixture skip where it is not installed (this plugin's own CI record) and run in
a session that composes both.
"""

from __future__ import annotations

import gzip
import importlib
import json
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

FIXTURES = Path(__file__).resolve().parent / "fixtures" / "cve_grid"
NOW = datetime(2026, 11, 20, 12, tzinfo=UTC)
CHECKED = "2099-01-01T00:00:00Z"  # dataset check time: always fresh, as vuln_mosaic's own tests seed it

LOG4SHELL, BHI, C0179, C0303, UNHELD, GHSA = (
    "CVE-2021-44228", "CVE-2022-0001", "CVE-2022-0179", "CVE-2022-0303", "CVE-2026-12345", "GHSA-fmf4-pr35-46c2",
)  # fmt: skip
VULN_IDS = (LOG4SHELL, BHI, C0179, C0303, UNHELD, GHSA)
RESET_FLOOD = "CVE-2019-9514"  # F8, added only by the environmental-vector tests
KEV_LISTED = {LOG4SHELL: ("2021-12-10", "2021-12-24")}  # added, due
EPSS = {LOG4SHELL: (0.97, 0.99), BHI: (0.0005, 0.15), C0179: (0.21, 0.95), RESET_FLOOD: (0.02, 0.6)}  # illustrative

# finding key -> (component, vuln_id or None, days since detection)
FINDINGS = {
    "F1": ("www", LOG4SHELL, 30),
    "F2": ("db", BHI, 30),
    "F3": ("api", C0179, 30),
    "F4": ("db", C0303, 30),
    "F5": ("stray", UNHELD, 30),
    "F6": ("api", GHSA, 30),
    "F7": ("db", None, 30),
}
SOURCE = "cve-grid-fixture"


# ------------------------------------------------------------------------------------------------------ vuln_mosaic
def _vuln_mosaic(module: str) -> Any:
    """A vuln_mosaic module, loaded at run time. vuln_mosaic is an optional collaborator of these tests (the way
    `pytest.importorskip` loads one), not an import dependency of this plugin, so `depends_on` does not name it."""
    return importlib.import_module(f"tap_plugin.vuln_mosaic.{module}")


def seed_home(home: Path) -> Path:
    """A vuln_mosaic home holding the fixture's records, KEV catalog and EPSS scores, as its own tests seed one."""
    files = _vuln_mosaic("files")
    DatasetFacts = _vuln_mosaic("staleness").DatasetFacts  # noqa: N806
    RecordStore = _vuln_mosaic("store").RecordStore  # noqa: N806

    with RecordStore.open_writer(home, "cvelist") as store:
        for p in sorted(FIXTURES.glob("CVE-*.json")):
            store.put(p.stem, "PUBLISHED", None, p.read_bytes())
        store.set_facts(as_of=CHECKED, checked_at=CHECKED, source_version="cve-grid-fixture", fetched_at=CHECKED)
    with RecordStore.open_writer(home, "ghsa") as store:
        for p in sorted(FIXTURES.glob("GHSA-*.json")):
            store.put(p.stem, "PUBLISHED", None, p.read_bytes())
        store.set_facts(as_of=CHECKED, checked_at=CHECKED, source_version="cve-grid-fixture", fetched_at=CHECKED)
    kev = {"catalogVersion": "2026.11.20", "dateReleased": "2026-11-20T00:00:00Z", "count": len(KEV_LISTED),
           "vulnerabilities": [{"cveID": c, "dateAdded": a, "dueDate": d, "requiredAction": "Apply updates.",
                                "knownRansomwareCampaignUse": "Known"} for c, (a, d) in KEV_LISTED.items()]}  # fmt: skip
    stage = files.new_staging(home, "kev", "b1")
    (stage / "known_exploited_vulnerabilities.json").write_text(json.dumps(kev))
    files.publish(home, "kev", "b1", stage, DatasetFacts(as_of="2026-11-20T00:00:00Z", checked_at=CHECKED,
                                                         source_version="2026.11.20"))  # fmt: skip
    rows = "".join(f"{c},{s},{p}\n" for c, (s, p) in EPSS.items())
    stage = files.new_staging(home, "epss", "b1")
    (stage / "epss_scores.csv.gz").write_bytes(
        gzip.compress(
            f"#model_version:v2026.06.15,score_date:2026-11-20T00:00:00Z\ncve,epss,percentile\n{rows}".encode()
        )
    )
    files.publish(home, "epss", "b1", stage, DatasetFacts(as_of="2026-11-20T00:00:00Z", checked_at=CHECKED,
                                                          source_version="v2026.06.15"))  # fmt: skip
    return home


# ------------------------------------------------------------------------------------------------------- the grid
def build_grid() -> dict[str, str]:
    """Seed the rules and the starter profile, and create the scenario's nodes and edges. Returns entity ids by name:
    components by component name and findings by finding key."""
    import tap_plugin.fedramp_20x_vdr as vdr_pkg

    from tap_grid.grift import grift_import
    from tap_grid.models import Entity
    from tap_grid.services import create_edge, create_node

    from .. import models as _models  # noqa: F401

    pkg = Path(__file__).resolve().parents[1]
    for path in (Path(vdr_pkg.__file__).parent / "grift" / "dimension.grift.json",
                 Path(vdr_pkg.__file__).parent / "grift" / "timeframes.grift.json",
                 pkg / "grift" / "profiles.grift.json"):  # fmt: skip
        result = grift_import(json.loads(path.read_text(encoding="utf-8")))
        assert result.success, (path.name, result.errors)

    ids: dict[str, str] = {}

    def node(etype: str, payload: dict[str, Any]) -> str:
        made = create_node(etype, payload)
        assert made.success, (etype, made.errors)
        return str(made.entity_id)

    def edge(a: str, b: str, etype: str, props: dict[str, Any] | None = None) -> None:
        create_edge(Entity.objects.get(pk=a), Entity.objects.get(pk=b), etype, props or {})

    ids["www"] = node("computing_core__web_host", {"name": "www", "hostname": "www.fixture.test"})
    ids["api"] = node("computing_core__program", {"name": "api", "program_name": "api"})
    ids["db"] = node("computing_core__host", {"name": "db", "realm": "fixture", "stable_id": "db"})
    ids["stray"] = node("computing_core__host", {"name": "stray", "realm": "fixture", "stable_id": "stray"})

    declarations: dict[str, dict[str, Any]] = {
        "www": {"exposure_intent": "public-edge", "data": ["public"], "agency_scope": "multi"},
        "api": {"exposure_intent": "public-backed", "data": ["pii"], "mission_critical": True, "agency_scope": "multi"},
        "db": {"exposure_intent": "internal", "data": ["pii", "cui"], "agency_scope": "single"},
    }
    for comp, fields in declarations.items():
        d = node("aydlette_vdr__declaration", {"source": SOURCE, "declaration_key": comp, "classified_by": "data owner",
                                               "criticality_judged_by": "system owner",
                                               "exposure_rationale": f"Fixture: {comp}.", **fields})  # fmt: skip
        edge(d, ids[comp], "DECLARES_COMPONENT__aydlette_vdr")

    f = node("aydlette_vdr__declared_flow", {"source": SOURCE, "flow_key": "www>api", "carries": ["pii"]})
    edge(f, ids["www"], "FLOW_SOURCE__aydlette_vdr")
    edge(f, ids["api"], "FLOW_TARGET__aydlette_vdr")

    seen = (NOW - timedelta(hours=1)).isoformat()
    for comp, observer, found in (("www", "inside-out", True), ("www", "outside-in", True),
                                  ("api", "inside-out", False), ("db", "inside-out", False)):  # fmt: skip
        o = node("aydlette_vdr__observation", {
            "source": SOURCE, "observation_key": f"{comp}|{observer}", "observer": observer, "kind": "internet-path",
            "path_found": found, "observed_at": seen, "allowlisted": False if observer == "outside-in" else None,
            "method": "fixture", "evidence": f"fixture {observer} observation of {comp}"})  # fmt: skip
        edge(o, ids[comp], "OBSERVES_COMPONENT__aydlette_vdr")

    vulns = {v: node("compliance_core__compliance_vulnerability", {"vuln_id": v}) for v in VULN_IDS}
    for key, (comp, vid, days) in FINDINGS.items():
        fid = node("compliance_core__compliance_finding", {
            "source": SOURCE, "source_key": key, "name": f"{key} {vid or 'configuration check'} on {comp}",
            "status": "open", "first_detected_at": (NOW - timedelta(days=days)).isoformat()})  # fmt: skip
        ids[key] = fid
        edge(ids[comp], fid, "CARRIES_COMPLIANCE_FINDING__compliance_core")
        if vid:
            edge(fid, vulns[vid], "CONCERNS_COMPLIANCE_VULNERABILITY__compliance_core")
    ids.update({f"vuln:{v}": e for v, e in vulns.items()})
    return ids


def add_reset_flood(ids: dict[str, str], *, authenticated_ingress: bool | None) -> str:
    """Add F8 (CVE-2019-9514 on `api`, bare until enriched) and, unless `authenticated_ingress` is None, an inside-out
    observation of whether an unauthenticated request can reach `api`. Returns F8's entity id."""
    from tap_grid.models import Entity
    from tap_grid.services import create_edge, create_node

    def node(etype: str, payload: dict[str, Any]) -> Entity:
        made = create_node(etype, payload)
        assert made.success, (etype, made.errors)
        return Entity.objects.get(pk=made.entity_id)

    api = Entity.objects.get(pk=ids["api"])
    vuln = node("compliance_core__compliance_vulnerability", {"vuln_id": RESET_FLOOD})
    f8 = node("compliance_core__compliance_finding", {
        "source": SOURCE, "source_key": "F8", "name": f"F8 {RESET_FLOOD} on api", "status": "open",
        "first_detected_at": (NOW - timedelta(days=30)).isoformat()})  # fmt: skip
    create_edge(api, f8, "CARRIES_COMPLIANCE_FINDING__compliance_core", {})
    create_edge(f8, vuln, "CONCERNS_COMPLIANCE_VULNERABILITY__compliance_core", {})
    if authenticated_ingress is not None:
        o = node("aydlette_vdr__observation", {
            "source": SOURCE, "observation_key": "api|inside-out|unauth-ingress", "observer": "inside-out",
            "kind": "unauth-ingress", "path_found": not authenticated_ingress,
            "observed_at": (NOW - timedelta(hours=1)).isoformat(), "method": "fixture",
            "evidence": "fixture: every route into api requires a JWT" if authenticated_ingress
            else "fixture: a route into api takes unauthenticated requests"})  # fmt: skip
        create_edge(o, api, "OBSERVES_COMPONENT__aydlette_vdr", {})
    return str(f8.pk)


def enrich(home: Path) -> Any:
    """Fill the bare vulnerability nodes with vuln_mosaic's `enrich_grid`, reading and writing this grid. Returns
    vuln_mosaic's own result (patched, unchanged, failed, problems).

    It runs as vuln_mosaic's collector runs: as the collector actor, with no batch bound, so vuln_mosaic mints and names
    its own batches. (TAP's test harness binds one batch per test, which the fixture's own writes have already opened
    under the test's name; a write that names its batch may not join that one.)"""
    enrich_grid = _vuln_mosaic("collectors.refresh.gridwrite").enrich_grid
    parse_settings = _vuln_mosaic("settings").parse_settings

    from tap_auth.actors import COLLECTOR, acting_as, get_builtin_actor

    seed_home(home)
    with acting_as(get_builtin_actor(COLLECTOR)):
        return enrich_grid(parse_settings({}), home)
