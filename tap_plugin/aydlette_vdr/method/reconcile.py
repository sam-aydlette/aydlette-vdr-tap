"""Reconciliation: declared exposure and flows against what the observers saw (Figure 6, REQ-IRV-2, -3, -4, -8, -11,
-13, REQ-PAI-5). Pure and Django-free.

The input is vendor-neutral. A component is any node with a declaration. An observation says whether an observer found a
path from the internet to a component (kind ``internet-path``) or a flow from one component to another (kind ``flow``),
when, and on what evidence. A declared flow says a component sends data to another and what it carries. An adapter (for
AWS, aydlette-vdr-aws-tap) turns a platform's facts into observations. The method never asks how they were made.

Figure 6, as cells (intent x observed path):

* internal or public-backed, path observed: undeclared exposure ("a backed component has no direct path"). G4 fails,
  its findings are IRV, and no disposition closes it.
* public-edge, no path: over-declared. Queued, and its findings stay IRV until someone decides.
* public-backed, no path: consistent when a declared flow from a public component reaches it; otherwise over-declared.
* every other cell: consistent.

Flows (REQ-IRV-8): an observed flow from a public component into an internal one with no declared flow is undeclared
exposure (G4); any other undeclared observed flow is queued. A declared flow from a public component into an internal one
contradicts the declarations (REQ-IRV-2, T5): G5.

Classification on flows (REQ-PAI-5): a declared flow that carries a data flag into a component without it fails G5 (T45);
a metadata-only flow must publish its reason; an undeclared flow from a sensitive component is queued, and the receiver is
classified as if it carried the source's data flags until someone decides (T47).

Observer coverage (REQ-IRV-3): every declared component needs a fresh inside-out observation, and every public-edge one a
fresh outside-in observation too, within the freshness window (at most a day). A missing or stale observation is a
detection failure: G7.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timedelta

from .evaluate import EXPOSURE_ORDER, Declaration

INTERNET_PATH = "internet-path"
FLOW = "flow"
INSIDE_OUT = "inside-out"
OUTSIDE_IN = "outside-in"
TELEMETRY = "telemetry"
OBSERVERS: tuple[str, ...] = (INSIDE_OUT, OUTSIDE_IN, TELEMETRY)
KINDS: tuple[str, ...] = (INTERNET_PATH, FLOW)
SENSITIVE: frozenset[str] = frozenset({"pii", "cui"})
MAX_FRESHNESS_HOURS = 24  # "at least once a day" (REQ-IRV-3); a profile may only shorten it


@dataclass(frozen=True)
class Observation:
    observation_id: str
    observer: str  # inside-out | outside-in | telemetry
    kind: str  # internet-path | flow
    target: str  # the component the path reaches, or the flow's receiver
    path_found: bool
    observed_at: datetime | None
    source: str | None = None  # a flow's sender
    allowlisted: bool | None = None  # REQ-IRV-11: an outside-in probe from an allowlisted address
    evidence: str = ""


@dataclass(frozen=True)
class Flow:
    flow_id: str
    source: str
    target: str
    carries: tuple[str, ...] = ()  # data flags; empty with metadata_reason means metadata only
    metadata_reason: str | None = None


@dataclass
class ComponentState:
    component: str
    intent: str | None
    observed_path: bool | None  # None: no fresh observer looked
    cell: str  # consistent | undeclared-exposure | over-declared | undeclared | unobserved
    publicly_exposed: bool  # REQ-IRV-13: yes for public-edge, no otherwise
    suggested_intent: str | None  # what the observations alone would suggest; never used as a declaration
    g4: list[str] = field(default_factory=list)
    g5: list[str] = field(default_factory=list)
    g7: list[str] = field(default_factory=list)
    queue: list[dict[str, str]] = field(default_factory=list)
    inherited_data: tuple[str, ...] = ()
    evidence: list[dict[str, object]] = field(default_factory=list)


def _public(decl: Declaration | None) -> bool:
    return decl is not None and decl.exposure_intent in ("public-edge", "public-backed")


def reconcile(
    declarations: dict[str, Declaration],
    observations: list[Observation],
    flows: list[Flow],
    *,
    now: datetime,
    freshness_hours: int = MAX_FRESHNESS_HOURS,
) -> dict[str, ComponentState]:
    """One state per declared component. `declarations` is keyed by component (node) id."""
    window = timedelta(hours=min(freshness_hours, MAX_FRESHNESS_HOURS))
    opened = now.isoformat()

    def fresh(o: Observation) -> bool:
        return o.observed_at is not None and now - o.observed_at <= window

    paths: dict[str, list[Observation]] = {}
    observed_flows: list[Observation] = []
    for o in observations:
        if o.kind == INTERNET_PATH:
            paths.setdefault(o.target, []).append(o)
        elif o.kind == FLOW and o.source:
            observed_flows.append(o)

    declared_into: dict[str, list[Flow]] = {}
    for f in flows:
        declared_into.setdefault(f.target, []).append(f)
    declared_pairs = {(f.source, f.target) for f in flows}

    observed_any: dict[str, bool] = {t: any(o.path_found for o in os_ if fresh(o)) for t, os_ in paths.items()}

    def reachable(component: str | None) -> bool:
        return bool(component) and (
            _public(declarations.get(component or "")) or observed_any.get(component or "", False)
        )

    out: dict[str, ComponentState] = {}
    for cid, decl in declarations.items():
        intent = decl.exposure_intent if decl.exposure_intent in EXPOSURE_ORDER else None
        mine = paths.get(cid, [])
        live = [o for o in mine if fresh(o)]
        observed = any(o.path_found for o in live) if live else None
        st = ComponentState(
            component=cid, intent=intent, observed_path=observed, cell="consistent",
            publicly_exposed=intent == "public-edge", suggested_intent=None,
        )  # fmt: skip
        st.evidence = [
            {"observer": o.observer, "path_found": o.path_found, "observed_at": o.observed_at.isoformat() if o.observed_at else None,
             "fresh": fresh(o), "allowlisted": o.allowlisted, "evidence": o.evidence}
            for o in mine
        ]  # fmt: skip

        # Observer coverage (G7).
        if not any(o.observer == INSIDE_OUT for o in live):
            st.g7.append("no fresh inside-out observation (REQ-IRV-3)")
        if intent == "public-edge" and not any(o.observer == OUTSIDE_IN for o in live):
            st.g7.append("no fresh outside-in observation of a public-edge component (REQ-IRV-3)")

        inbound_public = [f for f in declared_into.get(cid, []) if _public(declarations.get(f.source))]
        if intent is None:
            st.cell = "undeclared"
        elif observed is None:
            st.cell = "unobserved"
        elif intent in ("internal", "public-backed") and observed:
            st.cell = "undeclared-exposure"
            st.g4.append(
                f"an observer found a direct path from the internet to a component declared {intent} (Figure 6"
                + (": a backed component has no direct path)" if intent == "public-backed" else ")")
            )
        elif intent == "public-edge" and not observed:
            st.cell = "over-declared"
        elif intent == "public-backed" and not observed and not inbound_public:
            st.cell = "over-declared"
        if st.cell == "over-declared":
            st.queue.append(
                {
                    "kind": "over-declared",
                    "subject": cid,
                    "opened_at": opened,
                    "why": f"declared {intent}, but no fresh observation found a path"
                    + ("" if intent == "public-edge" else " and no declared flow from a public component"),
                    "options": "narrow the declaration to internal, or record why the observers miss the path",
                }
            )

        # Declared flows into this component (REQ-IRV-2, REQ-PAI-5).
        for f in declared_into.get(cid, []):
            src = declarations.get(f.source)
            if _public(src) and intent == "internal":
                st.g5.append(
                    f"declared flow {f.flow_id} from a public component into one declared internal (REQ-IRV-2)"
                )
            if f.carries:
                missing = sorted(set(f.carries) - set(decl.data))
                if missing:
                    st.g5.append(
                        f"declared flow {f.flow_id} carries {', '.join(missing)} into a component without it (REQ-PAI-5)"
                    )
            elif not f.metadata_reason:
                st.g5.append(
                    f"declared flow {f.flow_id} states neither what it carries nor why it is metadata only (REQ-PAI-5)"
                )

        # Observed flows into this component with no declared flow (REQ-IRV-8, REQ-PAI-5).
        inherited: set[str] = set()
        for o in observed_flows:
            if o.target != cid or not o.path_found or (o.source, cid) in declared_pairs:
                continue
            src = declarations.get(o.source) if o.source else None
            if _public(src) and intent == "internal":
                st.cell = "undeclared-exposure"
                st.g4.append(f"observed flow from public component {o.source} with no declared flow (REQ-IRV-8)")
            else:
                st.queue.append(
                    {
                        "kind": "undeclared-flow",
                        "subject": f"{o.source} -> {cid}",
                        "opened_at": opened,
                        "why": f"{o.observer} observed a flow that no declaration names",
                        "options": "declare the flow and what it carries, or remove it",
                    }
                )
            if src is not None and SENSITIVE & set(src.data):
                inherited |= SENSITIVE & set(src.data)
        st.inherited_data = tuple(sorted(inherited - set(decl.data)))

        # What the observations alone suggest. A suggestion is published beside the declaration, never used as one.
        if observed:
            st.suggested_intent = "public-edge"
        elif observed is False:
            fed = any(reachable(f.source) for f in declared_into.get(cid, [])) or any(
                o.target == cid and o.path_found and reachable(o.source) for o in observed_flows
            )
            st.suggested_intent = "public-backed" if fed else "internal"
        out[cid] = st
    return out
