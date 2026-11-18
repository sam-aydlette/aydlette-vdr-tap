"""Observation and declared flow: what the observers saw, and the flows the owners declared (Figure 6, REQ-IRV-8,
REQ-PAI-5). Vendor-neutral: an adapter turns a platform's facts into these nodes."""

from typing import Any, ClassVar

from django.db import models

from tap_grid.models import BaseModel

from ..method.reconcile import KINDS, OBSERVERS
from . import _common as c

DATA = ("public", "internal", "pii", "cui")


class Observation(BaseModel):
    """One observer's latest answer for one component: a path from the internet (`internet-path`) or a flow from another
    component (`flow`). The identity is the observer's key for (component, observer, kind), so each run overwrites the
    node and the node's history is the evidence trail. `OBSERVES_COMPONENT` points at the component (any node); a flow's
    sender is `OBSERVES_SENDER`.
    """

    ENTITY_TYPE: ClassVar[str] = "aydlette_vdr__observation"
    NATURAL_KEY: ClassVar[tuple[str, ...]] = ("source", "observation_key")
    ENTITY_NAME: ClassVar[str] = "Observation"
    ENTITY_DESCRIPTION: ClassVar[str] = (
        "An observer's finding about a component: whether a path from the internet, or a flow from another component, "
        "exists, when it looked, and on what evidence."
    )
    ENTITY_ICON: ClassVar[str] = "observation"
    DEFAULT_DIMENSIONS: ClassVar[dict[str, str]] = c.DIMENSIONS
    OUTBOUND_EDGES: ClassVar[list[dict[str, Any]]] = [
        {"edges": [{"type": "OBSERVES_COMPONENT__aydlette_vdr"}]},
        {"edges": [{"type": "OBSERVES_SENDER__aydlette_vdr"}]},
    ]
    INBOUND_EDGES: ClassVar[list[dict[str, Any]]] = []

    FIELD_CRUD_SCHEMA: ClassVar[dict[str, Any]] = {
        "source": {"type": "string", "minLength": 1, "maxLength": 128},
        "observation_key": {"type": "string", "minLength": 1, "maxLength": 512},
        "observer": c.enum(*OBSERVERS, nullable=False),
        "kind": c.enum(*KINDS, nullable=False),
        "path_found": c.BOOL,
        "observed_at": {"type": "string", "format": "date-time"},
        "allowlisted": c.OPT_BOOL,
        "method": c.OPT_STR,
        "evidence": {"type": "string"},
    }
    FIELD_VALIDATION_SCHEMA: ClassVar[dict[str, Any]] = c.validation(FIELD_CRUD_SCHEMA)
    CREATE_REQUIRED: ClassVar[list[str]] = [
        "source",
        "observation_key",
        "observer",
        "kind",
        "path_found",
        "observed_at",
    ]

    source = c.key(128, "The observer that made it (an adapter). Half of the identity.")
    observation_key = c.key(512, "The observer's key for (component, observer, kind). Other half.")
    observer = c.key(16, "inside-out, outside-in or telemetry.")
    kind = c.key(16, "internet-path or flow.")
    path_found = c.flag("A path (or flow) exists.")
    observed_at = c.opt_datetime("When the observer looked. Older than the freshness window counts as not looked (G7).")
    allowlisted = c.opt_bool("An outside-in probe ran from an allowlisted address (REQ-IRV-11).")
    method = c.opt_char(255, "How the observer decided, for example 'cloudfront-distribution-enabled'.")
    evidence = c.text("What the observer read: the facts, with their identifiers.")

    class Meta(BaseModel.Meta):
        db_table = "aydlette_vdr__observation"

    def get_name(self) -> str:
        return f"{self.observer} {self.kind} {self.observation_key}"

    def __str__(self) -> str:
        return self.get_name()


class DeclaredFlow(BaseModel):
    """A flow an owner declared: from one component to another, and what it carries (REQ-PAI-5). `FLOW_SOURCE` and
    `FLOW_TARGET` point at the two components (any node)."""

    ENTITY_TYPE: ClassVar[str] = "aydlette_vdr__declared_flow"
    NATURAL_KEY: ClassVar[tuple[str, ...]] = ("source", "flow_key")
    ENTITY_NAME: ClassVar[str] = "Declared Flow"
    ENTITY_DESCRIPTION: ClassVar[str] = "A declared data flow between two components and the data flags it carries."
    ENTITY_ICON: ClassVar[str] = "flow"
    DEFAULT_DIMENSIONS: ClassVar[dict[str, str]] = c.DIMENSIONS
    OUTBOUND_EDGES: ClassVar[list[dict[str, Any]]] = [
        {"edges": [{"type": "FLOW_SOURCE__aydlette_vdr"}]},
        {"edges": [{"type": "FLOW_TARGET__aydlette_vdr"}]},
    ]
    INBOUND_EDGES: ClassVar[list[dict[str, Any]]] = []

    FIELD_CRUD_SCHEMA: ClassVar[dict[str, Any]] = {
        "source": {"type": "string", "minLength": 1, "maxLength": 128},
        "flow_key": {"type": "string", "minLength": 1, "maxLength": 512},
        "carries": {"type": "array", "items": {"type": "string", "enum": list(DATA)}, "uniqueItems": True},
        "metadata_reason": c.OPT_STR,
    }
    FIELD_VALIDATION_SCHEMA: ClassVar[dict[str, Any]] = c.validation(FIELD_CRUD_SCHEMA)
    CREATE_REQUIRED: ClassVar[list[str]] = ["source", "flow_key"]

    source = c.key(128, "Who declared the flow. Half of the identity.")
    flow_key = c.key(512, "The declarer's key for the flow. Other half.")
    carries = models.JSONField(blank=True, default=list, help_text="Data flags it carries; empty = metadata only.")
    metadata_reason = c.opt_char(1000, "Why a metadata-only flow carries no data flags (REQ-PAI-5).")

    class Meta(BaseModel.Meta):
        db_table = "aydlette_vdr__declared_flow"

    def get_name(self) -> str:
        return f"Flow {self.flow_key}"

    def __str__(self) -> str:
        return self.get_name()
