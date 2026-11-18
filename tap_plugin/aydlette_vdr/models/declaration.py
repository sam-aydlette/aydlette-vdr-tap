"""Component declaration: what a component's owner declares about it (REQ-IRV-1, REQ-PAI-3)."""

from typing import Any, ClassVar

from django.db import models

from tap_grid.models import BaseModel

from . import _common as c

EXPOSURE = ("public-edge", "public-backed", "internal")
DATA = ("public", "internal", "pii", "cui")


class ComponentDeclaration(BaseModel):
    """Exposure intent and classification for one component, as a stamp that points at the component's node.

    The stamp may point at any node (`DECLARES_COMPONENT` is a wildcard edge), because a component is whatever the inventory
    calls one: a program, a host, a bucket, a CDN distribution. Adding a declaration changes no node or edge that
    describes the system. A missing exposure intent or data classification fails gate G5; there is no default (T6, T43).
    """

    ENTITY_TYPE: ClassVar[str] = "aydlette_vdr__declaration"
    NATURAL_KEY: ClassVar[tuple[str, ...]] = ("source", "declaration_key")
    ENTITY_NAME: ClassVar[str] = "Component Declaration"
    ENTITY_DESCRIPTION: ClassVar[str] = (
        "A component's declared exposure intent (public-edge, public-backed, internal) and data classification "
        "(public, internal, PII, CUI, Mission Critical, agency scope), with who classified it."
    )
    ENTITY_ICON: ClassVar[str] = "declaration"
    DEFAULT_DIMENSIONS: ClassVar[dict[str, str]] = c.DIMENSIONS
    OUTBOUND_EDGES: ClassVar[list[dict[str, Any]]] = [{"edges": [{"type": "DECLARES_COMPONENT__aydlette_vdr"}]}]
    INBOUND_EDGES: ClassVar[list[dict[str, Any]]] = []

    FIELD_CRUD_SCHEMA: ClassVar[dict[str, Any]] = {
        "source": {"type": "string", "minLength": 1, "maxLength": 128},
        "declaration_key": {"type": "string", "minLength": 1, "maxLength": 512},
        "exposure_intent": c.enum(*EXPOSURE),
        "exposure_rationale": c.OPT_STR,
        "data": {"type": "array", "items": {"type": "string", "enum": list(DATA)}, "uniqueItems": True},
        "mission_critical": c.BOOL,
        "agency_scope": c.enum("single", "multi"),
        "classified_by": c.OPT_STR,
        "criticality_judged_by": c.OPT_STR,
        "note": {"type": "string"},
    }
    FIELD_VALIDATION_SCHEMA: ClassVar[dict[str, Any]] = c.validation(FIELD_CRUD_SCHEMA)
    CREATE_REQUIRED: ClassVar[list[str]] = ["source", "declaration_key"]

    source = c.key(128, "Who made the declaration. Half of the identity.")
    declaration_key = c.key(512, "The source's own name for the component. Other half.")
    exposure_intent = c.opt_char(16, "public-edge, public-backed or internal. Null = not declared (G5).")
    exposure_rationale = c.opt_char(1000, "One sentence: why this exposure (REQ-IRV-1).")
    data = models.JSONField(
        blank=True, default=list, help_text="public | internal | pii | cui; empty = not declared (G5)."
    )
    mission_critical = c.flag("The mission depends on the component staying correct and available.")
    agency_scope = c.opt_char(8, "single or multi. Null = multi (REQ-PAI-3, T44).")
    classified_by = c.opt_char(255, "Who classified the data. Null is published as not recorded (T54).")
    criticality_judged_by = c.opt_char(255, "Who judged mission criticality. Null is published as not recorded.")
    note = c.text("Anything else about the declaration, such as where it was derived from.")

    class Meta(BaseModel.Meta):
        db_table = "aydlette_vdr__declaration"

    def get_name(self) -> str:
        return f"Declaration {self.declaration_key}"

    def __str__(self) -> str:
        return self.get_name()
