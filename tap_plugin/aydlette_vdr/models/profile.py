"""Governed profile and governed check vector: the provider's published choices (REQ-GOV-1, REQ-LEV-2, REQ-PAI-4)."""

from typing import Any, ClassVar

from django.db import models

from tap_grid.models import BaseModel

from . import _common as c


class Profile(BaseModel):
    """One governed profile: θ and its rationale, the combining function, the needs map, the tables, the severity
    fallback and the SSVC overlay switch. `document` holds the choices; anything it leaves out is the global default, and
    every output names the profile, its version, its sha256 and its deviations from the defaults.
    """

    ENTITY_TYPE: ClassVar[str] = "aydlette_vdr__profile"
    NATURAL_KEY: ClassVar[tuple[str, ...]] = ("profile_id",)
    ENTITY_NAME: ClassVar[str] = "Governed Profile"
    ENTITY_DESCRIPTION: ClassVar[str] = (
        "A provider's governed choices for the vulnerability-evidence method, versioned and published with every output."
    )
    ENTITY_ICON: ClassVar[str] = "profile"
    DEFAULT_DIMENSIONS: ClassVar[dict[str, str]] = c.DIMENSIONS
    OUTBOUND_EDGES: ClassVar[list[dict[str, Any]]] = []
    INBOUND_EDGES: ClassVar[list[dict[str, Any]]] = []

    FIELD_CRUD_SCHEMA: ClassVar[dict[str, Any]] = {
        "profile_id": {"type": "string", "minLength": 1, "maxLength": 128},
        "version": {"type": "string", "minLength": 1, "maxLength": 64},
        "description": {"type": "string"},
        "document": {"type": "object"},
    }
    FIELD_VALIDATION_SCHEMA: ClassVar[dict[str, Any]] = c.validation(FIELD_CRUD_SCHEMA)
    CREATE_REQUIRED: ClassVar[list[str]] = ["profile_id", "version", "document"]

    profile_id = c.key(128, "The profile's name. The identity.")
    version = models.CharField(max_length=64, blank=True, default="", help_text="Bumped on every change.")
    description = c.text("Whose profile this is and what it is for.")
    document = models.JSONField(blank=True, default=dict, help_text="The governed choices (method/profile.py).")

    class Meta(BaseModel.Meta):
        db_table = "aydlette_vdr__profile"

    def get_name(self) -> str:
        return f"Profile {self.profile_id} {self.version}"

    def __str__(self) -> str:
        return self.get_name()


class CheckVector(BaseModel):
    """A governed severity vector for a check that has none (a configuration check), decided once by a named person and
    reviewed by a date. It applies to every finding whose vulnerability record's `vuln_id` equals `check_id`. A record
    without decided_by and decided_on is a proposal, and one past review_by has lapsed: neither is in force.
    """

    ENTITY_TYPE: ClassVar[str] = "aydlette_vdr__check_vector"
    NATURAL_KEY: ClassVar[tuple[str, ...]] = ("check_id",)
    ENTITY_NAME: ClassVar[str] = "Check Vector"
    ENTITY_DESCRIPTION: ClassVar[str] = "A governed CVSS vector for a configuration check that carries none."
    ENTITY_ICON: ClassVar[str] = "check-vector"
    DEFAULT_DIMENSIONS: ClassVar[dict[str, str]] = c.DIMENSIONS
    OUTBOUND_EDGES: ClassVar[list[dict[str, Any]]] = []
    INBOUND_EDGES: ClassVar[list[dict[str, Any]]] = []

    FIELD_CRUD_SCHEMA: ClassVar[dict[str, Any]] = {
        "check_id": {"type": "string", "minLength": 1, "maxLength": 512},
        "vector": {"type": "string", "minLength": 1},
        "rationale": c.OPT_STR,
        "decided_by": c.OPT_STR,
        "decided_on": c.OPT_DATE,
        "review_by": c.OPT_DATE,
    }
    FIELD_VALIDATION_SCHEMA: ClassVar[dict[str, Any]] = c.validation(FIELD_CRUD_SCHEMA)
    CREATE_REQUIRED: ClassVar[list[str]] = ["check_id", "vector"]

    check_id = c.key(512, "The vuln_id of the check's vulnerability record. The identity.")
    vector = models.CharField(max_length=255, blank=True, default="", help_text="A complete CVSS 3.x or 4.0 vector.")
    rationale = c.opt_char(2000, "Why this vector.")
    decided_by = c.opt_char(255, "Who decided. Null = a proposal, not in force.")
    decided_on = c.opt_date("When. Null = a proposal, not in force.")
    review_by = c.opt_date("When it lapses.")

    class Meta(BaseModel.Meta):
        db_table = "aydlette_vdr__check_vector"

    def get_name(self) -> str:
        return f"Check vector {self.check_id}"

    def __str__(self) -> str:
        return self.get_name()
