"""Disposition: a decision about one or more findings, with who decided it and when it must be reviewed (REQ-DSP-1)."""

from typing import Any, ClassVar

from tap_grid.models import BaseModel

from ..method.evaluate import KINDS
from . import _common as c


class Disposition(BaseModel):
    """One decision record. It points at every finding it covers (`DISPOSES_FINDING`), so one record can cover one advisory
    across many components (REQ-LEV-4, T49). A record past `review_by` is absent (REQ-DSP-2, T16); no record pauses the
    clock (REQ-DLN-1).
    """

    ENTITY_TYPE: ClassVar[str] = "aydlette_vdr__disposition"
    NATURAL_KEY: ClassVar[tuple[str, ...]] = ("source", "disposition_key")
    ENTITY_NAME: ClassVar[str] = "Disposition"
    ENTITY_DESCRIPTION: ClassVar[str] = (
        "A decision about findings: false positive, mitigation, narrowing, deflection, LEV override, vendor dependency, "
        "risk acceptance or operational requirement, with decided_by, decided_on and review_by."
    )
    ENTITY_ICON: ClassVar[str] = "disposition"
    DEFAULT_DIMENSIONS: ClassVar[dict[str, str]] = c.DIMENSIONS
    OUTBOUND_EDGES: ClassVar[list[dict[str, Any]]] = [
        {
            "nodes": [{"type": "compliance_core__compliance_finding"}],
            "edges": [{"type": "DISPOSES_FINDING__aydlette_vdr"}],
        }
    ]
    INBOUND_EDGES: ClassVar[list[dict[str, Any]]] = []

    FIELD_CRUD_SCHEMA: ClassVar[dict[str, Any]] = {
        "source": {"type": "string", "minLength": 1, "maxLength": 128},
        "disposition_key": {"type": "string", "minLength": 1, "maxLength": 512},
        "kind": c.enum(*KINDS, nullable=False),
        "reason": c.OPT_STR,
        "decided_by": c.OPT_STR,
        "decided_on": c.OPT_DATE,
        "review_by": c.OPT_DATE,
        "control_id": c.OPT_STR,
        "tested": c.BOOL,
        "pain_after": c.enum("N0", "N1", "N2", "N3", "N4", "N5"),
        "vex_version": c.OPT_STR,
        "vex_withdrawn": c.BOOL,
    }
    FIELD_VALIDATION_SCHEMA: ClassVar[dict[str, Any]] = c.validation(FIELD_CRUD_SCHEMA)
    CREATE_REQUIRED: ClassVar[list[str]] = ["source", "disposition_key", "kind"]

    source = c.key(128, "Who recorded the decision. Half of the identity.")
    disposition_key = c.key(512, "The source's own id for the decision (a decision record id). Other half.")
    kind = c.key(32, "What was decided; see KINDS in method/evaluate.py.")
    reason = c.opt_char(2000, "Why. Null is published as not recorded.")
    decided_by = c.opt_char(255, "Who decided. Null is published as not recorded.")
    decided_on = c.opt_date("When it was decided.")
    review_by = c.opt_date("When it lapses. Null or past = not in force (REQ-DSP-1, -2).")
    control_id = c.opt_char(512, "A mitigation's control, by inventory identifier (REQ-MIT-1).")
    tested = c.flag("A deflection was verified by an outside-in triggering-payload test (REQ-IRV-5).")
    pain_after = c.opt_char(2, "A partial mitigation's reduced rating (FRD-PMV).")
    vex_version = c.opt_char(128, "The product version a VEX statement covers (REQ-DSP-5).")
    vex_withdrawn = c.flag("The VEX statement behind a false positive was changed or withdrawn (T70).")

    class Meta(BaseModel.Meta):
        db_table = "aydlette_vdr__disposition"

    def get_name(self) -> str:
        return f"{self.kind} {self.disposition_key}"

    def __str__(self) -> str:
        return self.get_name()
