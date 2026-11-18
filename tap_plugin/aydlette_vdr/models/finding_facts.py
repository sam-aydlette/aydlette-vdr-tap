"""Finding facts: what the method reads about a finding that compliance_core does not carry."""

from typing import Any, ClassVar

from tap_grid.models import BaseModel

from . import _common as c


class FindingFacts(BaseModel):
    """The scanner's severity and access data, SSVC values with their source (REQ-LEV-5), fix state (REQ-VD-1) and the
    first evaluation time (REQ-DLN-1) of one finding. Every field may be null, and null reads as the worst case.
    """

    ENTITY_TYPE: ClassVar[str] = "aydlette_vdr__finding_facts"
    NATURAL_KEY: ClassVar[tuple[str, ...]] = ("source", "facts_key")
    ENTITY_NAME: ClassVar[str] = "Finding Facts"
    ENTITY_DESCRIPTION: ClassVar[str] = (
        "Scanner severity and access data, SSVC decision points with their source, fix state and first evaluation of a "
        "finding, as the vulnerability-evidence method reads them."
    )
    ENTITY_ICON: ClassVar[str] = "facts"
    DEFAULT_DIMENSIONS: ClassVar[dict[str, str]] = c.DIMENSIONS
    OUTBOUND_EDGES: ClassVar[list[dict[str, Any]]] = [
        {
            "nodes": [{"type": "compliance_core__compliance_finding"}],
            "edges": [{"type": "DESCRIBES_FINDING__aydlette_vdr"}],
        }
    ]
    INBOUND_EDGES: ClassVar[list[dict[str, Any]]] = []

    FIELD_CRUD_SCHEMA: ClassVar[dict[str, Any]] = {
        "source": {"type": "string", "minLength": 1, "maxLength": 128},
        "facts_key": {"type": "string", "minLength": 1, "maxLength": 512},
        "scanner_severity": c.OPT_STR,
        "access_network": c.OPT_BOOL,
        "access_privileges": c.OPT_BOOL,
        "access_user_interaction": c.OPT_BOOL,
        "exploitation_observed": c.BOOL,
        "ssvc_exploitation": c.enum("none", "poc", "active"),
        "ssvc_automatable": c.enum("yes", "no"),
        "ssvc_technical_impact": c.enum("partial", "total"),
        "ssvc_source": c.OPT_STR,
        "ssvc_recorded_at": c.OPT_DATETIME,
        "fix_state": c.enum("available", "none_planned", "pending"),
        "deployed_version": c.OPT_STR,
        "first_evaluated_at": c.OPT_DATETIME,
        "non_machine": c.BOOL,
        "prediction_model": c.OPT_STR,
    }
    FIELD_VALIDATION_SCHEMA: ClassVar[dict[str, Any]] = c.validation(FIELD_CRUD_SCHEMA)
    CREATE_REQUIRED: ClassVar[list[str]] = ["source", "facts_key"]

    source = c.key(128, "Who recorded the facts. Half of the identity.")
    facts_key = c.key(512, "The source's own key for the finding. Other half.")
    scanner_severity = c.opt_char(32, "The scanner's severity label, for the published fallback (REQ-PAI-7).")
    access_network = c.opt_bool("Exploitable over the network, by the scanner, where there is no vector.")
    access_privileges = c.opt_bool("Needs privileges, by the scanner, where there is no vector.")
    access_user_interaction = c.opt_bool("Needs a user to act, by the scanner, where there is no vector.")
    exploitation_observed = c.flag("Threat intelligence or incident response saw it exploited.")
    ssvc_exploitation = c.opt_char(8, "SSVC Exploitation: none, poc or active. Null = not recorded.")
    ssvc_automatable = c.opt_char(4, "SSVC Automatable: yes or no. Null = not recorded (read as yes, VER-EVA-AIA).")
    ssvc_technical_impact = c.opt_char(8, "SSVC Technical Impact: partial or total. Null = not recorded.")
    ssvc_source = c.opt_char(255, "Where the SSVC values came from (REQ-LEV-5).")
    ssvc_recorded_at = c.opt_datetime("When the SSVC values were recorded.")
    fix_state = c.opt_char(16, "available, none_planned or pending. Null = unknown, which counts as available.")
    deployed_version = c.opt_char(128, "The deployed version, which a VEX false positive must cover (T69).")
    first_evaluated_at = c.opt_datetime("First evaluation; the clock's start. Null = detection (same pass).")
    non_machine = c.flag("The finding concerns a process that touches no machine-based resource: NIRV (T32).")
    prediction_model = c.opt_char(64, "The exploit-prediction model version (REQ-LEV-2).")

    class Meta(BaseModel.Meta):
        db_table = "aydlette_vdr__finding_facts"

    def get_name(self) -> str:
        return f"Facts {self.facts_key}"

    def __str__(self) -> str:
        return self.get_name()
