"""The Searches' input schemas. Pure, so the shipped Search nodes (grift/searches.grift.json) are tested against them."""

from __future__ import annotations

from typing import Any

DEFAULT_MAX_RESULTS = 1000
MAX_RESULTS = 5000

_COMMON: dict[str, Any] = {
    "profile_id": {"type": "string", "minLength": 1, "default": "aydlette-starter", "description": "Governed profile."},
    "declaration_source": {"type": "string", "description": "Read only the declarations of this source."},
    "now": {"type": "string", "format": "date-time", "description": "Evaluate as of this time (default: now)."},
    "max_results": {"type": "integer", "minimum": 1, "maximum": MAX_RESULTS, "default": DEFAULT_MAX_RESULTS},
}

INPUT_SCHEMA: dict[str, Any] = {
    "type": "object",
    "additionalProperties": False,
    "required": ["fedramp_class"],
    "properties": {
        "fedramp_class": {"type": "string", "enum": ["a", "b", "c", "d"], "description": "The offering's class."},
        **_COMMON,
        "finding_source": {"type": "string", "description": "Evaluate only the findings of this source."},
        "entity_id": {"type": "string", "description": "One finding."},
    },
}

RECONCILE_INPUT_SCHEMA: dict[str, Any] = {
    "type": "object",
    "additionalProperties": False,
    "required": [],
    "properties": dict(_COMMON),
}

#: The Search nodes the plugin ships: runner key -> (name, description, input schema).
SEARCHES: dict[str, tuple[str, str, dict[str, Any]]] = {
    "aydlette-pain": (
        "Aydlette VDR: findings",
        "One row per open finding: component, IRV, LEV and PAIN with their bases, dispositions, clock, gates and queue.",
        INPUT_SCHEMA,
    ),
    "aydlette-summary": (
        "Aydlette VDR: summary",
        "Counts by rating, group and state; gates G1 to G5 and G7; the decision queue and its rates.",
        INPUT_SCHEMA,
    ),
    "aydlette-reconcile": (
        "Aydlette VDR: reconciliation",
        "One row per declared component: declared intent against what the observers saw (Figure 6), G4, G5, G7.",
        RECONCILE_INPUT_SCHEMA,
    ),
}
