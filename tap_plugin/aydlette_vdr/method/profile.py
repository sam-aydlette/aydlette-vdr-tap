"""The governed profile: every value the method lets a provider choose, and the global defaults it may deviate from.

Pure and Django-free. A profile is a plain dict (a profile node's fields, or a file). `validate` refuses one that is missing
or outside the method (REQ-GOV-1, T18), that enables half of the SSVC overlay (T68), or whose mapping onto the scale does
not cover every level the pinned rules publish (T19). `deviations` names every place a profile departs from the global
defaults, so each output can publish them (REQ-PAI-4).

What is global and never in a profile: the classification vocabulary, the fail-safe classification (REQ-PAI-6), the order
of the checks in Figure 7 and the timeframes, which are read from the rules (REQ-RUL-1).
"""

from __future__ import annotations

import copy
import hashlib
import json
from collections.abc import Iterable
from decimal import Decimal, InvalidOperation
from typing import Any

NEED_LEVELS: tuple[str, ...] = ("low", "medium", "high")
TECHNICAL_IMPACTS: tuple[str, ...] = ("partial", "total")
EFFECTS: tuple[str, ...] = ("minimal", "narrow", "disruptive", "debilitating")
SCOPES: tuple[str, ...] = ("single", "multi")
DATA_FLAGS: tuple[str, ...] = ("public", "internal", "pii", "cui")
COMBINING: tuple[str, ...] = ("decision_table", "cvss_environmental")
#: The severity fallback sets technical impact only (REQ-PAI-7). A fallback straight to the scale is not offered: it would
#: skip the classification, and with it the fail-safe for unresolved findings (REQ-PAI-6).
FALLBACK_MODES: tuple[str, ...] = ("technical_impact",)

#: The fail-safe classification (REQ-PAI-6): PII, CUI, Mission Critical and multi-agency.
FAIL_SAFE_CLASSIFICATION: dict[str, Any] = {"data": ("pii", "cui"), "mission_critical": True, "agency_scope": "multi"}

#: The global defaults (the paper's Impact section). A profile that changes any of them publishes the change.
GLOBAL_DEFAULTS: dict[str, Any] = {
    "needs": {
        "public": {"c": "low", "i": "low", "a": "low"},
        "internal": {"c": "medium", "i": "medium", "a": "medium"},
        "pii": {"c": "high", "i": "medium", "a": "medium"},
        "cui": {"c": "high", "i": "medium", "a": "medium"},
        "mission_critical": {"i": "high", "a": "high"},
    },
    "effect_table": {
        "low": {"partial": "minimal", "total": "narrow"},
        "medium": {"partial": "narrow", "total": "disruptive"},
        "high": {"partial": "disruptive", "total": "debilitating"},
    },
    "scale": {
        "minimal": {"single": "N1", "multi": "N1"},
        "narrow": {"single": "N2", "multi": "N2"},
        "disruptive": {"single": "N3", "multi": "N4"},
        "debilitating": {"single": "N4", "multi": "N5"},
    },
    "combining": "decision_table",
    "severity_fallback": {
        "mode": "technical_impact",
        "map": {"critical": "total", "high": "partial", "medium": "partial", "low": "partial", "info": "partial"},
    },
    "ssvc_overlay": {"automatable_floor": False, "poc_check": False},
}

#: The parameters of the CVSS-environmental combining function, when a profile chooses it (a published deviation).
CVSS_ENVIRONMENTAL_KEYS: tuple[str, ...] = ("impact_weights", "requirement_weights", "isc_cap", "word_thresholds")


class ProfileError(ValueError):
    """A governed profile the method refuses to run on (the build fails, REQ-GOV-1)."""


def merged(profile: dict[str, Any]) -> dict[str, Any]:
    """The profile with every global default it leaves out filled in."""
    out = copy.deepcopy(GLOBAL_DEFAULTS)
    for key, value in profile.items():
        out[key] = copy.deepcopy(value)
    return out


def digest(profile: dict[str, Any]) -> str:
    """sha256 of the profile's canonical JSON, recorded in every output beside its version (REQ-GOV-1)."""
    return hashlib.sha256(json.dumps(profile, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def _need(value: Any, where: str) -> None:
    if value not in NEED_LEVELS:
        raise ProfileError(f"{where} must be one of {', '.join(NEED_LEVELS)}, not {value!r}")


def _number(value: Any) -> Decimal:
    """A profile number: an int, a float, or a decimal string. A string keeps a boundary exact, which matters when a
    worked example sits on it (stackArmor's example 5 has U exactly 0.28)."""
    if isinstance(value, bool) or not isinstance(value, int | float | str):
        raise ValueError(f"{value!r} is not a number")
    try:
        return Decimal(str(value))
    except InvalidOperation:
        raise ValueError(f"{value!r} is not a number") from None


def validate(profile: dict[str, Any] | None, rules_levels: Iterable[str]) -> dict[str, Any]:
    """Return the merged profile, or raise `ProfileError` naming the first thing wrong with it.

    `rules_levels` is the impact scale the pinned rules publish, lowest first (for example N1 to N5); the lowest level a
    fully mitigated finding takes (N0) is the method's and needs no mapping.
    """
    if not profile:
        raise ProfileError("no governed profile: the method does not run without one (REQ-GOV-1, T18)")
    for key in ("profile_id", "version"):
        if not isinstance(profile.get(key), str) or not profile[key].strip():
            raise ProfileError(f"the profile has no {key}")
    p = merged(profile)

    theta = p.get("theta")
    if isinstance(theta, bool) or not isinstance(theta, int | float) or not 0 < theta <= 1:
        raise ProfileError("theta is governed and has no default: set a number in (0, 1] (REQ-LEV-2)")
    if not isinstance(p.get("theta_rationale"), str) or not p["theta_rationale"].strip():
        raise ProfileError("theta must be published with its rationale (REQ-LEV-2)")

    needs = p["needs"]
    for flag in (*DATA_FLAGS, "mission_critical"):
        entry = needs.get(flag)
        if not isinstance(entry, dict):
            raise ProfileError(f"needs.{flag} is missing")
        props = ("c", "i", "a") if flag != "mission_critical" else tuple(entry)
        for prop in props:
            if prop not in ("c", "i", "a"):
                raise ProfileError(f"needs.{flag} names {prop!r}, not one of c, i, a")
            _need(entry.get(prop), f"needs.{flag}.{prop}")

    if p["combining"] not in COMBINING:
        raise ProfileError(f"combining must be one of {', '.join(COMBINING)}")
    for need in NEED_LEVELS:
        for ti in TECHNICAL_IMPACTS:
            if p["effect_table"].get(need, {}).get(ti) not in EFFECTS:
                raise ProfileError(f"effect_table.{need}.{ti} must be one of {', '.join(EFFECTS)}")

    levels = list(rules_levels)
    mapped: set[str] = set()
    for effect in EFFECTS:
        for scope in SCOPES:
            level = p["scale"].get(effect, {}).get(scope)
            if level not in levels:
                raise ProfileError(
                    f"scale.{effect}.{scope} is {level!r}, not a level of the pinned rules ({', '.join(levels)})"
                )
            mapped.add(level)
    unmapped = [lv for lv in levels if lv not in mapped]
    if unmapped:
        raise ProfileError(f"the scale mapping never places a finding at {', '.join(unmapped)}: cover it (T19)")

    fb = p["severity_fallback"]
    if fb.get("mode") not in FALLBACK_MODES:
        raise ProfileError(f"severity_fallback.mode must be one of {', '.join(FALLBACK_MODES)}")
    allowed = TECHNICAL_IMPACTS
    if not isinstance(fb.get("map"), dict) or not fb["map"]:
        raise ProfileError("severity_fallback.map must name at least one scanner severity")
    for sev, value in fb["map"].items():
        if value not in allowed:
            raise ProfileError(f"severity_fallback.map.{sev} must be one of {', '.join(allowed)}")

    overlay = p["ssvc_overlay"]
    if bool(overlay.get("automatable_floor")) != bool(overlay.get("poc_check")):
        raise ProfileError("the SSVC overlay applies both of its changes or neither (REQ-LEV-8, T68)")

    if p["combining"] == "cvss_environmental":
        env = p.get("cvss_environmental")
        if not isinstance(env, dict) or any(k not in env for k in CVSS_ENVIRONMENTAL_KEYS):
            raise ProfileError(f"cvss_environmental needs {', '.join(CVSS_ENVIRONMENTAL_KEYS)}")
        try:
            iw = {k: _number(v) for k, v in env["impact_weights"].items()}
            rw = {k: _number(v) for k, v in env["requirement_weights"].items()}
            t = {k: _number(v) for k, v in env["word_thresholds"].items()}
            cap = _number(env["isc_cap"])
        except (ValueError, KeyError, AttributeError) as exc:
            raise ProfileError(f"cvss_environmental: {exc}") from None
        if not 0 <= iw["none"] < iw["low"] < iw["high"] <= 1:
            raise ProfileError("cvss_environmental.impact_weights must satisfy 0 <= none < low < high <= 1")
        if not 0 < rw["low"] <= rw["medium"] <= rw["high"]:
            raise ProfileError("cvss_environmental.requirement_weights must satisfy 0 < low <= medium <= high")
        if iw["high"] * rw["high"] > 1:
            raise ProfileError("impact_weights.high times requirement_weights.high must not exceed 1")
        if not 0 < t["minimal_to_narrow"] < t["narrow_to_disruptive"] < t["disruptive_to_debilitating"] <= 1:
            raise ProfileError("cvss_environmental.word_thresholds must rise within (0, 1]")
        if not 0 < cap <= 1:
            raise ProfileError("cvss_environmental.isc_cap must be in (0, 1]")

    fresh = p.get("observer_freshness_hours", 24)
    if isinstance(fresh, bool) or not isinstance(fresh, int) or not 1 <= fresh <= 24:
        raise ProfileError("observer_freshness_hours must be 1 to 24: observers run at least daily (REQ-IRV-3)")
    margin = p.get("likely_overdue_margin_hours", 0)
    if isinstance(margin, bool) or not isinstance(margin, int) or margin < 0:
        raise ProfileError("likely_overdue_margin_hours must be a whole number of hours, at least 0 (REQ-DLN-2)")
    return p


def deviations(profile: dict[str, Any]) -> list[str]:
    """Each place the merged profile departs from a global default, as a dotted path (REQ-PAI-4)."""
    p = merged(profile)
    out: list[str] = []

    def walk(default: Any, actual: Any, path: str) -> None:
        if isinstance(default, dict) and isinstance(actual, dict):
            for key in sorted(set(default) | set(actual)):
                walk(default.get(key), actual.get(key), f"{path}.{key}" if path else key)
        elif default != actual:
            out.append(path)

    for key, default in GLOBAL_DEFAULTS.items():
        walk(default, p[key], key)
    return out
