"""What the method reads from a severity vector (CVSS 3.0, 3.1 or 4.0). Pure and Django-free.

Three readings, and nothing else, come from the vector:

* the access facts the FRD-LEV floor needs: reachable over the network, needs no privileges, needs no user interaction
  (Figure 7);
* the properties the flaw touches, so it is weighed only on those (Impact, "each flaw is weighed only on the properties it
  affects");
* whether confidentiality and integrity are both High, which makes the technical impact total (REQ-PAI-7).

A vector that is missing, malformed or missing a Base metric is no vector: the caller falls back as REQ-PAI-7 says, and an
absent reading is never taken as evidence of safety.
"""

from __future__ import annotations

from dataclasses import dataclass

PROPERTIES: tuple[str, str, str] = ("c", "i", "a")

_CIA = "NLH"
_BASE: dict[str, dict[str, str]] = {
    "3.0": {"AV": "NALP", "AC": "LH", "PR": "NLH", "UI": "NR", "S": "UC", "C": _CIA, "I": _CIA, "A": _CIA},
    "3.1": {"AV": "NALP", "AC": "LH", "PR": "NLH", "UI": "NR", "S": "UC", "C": _CIA, "I": _CIA, "A": _CIA},
    "4.0": {
        "AV": "NALP",
        "AC": "LH",
        "AT": "NP",
        "PR": "NLH",
        "UI": "NPA",
        "VC": "HLN",
        "VI": "HLN",
        "VA": "HLN",
        "SC": "HLN",
        "SI": "HLN",
        "SA": "HLN",
    },  # fmt: skip
}
_LEVEL = {"N": "none", "L": "low", "H": "high"}


@dataclass(frozen=True)
class Vector:
    version: str
    network: bool
    privileges: bool  # True when the attack needs privileges
    user_interaction: bool  # True when the attack needs a user to act
    impact: tuple[str, str, str]  # none, low or high for C, I, A

    @property
    def affected(self) -> tuple[str, ...]:
        """The properties the flaw touches (impact other than none)."""
        return tuple(p for p, level in zip(PROPERTIES, self.impact, strict=True) if level != "none")

    @property
    def total(self) -> bool:
        """REQ-PAI-7: total when confidentiality and integrity are both High."""
        return self.impact[0] == "high" and self.impact[1] == "high"


def parse(vector: str | None) -> Vector | None:
    """The reading of a CVSS vector string, or None when it is not a complete, valid Base vector."""
    if not isinstance(vector, str) or not vector.strip():
        return None
    parts = vector.strip().split("/")
    prefix = parts[0]
    if not prefix.startswith("CVSS:"):
        return None
    version = prefix.removeprefix("CVSS:")
    required = _BASE.get(version)
    if required is None:
        return None
    metrics: dict[str, str] = {}
    for part in parts[1:]:
        key, sep, value = part.partition(":")
        if not sep or not key or key in metrics:
            return None
        metrics[key] = value
    if any(metrics.get(key, "") == "" or metrics[key] not in values for key, values in required.items()):
        return None
    keys = ("C", "I", "A") if version != "4.0" else ("VC", "VI", "VA")
    impact = tuple(_LEVEL[metrics[k]] for k in keys)
    return Vector(
        version=version,
        network=metrics["AV"] == "N",
        privileges=metrics["PR"] != "N",
        user_interaction=metrics["UI"] != "N",
        impact=impact,  # type: ignore[arg-type]
    )


def with_environmental(vector: str, modified: dict[str, str]) -> str:
    """The Base vector with this method's Environmental metrics appended (`MAV:A`, `MPR:L`), in the syntax CVSS 3.x and
    4.0 share for them. Any Environmental, Threat or Supplemental metric the record carries is dropped: it describes the
    publisher's environment, not this one, and the method never reads it."""
    parts = vector.strip().split("/")
    base = _BASE[parts[0].removeprefix("CVSS:")]
    kept = [p for p in parts[1:] if p.partition(":")[0] in base]
    return "/".join([parts[0], *kept, *(f"{k}:{v}" for k, v in modified.items())])
