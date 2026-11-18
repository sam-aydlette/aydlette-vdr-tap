"""Write this method's results as fedramp_20x_vdr evaluations of scheme `aydlette` (vdr_bridge.py).

Runs the same evaluation as the `aydlette-pain` Search, over every declaration and finding on the grid, without a FedRAMP
class (IRV, LEV and PAIN do not depend on it). The governed profile is `aydlette-starter` unless the environment sets
AYDLETTE_VDR_PROFILE. Run it after the observers.
"""

from __future__ import annotations

import os
from datetime import UTC, datetime

from tap_cares.collectors import CollectorBase

from tap_grid.models import Entity

from ...method.reconcile import ComponentState
from ...searches.pain import evaluate_rows
from ...vdr_bridge import build_evaluations

PROFILE_ENV = "AYDLETTE_VDR_PROFILE"
_SITE_STARTED = "a1e0"
_SITE_DONE = "a1e1"
_SITE_NOTHING = "a1e2"


class VdrEvaluationsCollector(CollectorBase):
    """Turns aydlette_vdr's evaluation into fedramp_20x_vdr evaluations, scheme `aydlette`."""

    def run(self) -> None:
        profile_id = os.environ.get(PROFILE_ENV, "aydlette-starter")
        self.record_info(_SITE_STARTED, "RUN_STARTED", f"Evaluating with profile {profile_id}.")
        self.declare_no_surfaces()
        now = datetime.now(UTC)
        states: dict[str, ComponentState] = {}
        rows, block = evaluate_rows(
            {"profile_id": profile_id, "now": now.isoformat()}, deadlines=False, states_sink=states
        )
        if not rows:
            self.summary = "No open findings: nothing to evaluate."
            self.record_info(_SITE_NOTHING, "NOTHING_TO_DO", self.summary)
            return
        names = {str(k): v for k, v in Entity.objects.filter(pk__in=sorted(states)).values_list("pk", "name")}
        doc, counts = build_evaluations(rows, states, block["profile"], now, names)
        self.submit_grift(doc)
        self.summary = (
            f"{counts['evaluations']} findings evaluated (scheme aydlette): {counts['irv']} IRV, {counts['lev']} LEV; "
            f"{counts['backed_unreachable']} not internet-reachable with reconciliation evidence."
        )
        self.record_info(_SITE_DONE, "BATCH_SUBMITTED", self.summary, message_data=counts)
