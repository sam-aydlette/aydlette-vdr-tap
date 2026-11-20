"""TAP Aydlette VDR plugin AppConfig."""

from tap_plugins.base import TapPluginConfig


class AydletteVdrConfig(TapPluginConfig):
    """Seven models, seven edges, two seeds, four Search runners and one collector, which writes the method's results
    as fedramp_20x_vdr evaluations of scheme `aydlette`."""

    def ready(self) -> None:
        super().ready()
        from tap_cares.registry import register_collector

        from tap_plugin.aydlette_vdr.collectors.vdr_evaluations.collector import VdrEvaluationsCollector

        register_collector(
            key="vdr_evaluations",
            scope="aydlette_vdr",
            cls=VdrEvaluationsCollector,
            name="Aydlette VDR Evaluations",
            description=(
                "Writes the vulnerability-evidence method's IRV and LEV for every open finding as fedramp_20x_vdr "
                "evaluations of scheme aydlette, so other methods on the grid can read them. Internet unreachability is "
                "backed with evidence only when reconciliation supports it. Reads the grid; no network."
            ),
        )
