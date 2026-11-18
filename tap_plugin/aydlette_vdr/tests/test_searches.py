"""The shipped Search nodes match the runners' schemas and keys."""

from __future__ import annotations

import json
import tomllib
from pathlib import Path

from tap_plugin.aydlette_vdr.searches.schema import SEARCHES

PKG = Path(__file__).resolve().parents[1]


def shipped() -> dict[str, dict]:
    doc = json.loads((PKG / "grift" / "searches.grift.json").read_text())
    return {n["node"]["definition"]["runner_key"].split(":")[1]: n["node"] for n in doc["batches"][0]["nodes"]}


def test_every_runner_ships_a_search_node_with_its_schema():
    nodes = shipped()
    assert set(nodes) == set(SEARCHES)
    for key, (name, _desc, schema) in SEARCHES.items():
        assert nodes[key]["input_schema"] == schema and nodes[key]["name"] == name


def test_runner_keys_are_declared_in_the_manifest():
    manifest = tomllib.loads((PKG / "tap-plugin.toml").read_text())
    assert set(manifest["searches"]) == set(SEARCHES)
    for node in shipped().values():
        module, _, runner = node["definition"]["runner_key"].partition(":")
        assert manifest["searches"][runner].startswith(module + ".")
