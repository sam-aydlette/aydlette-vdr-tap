"""Shared field helpers for the plugin's models. Every value a method input can lack is nullable: null is unobserved, and
the method reads it as the worst case."""

from __future__ import annotations

from typing import Any

from django.db import models

DIMENSIONS: dict[str, str] = {"fedramp.rule": "vdr"}

STR: dict[str, Any] = {"type": "string", "minLength": 1}
OPT_STR: dict[str, Any] = {"type": ["string", "null"]}
OPT_BOOL: dict[str, Any] = {"type": ["boolean", "null"]}
BOOL: dict[str, Any] = {"type": "boolean"}
OPT_DATE: dict[str, Any] = {"type": ["string", "null"], "format": "date"}
OPT_DATETIME: dict[str, Any] = {"type": ["string", "null"], "format": "date-time"}


def enum(*values: str, nullable: bool = True) -> dict[str, Any]:
    return {"type": ["string", "null"] if nullable else "string", "enum": [*values, *([None] if nullable else [])]}


def validation(schema: dict[str, Any]) -> dict[str, Any]:
    return {name: {"validation": "jsonschema", "schema": s} for name, s in schema.items()}


def key(max_length: int = 512, help_text: str = "") -> models.CharField[Any, Any]:
    return models.CharField(max_length=max_length, blank=True, default="", db_index=True, help_text=help_text)


def text(help_text: str = "") -> models.TextField[Any, Any]:
    return models.TextField(blank=True, default="", help_text=help_text)


def opt_char(max_length: int, help_text: str) -> models.CharField[Any, Any]:
    return models.CharField(max_length=max_length, null=True, blank=True, default=None, help_text=help_text)  # noqa: DJ001


def opt_bool(help_text: str) -> models.BooleanField[Any, Any]:
    return models.BooleanField(null=True, blank=True, default=None, help_text=help_text)


def flag(help_text: str) -> models.BooleanField[Any, Any]:
    return models.BooleanField(default=False, help_text=help_text)


def opt_date(help_text: str) -> models.DateField[Any, Any]:
    return models.DateField(null=True, blank=True, default=None, help_text=help_text)


def opt_datetime(help_text: str) -> models.DateTimeField[Any, Any]:
    return models.DateTimeField(null=True, blank=True, default=None, help_text=help_text)
