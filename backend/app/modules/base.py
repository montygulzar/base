"""Module contract. Each module is a collector that returns a list of
Findings plus optional graph Entities / Relationships. Modules never
fabricate data — if a source is unconfigured, they simply skip it and
emit a `source_unavailable` finding.
"""
from __future__ import annotations
from dataclasses import dataclass, field
from typing import Any, Callable, Awaitable

REGISTRY: dict[str, "Module"] = {}


@dataclass
class Finding:
    source: str
    kind: str
    data: dict[str, Any]
    confidence: float = 0.6


@dataclass
class Entity:
    type: str
    value: str
    attributes: dict[str, Any] = field(default_factory=dict)
    confidence: float = 0.7


@dataclass
class Relationship:
    src_type: str
    src_value: str
    dst_type: str
    dst_value: str
    type: str
    source: str = ""
    confidence: float = 0.7
    evidence: dict[str, Any] = field(default_factory=dict)


@dataclass
class CollectionResult:
    findings: list[Finding] = field(default_factory=list)
    entities: list[Entity] = field(default_factory=list)
    relationships: list[Relationship] = field(default_factory=list)


Collector = Callable[[str, "RunContext"], Awaitable[CollectionResult]]


@dataclass
class RunContext:
    investigation_id: str
    subject_id: str
    settings: Any


@dataclass
class Module:
    key: str                 # e.g. "domain"
    name: str                # display
    subject_types: list[str] # subject kinds it accepts
    run: Collector
    description: str = ""


def register(m: Module) -> Module:
    REGISTRY[m.key] = m
    return m
