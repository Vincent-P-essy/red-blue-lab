"""Red-team scenario interface."""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass


@dataclass
class RedContext:
    base_url: str
    tcp_ports: list[int]


@dataclass
class ScenarioResult:
    attacks: int
    note: str = ""


class Scenario(ABC):
    #: short scenario id (matches the report / referee)
    name: str = "scenario"
    #: the alert type the blue team should raise for this attack
    expected_alert: str = ""
    #: the source identity this attack presents (referee matches the alert on it)
    source: str = ""

    @abstractmethod
    def run(self, ctx: RedContext) -> ScenarioResult: ...
