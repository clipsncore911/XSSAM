from __future__ import annotations

from datetime import UTC, datetime
from enum import Enum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field


class ParameterLocation(str, Enum):
    QUERY = "QUERY"
    PATH = "PATH"
    FORM = "FORM"
    BODY = "BODY"
    HEADER = "HEADER"
    COOKIE = "COOKIE"
    FRAGMENT = "FRAGMENT"
    JAVASCRIPT = "JAVASCRIPT"


class FindingStatus(str, Enum):
    REFLECTED = "REFLECTED"
    POTENTIAL = "POTENTIAL"
    CONFIRMED = "CONFIRMED"
    NOT_VULNERABLE = "NOT_VULNERABLE"


class XSSAMModel(BaseModel):
    model_config = ConfigDict(validate_assignment=True)


class TargetURL(XSSAMModel):
    url: str
    domain: str
    protocol: str


class Parameter(XSSAMModel):
    name: str
    value: str = ""
    location: ParameterLocation
    discovery_source: str = "unknown"
    method: str = "GET"
    action_url: str | None = None
    first_seen: datetime = Field(default_factory=lambda: datetime.now(UTC))
    occurrences: int = 1


class Payload(XSSAMModel):
    payload_id: str
    text: str
    # Payload YAML files used to omit this required field, crashing the scanner.
    context: str = "html"
    purpose: str = ""
    encoding: str = "raw"
    risk: str = "low"


class ProofOfConcept(XSSAMModel):
    method: str = "GET"
    url: str
    data: dict[str, str] | None = None
    headers: dict[str, str] = Field(default_factory=dict)
    cookies: dict[str, str] = Field(default_factory=dict)


class Finding(XSSAMModel):
    finding_id: str
    target_url: str
    parameter: Parameter
    payload: Payload
    status: FindingStatus = FindingStatus.POTENTIAL
    context: str = "html"
    proof_url: str | None = None
    rendered_payload: str = ""
    marker: str = ""
    poc: ProofOfConcept | None = None
    evidence: dict[str, Any] = Field(default_factory=dict)
    timestamp: datetime = Field(default_factory=lambda: datetime.now(UTC))
    severity: str = "Medium"
    confidence: str = "Low"
