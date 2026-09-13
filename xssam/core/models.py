from pydantic import BaseModel, Field
from typing import List, Optional, Dict, Any
from datetime import datetime
from enum import Enum

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

class TargetURL(BaseModel):
    url: str
    domain: str
    protocol: str

class Parameter(BaseModel):
    name: str
    value: str
    location: ParameterLocation
    discovery_source: str
    first_seen: datetime = Field(default_factory=datetime.now)
    occurrences: int = 1

class Payload(BaseModel):
    payload_id: str
    text: str
    context: str
    purpose: str
    encoding: str = "raw"
    risk: str = "low"

class Finding(BaseModel):
    finding_id: str
    target_url: str
    parameter: Parameter
    payload: Payload
    status: FindingStatus
    context: str
    proof_url: Optional[str] = None
    evidence: Dict[str, Any] = Field(default_factory=dict)
    timestamp: datetime = Field(default_factory=datetime.now)
    severity: str = "Medium"
    confidence: str = "Low"
