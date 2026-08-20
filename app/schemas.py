from pydantic import BaseModel, Field
from typing import Optional, Any
from datetime import datetime

class LoginIn(BaseModel):
    username: str
    password: str

class EventIn(BaseModel):
    ts: Optional[datetime] = None
    source: str = "generic"
    event_type: str = "event"
    severity: str = "info"
    asset: Optional[str] = None
    user: Optional[str] = None
    src_ip: Optional[str] = None
    dst_ip: Optional[str] = None
    dst_port: Optional[int] = None
    domain: Optional[str] = None
    file_hash: Optional[str] = None
    bytes_out: Optional[int] = None
    message: str = ""
    raw: dict[str, Any] = Field(default_factory=dict)

class IOCIn(BaseModel):
    kind: str
    value: str
    reputation: str = "malicious"
    confidence: float = 0.8
    source: str = "local"
    notes: str = ""

class CaseIn(BaseModel):
    title: str
    priority: str = "medium"
    owner: Optional[str] = None
    incident_id: Optional[int] = None
    notes: str = ""
