from datetime import datetime, timezone
from sqlalchemy import Column, Integer, String, DateTime, Float, Text, ForeignKey, Boolean
from sqlalchemy.orm import relationship
from .db import Base

def now_utc():
    return datetime.now(timezone.utc)

class Event(Base):
    __tablename__ = "events"
    id = Column(Integer, primary_key=True)
    ts = Column(DateTime(timezone=True), default=now_utc, index=True)
    source = Column(String(64), default="generic", index=True)
    event_type = Column(String(96), default="event", index=True)
    severity = Column(String(16), default="info", index=True)
    asset = Column(String(160), nullable=True, index=True)
    user = Column(String(160), nullable=True, index=True)
    src_ip = Column(String(64), nullable=True, index=True)
    dst_ip = Column(String(64), nullable=True, index=True)
    dst_port = Column(Integer, nullable=True)
    domain = Column(String(255), nullable=True, index=True)
    file_hash = Column(String(128), nullable=True, index=True)
    bytes_out = Column(Integer, nullable=True)
    message = Column(Text, default="")
    raw_json = Column(Text, default="{}")

class Alert(Base):
    __tablename__ = "alerts"
    id = Column(Integer, primary_key=True)
    created_at = Column(DateTime(timezone=True), default=now_utc, index=True)
    title = Column(String(255), index=True)
    severity = Column(String(16), index=True)
    confidence = Column(Float, default=0.7)
    rule_id = Column(String(96), index=True)
    mitre_tactic = Column(String(96), nullable=True)
    mitre_technique = Column(String(96), nullable=True)
    asset = Column(String(160), nullable=True, index=True)
    user = Column(String(160), nullable=True, index=True)
    src_ip = Column(String(64), nullable=True, index=True)
    dst_ip = Column(String(64), nullable=True, index=True)
    status = Column(String(32), default="new", index=True)
    analyst = Column(String(160), nullable=True, index=True)
    description = Column(Text, default="")
    event_id = Column(Integer, ForeignKey("events.id"), nullable=True)
    event = relationship("Event")

class Incident(Base):
    __tablename__ = "incidents"
    id = Column(Integer, primary_key=True)
    created_at = Column(DateTime(timezone=True), default=now_utc, index=True)
    updated_at = Column(DateTime(timezone=True), default=now_utc, index=True)
    title = Column(String(255))
    severity = Column(String(16), index=True)
    status = Column(String(32), default="new", index=True)
    risk_score = Column(Float, default=50)
    asset = Column(String(160), nullable=True, index=True)
    user = Column(String(160), nullable=True, index=True)
    owner = Column(String(160), nullable=True)
    summary = Column(Text, default="")

class IncidentAlert(Base):
    __tablename__ = "incident_alerts"
    id = Column(Integer, primary_key=True)
    incident_id = Column(Integer, ForeignKey("incidents.id"), index=True)
    alert_id = Column(Integer, ForeignKey("alerts.id"), index=True)

class IOC(Base):
    __tablename__ = "iocs"
    id = Column(Integer, primary_key=True)
    created_at = Column(DateTime(timezone=True), default=now_utc)
    kind = Column(String(32), index=True)
    value = Column(String(255), unique=True, index=True)
    reputation = Column(String(32), default="malicious")
    confidence = Column(Float, default=0.8)
    source = Column(String(128), default="local")
    active = Column(Boolean, default=True)
    notes = Column(Text, default="")

class Case(Base):
    __tablename__ = "cases"
    id = Column(Integer, primary_key=True)
    created_at = Column(DateTime(timezone=True), default=now_utc)
    title = Column(String(255))
    priority = Column(String(16), default="medium", index=True)
    status = Column(String(32), default="new", index=True)
    owner = Column(String(160), nullable=True)
    incident_id = Column(Integer, ForeignKey("incidents.id"), nullable=True)
    notes = Column(Text, default="")

class Analyst(Base):
    __tablename__ = "analysts"
    id = Column(Integer, primary_key=True)
    name = Column(String(160), unique=True)
    tier = Column(String(32), default="Tier 1")
    status = Column(String(32), default="online")
