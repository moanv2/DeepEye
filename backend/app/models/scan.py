from sqlalchemy import Column, String, Integer, DateTime, ForeignKey, Boolean
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import relationship
from datetime import datetime
import uuid

from .database import Base


class Scan(Base):
    __tablename__ = "scans"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    domain = Column(String(255), nullable=False)
    status = Column(String(20), default="pending")
    progress = Column(Integer, default=0)
    created_at = Column(DateTime, default=datetime.utcnow)
    completed_at = Column(DateTime, nullable=True)

    subdomains = relationship("Subdomain", back_populates="scan")
    endpoints = relationship("Endpoint", back_populates="scan")



class Subdomain(Base):
    __tablename__ = "subdomains"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    scan_id = Column(UUID(as_uuid=True), ForeignKey("scans.id"), nullable=False)
    subdomain = Column(String(512), nullable=False)
    ip_address = Column(String(45), nullable=True)
    host_status = Column(Integer, default=2)  # 0=dead, 1=alive, 2=unknown
    discovered_at = Column(DateTime, default=datetime.utcnow)
    asn = Column(String(20), nullable=True)
    asn_org = Column(String(225), nullable=True)

    scan = relationship("Scan", back_populates="subdomains")

class Endpoint(Base):
    __tablename__ = "endpoints"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    scan_id = Column(UUID(as_uuid=True), ForeignKey("scans.id"), nullable=False)
    url = Column(String(2048), nullable=False)
    path = Column(String(1024), nullable=True)
    method = Column(String(10), default="GET")
    status_code = Column(Integer, nullable=True)
    content_type = Column(String(255), nullable=True)
    is_sensitive = Column(Boolean, default=False)
    sensitivity_reason = Column(String(255), nullable=True)
    discovered_at = Column(DateTime, default=datetime.utcnow)

    scan = relationship("Scan", back_populates="endpoints")