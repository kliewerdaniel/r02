"""
QASP Database Models for persistent key and audit storage.
Uses SQLAlchemy for ORM with support for PostgreSQL and SQLite.
"""

from sqlalchemy import Column, Integer, String, Text, DateTime, Boolean, ForeignKey, Index
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.sql import func

Base = declarative_base()


class Tenant(Base):
    """
    Tenant model for multi-tenant key isolation.
    Each tenant has isolated key material and audit logs.
    """
    __tablename__ = 'tenants'

    id = Column(String(64), primary_key=True, index=True)  # tenant_id (e.g., "default", "tenant1")
    name = Column(String(255), nullable=False, unique=True)
    description = Column(Text, nullable=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), onupdate=func.now())
    is_active = Column(Boolean, default=True, nullable=False)

    def __repr__(self):
        return f"<Tenant(id='{self.id}', name='{self.name}', active={self.is_active})>"


class KeyRecord(Base):
    """
    Key record model for persistent encrypted key storage.
    Keys are stored as AES-GCM encrypted blobs in the database.
    """
    __tablename__ = 'key_records'

    id = Column(Integer, primary_key=True, autoincrement=True)
    tenant_id = Column(String(64), ForeignKey('tenants.id'), nullable=False, index=True)
    key_id = Column(String(255), nullable=False, index=True)  # unique key identifier
    key_type = Column(String(50), nullable=False)  # e.g., "server_private", "session"
    key_algorithm = Column(String(50), nullable=False)  # e.g., "Kyber512", "Dilithium3"
    encrypted_key_data = Column(Text, nullable=False)  # AES-GCM encrypted key material (base64)
    key_nonce = Column(String(32), nullable=False)  # GCM nonce (hex)
    key_tag = Column(String(32), nullable=False)  # GCM authentication tag (hex)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), onupdate=func.now())
    expires_at = Column(DateTime(timezone=True), nullable=True)
    is_active = Column(Boolean, default=True, nullable=False)

    # Composite index for efficient tenant+key lookup
    __table_args__ = (
        Index('ix_tenant_key', 'tenant_id', 'key_id', unique=True),
        Index('ix_tenant_type', 'tenant_id', 'key_type'),
    )

    def __repr__(self):
        return f"<KeyRecord(tenant='{self.tenant_id}', key_id='{self.key_id}', type='{self.key_type}', active={self.is_active})>"


class AuditEvent(Base):
    """
    Audit event model for security auditing and compliance.
    All cryptographic operations are logged for formal verification.
    """
    __tablename__ = 'audit_events'

    id = Column(Integer, primary_key=True, autoincrement=True)
    tenant_id = Column(String(64), ForeignKey('tenants.id'), nullable=False, index=True)
    event_type = Column(String(50), nullable=False)  # e.g., "key_generation", "handshake_init", "key_rotation"
    event_data = Column(Text, nullable=False)  # JSON serialized event data
    client_id = Column(String(255), nullable=True)  # if applicable
    session_id = Column(String(255), nullable=True)  # if applicable
    key_id = Column(String(255), nullable=True)  # referenced key
    success = Column(Boolean, default=False, nullable=False)
    error_message = Column(Text, nullable=True)
    ip_address = Column(String(45), nullable=True)  # IPv4/IPv6
    user_agent = Column(Text, nullable=True)
    timestamp = Column(DateTime(timezone=True), server_default=func.now())
    qasp_version = Column(String(10), default="v1.0", nullable=False)

    # Indexes for common audit queries
    __table_args__ = (
        Index('ix_tenant_timestamp', 'tenant_id', 'timestamp'),
        Index('ix_tenant_event', 'tenant_id', 'event_type'),
    )

    def __repr__(self):
        return f"<AuditEvent(tenant='{self.tenant_id}', type='{self.event_type}', success={self.success}, ts={self.timestamp})>"


class KeyRotationRecord(Base):
    """
    Key rotation record for tracking key lifecycle management.
    """
    __tablename__ = 'key_rotation_records'

    id = Column(Integer, primary_key=True, autoincrement=True)
    tenant_id = Column(String(64), ForeignKey('tenants.id'), nullable=False, index=True)
    key_id = Column(String(255), ForeignKey('key_records.key_id'), nullable=False)
    old_key_id = Column(String(255), nullable=True)  # if rotating existing key
    rotation_reason = Column(String(100), nullable=True)  # e.g., "scheduled", "compromised"
    rotated_at = Column(DateTime(timezone=True), server_default=func.now())
    success = Column(Boolean, default=False, nullable=False)
    notes = Column(Text, nullable=True)

    def __repr__(self):
        return f"<KeyRotationRecord(tenant='{self.tenant_id}', key='{self.key_id}', reason='{self.rotation_reason}', success={self.success})>"
