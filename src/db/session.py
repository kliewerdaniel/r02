"""
Database session management for QASP.
Provides connection pooling and session factories.
"""

import os
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, Session
from sqlalchemy.pool import StaticPool
from typing import Optional
from .models import Base


def get_database_url() -> str:
    """
    Get database URL from environment or default to SQLite for development.
    """
    return os.getenv("DATABASE_URL", "sqlite:///./qasp.db")


def create_engine_from_url(database_url: Optional[str] = None) -> create_engine:
    """
    Create SQLAlchemy engine with appropriate configuration.
    """
    url = database_url or get_database_url()

    if url.startswith("sqlite"):
        # SQLite configuration for development
        engine = create_engine(
            url,
            connect_args={"check_same_thread": False},
            poolclass=StaticPool,
            echo=False  # Set to True for debug logging
        )
    else:
        # PostgreSQL configuration for production
        engine = create_engine(
            url,
            pool_pre_ping=True,  # Test connections before use
            pool_recycle=300,    # Recycle connections every 5 minutes
            echo=False
        )

    return engine


def create_tables(engine) -> None:
    """
    Create all database tables defined in models.
    """
    Base.metadata.create_all(bind=engine)


def get_session_factory(engine) -> sessionmaker:
    """
    Create session factory for database operations.
    """
    return sessionmaker(autocommit=False, autoflush=False, bind=engine)


# Global session factory (configured at startup)
_session_factory: Optional[sessionmaker] = None


def init_database(database_url: Optional[str] = None) -> None:
    """
    Initialize database connection and create tables.
    Call this once at application startup.
    """
    global _session_factory

    engine = create_engine_from_url(database_url)
    create_tables(engine)
    _session_factory = get_session_factory(engine)


def get_db() -> Session:
    """
    Get a database session.
    Usage: with get_db() as db: ...
    """
    if _session_factory is None:
        raise RuntimeError("Database not initialized. Call init_database() first.")

    db = _session_factory()
    try:
        yield db
    finally:
        db.close()


class DatabaseSession:
    """
    Context manager for database sessions.
    Useful for manual session management when dependency injection isn't used.
    """

    def __init__(self):
        if _session_factory is None:
            raise RuntimeError("Database not initialized. Call init_database() first.")
        self.db = _session_factory()

    def __enter__(self):
        return self.db

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.db.close()


def create_tenant_if_not_exists(tenant_id: str, name: str, description: str = "") -> None:
    """
    Create a tenant record if it doesn't already exist.
    Useful for ensuring tenant isolation on first use.
    """
    from .models import Tenant

    with DatabaseSession() as db:
        tenant = db.query(Tenant).filter(Tenant.id == tenant_id).first()
        if not tenant:
            tenant = Tenant(id=tenant_id, name=name, description=description)
            db.add(tenant)
            db.commit()
        db.refresh(tenant)


def ensure_default_tenant() -> None:
    """
    Ensure the default tenant exists.
    Call this during application initialization.
    """
    create_tenant_if_not_exists(
        tenant_id="default",
        name="Default Tenant",
        description="Default tenant for QASP operations"
    )
