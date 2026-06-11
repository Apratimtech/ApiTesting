from sqlalchemy import Column, String, Text, ForeignKey, DateTime
from sqlalchemy.dialects.postgresql import UUID, JSONB
from sqlalchemy.sql import func
from sqlalchemy.orm import relationship
from app.db.postgres import Base
from uuid import uuid4


# =========================================================
# 🔹 COLLECTION MODEL
# =========================================================
class Collection(Base):
    __tablename__ = "collections"
    id = Column(
        UUID(as_uuid=True),
        primary_key=True,
        default=uuid4
    )
    name = Column(
        String(255),
        nullable=False
    )
    parent_id = Column(
        UUID(as_uuid=True),
        ForeignKey("collections.id", ondelete="CASCADE"),
        nullable=True,
        index=True
    )
    created_at = Column(
        DateTime(timezone=True),
        server_default=func.now(),
        nullable=False
    )
    updated_at = Column(
        DateTime(timezone=True),
        server_default=func.now(),
        onupdate=func.now(),
        nullable=False
    )
    # =====================================================
    # 🔗 RELATIONSHIPS (Self-referential + Requests)
    # =====================================================
    parent = relationship(
        "Collection",
        remote_side=[id],
        back_populates="children",
        foreign_keys=[parent_id]  # ← Critical fix
    )
    children = relationship(
        "Collection",
        back_populates="parent",
        cascade="all, delete-orphan",
        foreign_keys=[parent_id]  # ← Critical fix
    )
    requests = relationship(
        "SavedRequest",
        back_populates="collection",
        cascade="all, delete-orphan"
    )


# =========================================================
# 🔹 SAVED REQUEST MODEL
# =========================================================
class SavedRequest(Base):
    __tablename__ = "saved_requests"
    id = Column(
        UUID(as_uuid=True),
        primary_key=True,
        default=uuid4
    )
    collection_id = Column(
        UUID(as_uuid=True),
        ForeignKey("collections.id", ondelete="CASCADE"),
        nullable=False,
        index=True
    )
    name = Column(
        String(255),
        nullable=False
    )
    method = Column(
        String(20),
        nullable=False
    )
    url = Column(
        Text,
        nullable=False
    )
    # NEW: Protocol Type (HTTP, MQTT, gRPC, etc.)
    type = Column(
        String(50),
        nullable=False,
        default="HTTP"
    )
    headers = Column(JSONB, nullable=True)
    body = Column(JSONB, nullable=True)
    created_at = Column(
        DateTime(timezone=True),
        server_default=func.now(),
        nullable=False
    )
    updated_at = Column(
        DateTime(timezone=True),
        server_default=func.now(),
        onupdate=func.now(),
        nullable=False
    )
    # =====================================================
    # 🔗 RELATIONSHIP
    # =====================================================
    collection = relationship(
        "Collection",
        back_populates="requests"
    )

