import enum
from datetime import datetime

from sqlalchemy import (
    Boolean,
    Column,
    DateTime,
    Enum,
    ForeignKey,
    Integer,
    JSON,
    String,
    Text,
)

from sqlalchemy.orm import relationship

from app.db.postgres import Base


# =========================================================
# ENUMS
# =========================================================

class SeverityEnum(str, enum.Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class ScanStatusEnum(str, enum.Enum):
    PENDING = "PENDING"
    RUNNING = "RUNNING"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"


# =========================================================
# MAIN SCAN
# =========================================================

class AnalyzerScan(Base):

    __tablename__ = "analyzer_scans"

    id = Column(
        Integer,
        primary_key=True,
        index=True,
    )

    success = Column(
        Boolean,
        default=True,
        nullable=False,
    )

    status = Column(
        Enum(ScanStatusEnum),
        default=ScanStatusEnum.PENDING,
        nullable=False,
    )

    url = Column(
        Text,
        nullable=False,
        index=True,
    )

    method = Column(
        String(20),
        nullable=False,
    )

    overall_risk_score = Column(
        Integer,
        default=0,
    )

    severity = Column(
        Enum(SeverityEnum),
        nullable=False,
    )

    summary = Column(Text)

    generated_by = Column(
        String(255),
    )

    is_deleted = Column(
        Boolean,
        default=False,
    )

    created_at = Column(
        DateTime,
        default=datetime.utcnow,
        nullable=False,
    )

    updated_at = Column(
        DateTime,
        default=datetime.utcnow,
        onupdate=datetime.utcnow,
    )

    findings = relationship(
        "AnalyzerFinding",
        back_populates="scan",
        cascade="all, delete-orphan",
    )

    request_data = relationship(
        "AnalyzerRequest",
        back_populates="scan",
        uselist=False,
        cascade="all, delete-orphan",
    )

    response_data = relationship(
        "AnalyzerResponse",
        back_populates="scan",
        uselist=False,
        cascade="all, delete-orphan",
    )


# =========================================================
# FINDINGS
# =========================================================

class AnalyzerFinding(Base):

    __tablename__ = "analyzer_findings"

    id = Column(
        Integer,
        primary_key=True,
        index=True,
    )

    scan_id = Column(
        Integer,
        ForeignKey(
            "analyzer_scans.id",
            ondelete="CASCADE",
        ),
        nullable=False,
        index=True,
    )

    issue = Column(
        Text,
        nullable=False,
    )

    description = Column(Text)

    severity = Column(
        Enum(SeverityEnum),
        nullable=False,
    )

    category = Column(
        String(100),
        index=True,
    )

    recommendation = Column(Text)

    cwe = Column(
        String(50),
        index=True,
    )

    created_at = Column(
        DateTime,
        default=datetime.utcnow,
        nullable=False,
    )

    updated_at = Column(
        DateTime,
        default=datetime.utcnow,
        onupdate=datetime.utcnow,
    )

    scan = relationship(
        "AnalyzerScan",
        back_populates="findings",
    )


# =========================================================
# REQUEST
# =========================================================

class AnalyzerRequest(Base):

    __tablename__ = "analyzer_requests"

    id = Column(
        Integer,
        primary_key=True,
        index=True,
    )

    scan_id = Column(
        Integer,
        ForeignKey(
            "analyzer_scans.id",
            ondelete="CASCADE",
        ),
        nullable=False,
        unique=True,
        index=True,
    )

    headers = Column(JSON)

    body = Column(JSON)

    method = Column(
        String(20),
    )

    url = Column(Text)

    body_type = Column(
        String(50),
    )

    created_at = Column(
        DateTime,
        default=datetime.utcnow,
        nullable=False,
    )

    updated_at = Column(
        DateTime,
        default=datetime.utcnow,
        onupdate=datetime.utcnow,
    )

    scan = relationship(
        "AnalyzerScan",
        back_populates="request_data",
    )


# =========================================================
# RESPONSE
# =========================================================

class AnalyzerResponse(Base):

    __tablename__ = "analyzer_responses"

    id = Column(
        Integer,
        primary_key=True,
        index=True,
    )

    scan_id = Column(
        Integer,
        ForeignKey(
            "analyzer_scans.id",
            ondelete="CASCADE",
        ),
        nullable=False,
        unique=True,
        index=True,
    )

    status_code = Column(Integer)

    headers = Column(JSON)

    body = Column(JSON)

    raw_text = Column(Text)

    created_at = Column(
        DateTime,
        default=datetime.utcnow,
        nullable=False,
    )

    updated_at = Column(
        DateTime,
        default=datetime.utcnow,
        onupdate=datetime.utcnow,
    )

    scan = relationship(
        "AnalyzerScan",
        back_populates="response_data",
    )
