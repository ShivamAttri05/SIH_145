from datetime import datetime

from sqlalchemy import DateTime
from sqlalchemy import Float
from sqlalchemy import Integer
from sqlalchemy import JSON
from sqlalchemy import String
from sqlalchemy.orm import Mapped
from sqlalchemy.orm import mapped_column

from .database import Base


class Alert(Base):

    __tablename__ = "alerts"


    id: Mapped[int] = mapped_column(
        Integer,
        primary_key=True,
        autoincrement=True,
    )


    timestamp: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
    )


    flow_id: Mapped[str] = mapped_column(
        String(128),
        nullable=False,
        index=True,
    )


    source_ip: Mapped[str] = mapped_column(
        String(64),
        nullable=False,
        index=True,
    )


    destination_ip: Mapped[str] = mapped_column(
        String(64),
        nullable=False,
    )


    threat_class: Mapped[str] = mapped_column(
        String(64),
        nullable=False,
        index=True,
    )


    confidence: Mapped[float] = mapped_column(
        Float,
        nullable=False,
    )


    risk_score: Mapped[float] = mapped_column(
        Float,
        nullable=False,
    )


    ml_risk_contribution: Mapped[float | None] = mapped_column(
        Float,
        nullable=True,
    )


    rule_contribution: Mapped[float | None] = mapped_column(
        Float,
        nullable=True,
    )


    behavior_contribution: Mapped[float | None] = mapped_column(
        Float,
        nullable=True,
    )


    severity: Mapped[str] = mapped_column(
        String(32),
        nullable=False,
        index=True,
    )


    evidence: Mapped[list] = mapped_column(
        JSON,
        nullable=False,
    )


    features: Mapped[dict] = mapped_column(
        JSON,
        nullable=False,
    )