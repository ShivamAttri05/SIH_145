from datetime import datetime

from pydantic import BaseModel
from pydantic import ConfigDict


class AlertCreate(BaseModel):

    timestamp: datetime

    flow_id: str

    source_ip: str

    destination_ip: str

    threat_class: str

    confidence: float

    ml_risk_contribution: float | None = None

    rule_contribution: float | None = None

    behavior_contribution: float | None = None

    risk_score: float

    severity: str

    evidence: list[str]

    features: dict


class AlertResponse(BaseModel):

    id: int

    event_type: str

    timestamp: datetime

    flow_id: str

    source_ip: str

    destination_ip: str

    threat_class: str

    confidence: float

    ml_risk_contribution: float | None

    rule_contribution: float | None

    behavior_contribution: float | None

    risk_score: float

    severity: str

    evidence: list[str]

    features: dict

    model_config = ConfigDict(
        from_attributes=True,
    )