from sqlalchemy import desc
from sqlalchemy.orm import Session

from .models import Alert
from .schemas import AlertCreate


def create_alert(
    db: Session,
    alert_data: AlertCreate,
) -> Alert:

    alert = Alert(
        timestamp=alert_data.timestamp,
        flow_id=alert_data.flow_id,
        source_ip=alert_data.source_ip,
        destination_ip=alert_data.destination_ip,
        threat_class=alert_data.threat_class,
        confidence=alert_data.confidence,
        risk_score=alert_data.risk_score,
        ml_risk_contribution=(
            alert_data.ml_risk_contribution
        ),
        rule_contribution=(
            alert_data.rule_contribution
        ),
        behavior_contribution=(
            alert_data.behavior_contribution
        ),
        severity=alert_data.severity,
        evidence=alert_data.evidence,
        features=alert_data.features,
        c2_risk_contribution=alert_data.c2_risk_contribution,
        tls_risk_contribution=alert_data.tls_risk_contribution,
    )


    db.add(alert)

    db.commit()

    db.refresh(alert)

    return alert


def get_alerts(
    db: Session,
    limit: int = 100,
) -> list[Alert]:

    return (
        db.query(Alert)
        .order_by(desc(Alert.timestamp))
        .limit(limit)
        .all()
    )


def get_alert(
    db: Session,
    alert_id: int,
) -> Alert | None:

    return (
        db.query(Alert)
        .filter(Alert.id == alert_id)
        .first()
    )