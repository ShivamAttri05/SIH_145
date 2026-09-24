import asyncio

from datetime import datetime, timezone
from typing import List

from fastapi import (
    FastAPI,
    WebSocket,
    WebSocketDisconnect
)

from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

from .detection_service import DetectionService
from .flow_service import FlowService

from step17.websocket_manager import (
    ConnectionManager
)

from step17.live_stream_service import (
    LiveStreamService
)

from step17.scenario_registry import (
    get_scenarios,
    get_scenario,
)

from step19.database import SessionLocal
from step19.alert_repository import (
    get_alerts as get_alerts_from_db,
    get_alert as get_alert_from_db
)

import uuid

from step19.schemas import AlertCreate
from step19.schemas import AlertResponse
from step19.alert_repository import (
    create_alert
)

# ============================================================
# FASTAPI APPLICATION
# ============================================================

app = FastAPI(
    title="SIH Cyber Threat Detection API",
    description=(
        "Passive AI-based cyber threat detection "
        "API for unidirectional IP traffic."
    ),
    version="1.0.0"
)

# ============================================================
# CORS CONFIGURATION
# ============================================================

app.add_middleware(
    CORSMiddleware,

    allow_origins=[
        "http://localhost:5173",
        "http://127.0.0.1:5173",
    ],

    allow_credentials=True,

    allow_methods=[
        "*"
    ],

    allow_headers=[
        "*"
    ],
)


# ============================================================
# DETECTION SERVICE
# ============================================================

detector = DetectionService()
manager = ConnectionManager()

flow_service = FlowService()

live_stream = LiveStreamService(
    manager
)


# ============================================================
# ALERT STORAGE
# ============================================================

MAX_ALERTS = 100


# ============================================================
# ALERT RESPONSE FORMATTER
# ============================================================

def serialize_alert(
    alert
):

    return {

        "id":
            alert.id,

        "event_type":
            "THREAT_DETECTION",

        "timestamp":
            alert.timestamp.isoformat(),

        "flow_id":
            alert.flow_id,

        "source_ip":
            alert.source_ip,

        "destination_ip":
            alert.destination_ip,

        "threat_class":
            alert.threat_class,

        "confidence":
            alert.confidence,

        "ml_risk_contribution":
            alert.ml_risk_contribution,

        "rule_contribution":
            alert.rule_contribution,

        "behavior_contribution":
            alert.behavior_contribution,

        "risk_score":
            alert.risk_score,

        "severity":
            alert.severity,

        "evidence":
            alert.evidence,

        "features":
            alert.features,
    }


# ============================================================
# INPUT SCHEMA
# ============================================================

class TrafficFeatures(BaseModel):

    source_ip: str = Field(
        ...,
        description="Observed source IP address"
    )

    destination_ip: str = Field(
        ...,
        description="Observed destination IP address"
    )

    packets: int = Field(
        ...,
        ge=0
    )

    bytes: int = Field(
        ...,
        ge=0
    )

    unique_destination_ips: int = Field(
        ...,
        ge=0
    )

    unique_destination_ports: int = Field(
        ...,
        ge=0
    )

    duration: float = Field(
        ...,
        ge=0
    )

    packets_per_sec: float = Field(
        ...,
        ge=0
    )

    bytes_per_sec: float = Field(
        ...,
        ge=0
    )

    tcp_packets: int = Field(
        ...,
        ge=0
    )

    syn_packets: int = Field(
        ...,
        ge=0
    )

    ack_packets: int = Field(
        ...,
        ge=0
    )

    rst_packets: int = Field(
        ...,
        ge=0
    )

    fin_packets: int = Field(
        ...,
        ge=0
    )

    syn_ratio: float = Field(
        ...,
        ge=0,
        le=1
    )

    ack_ratio: float = Field(
        ...,
        ge=0,
        le=1
    )

    rst_ratio: float = Field(
        ...,
        ge=0,
        le=1
    )

    fin_ratio: float = Field(
        ...,
        ge=0,
        le=1
    )

    dns_packets: int = Field(
        ...,
        ge=0
    )

    average_inter_arrival: float = Field(
        ...,
        ge=0
    )

# ============================================================
# PCAP REPLAY REQUEST
# ============================================================

class StreamStartRequest(BaseModel):

    scenario: str = Field(
        ...,
        description="PCAP replay scenario identifier"
    )

# ============================================================
# HEALTH RESPONSE
# ============================================================

class HealthResponse(BaseModel):

    status: str

    service: str

    model_loaded: bool

    alerts_in_memory: int


# ============================================================
# ROOT
# ============================================================

@app.get("/")
def root():

    return {

        "service":
            "SIH Cyber Threat Detection API",

        "version":
            "1.0.0",

        "status":
            "running",

        "documentation":
            "/docs"
    }


# ============================================================
# HEALTH CHECK
# ============================================================

@app.get(
    "/api/v1/health",
    response_model=HealthResponse
)
def health():

    return {

        "status":
            "healthy",

        "service":
            "threat-detection-engine",

        "model_loaded":
            detector.model is not None,

        "alerts_in_memory":
            len(alerts)
    }


# ============================================================
# ANALYZE TRAFFIC
# ============================================================

@app.post(
    "/api/v1/analyze"
)
def analyze_traffic(
    traffic: TrafficFeatures
):

    # --------------------------------------------------------
    # Extract ML features
    # --------------------------------------------------------

    features = {

        "packets":
            traffic.packets,

        "bytes":
            traffic.bytes,

        "unique_destination_ips":
            traffic.unique_destination_ips,

        "unique_destination_ports":
            traffic.unique_destination_ports,

        "duration":
            traffic.duration,

        "packets_per_sec":
            traffic.packets_per_sec,

        "bytes_per_sec":
            traffic.bytes_per_sec,

        "tcp_packets":
            traffic.tcp_packets,

        "syn_packets":
            traffic.syn_packets,

        "ack_packets":
            traffic.ack_packets,

        "rst_packets":
            traffic.rst_packets,

        "fin_packets":
            traffic.fin_packets,

        "syn_ratio":
            traffic.syn_ratio,

        "ack_ratio":
            traffic.ack_ratio,

        "rst_ratio":
            traffic.rst_ratio,

        "fin_ratio":
            traffic.fin_ratio,

        "dns_packets":
            traffic.dns_packets,

        "average_inter_arrival":
            traffic.average_inter_arrival
    }

    # --------------------------------------------------------
    # Detection
    # --------------------------------------------------------

    result = detector.analyze(
        features
    )

    # --------------------------------------------------------
    # Create standardized alert
    # --------------------------------------------------------

    timestamp = datetime.now(
        timezone.utc
    )

    flow_id = str(
        uuid.uuid4()
    )


    alert_data = AlertCreate(

        timestamp=timestamp,

        flow_id=flow_id,

        source_ip=traffic.source_ip,

        destination_ip=traffic.destination_ip,

        threat_class=result[
            "threat_class"
        ],

        confidence=result[
            "confidence"
        ],

        risk_score=result[
            "risk_score"
        ],

        ml_risk_contribution=result[
            "ml_risk_contribution"
        ],

        rule_contribution=result[
            "rule_contribution"
        ],

        behavior_contribution=result[
            "behavior_contribution"
        ],

        severity=result[
            "severity"
        ],

        evidence=result[
            "evidence"
        ],

        features=features,

    )


    # --------------------------------------------------------
    # Persist alert
    # --------------------------------------------------------

    db = SessionLocal()

    try:

        saved_alert = create_alert(
            db,
            alert_data
        )

    finally:

        db.close()


    # --------------------------------------------------------
    # API response
    # --------------------------------------------------------

    return serialize_alert(
        saved_alert
    )


# ============================================================
# GET ALERTS
# ============================================================

@app.get(
    "/api/v1/alerts",
    response_model=dict
)
def get_alerts():

    db = SessionLocal()

    try:

        db_alerts = get_alerts_from_db(
            db,
            limit=MAX_ALERTS
        )


        serialized_alerts = [

            serialize_alert(
                alert
            )

            for alert in db_alerts

        ]


        return {

            "count":
                len(
                    serialized_alerts
                ),

            "alerts":
                serialized_alerts
        }

    finally:

        db.close()

# ============================================================
# GET SINGLE ALERT
# ============================================================

@app.get(
    "/api/v1/alerts/{alert_id}"
)
def get_alert(
    alert_id: int
):

    db = SessionLocal()

    try:

        alert = get_alert_from_db(
            db,
            alert_id
        )


        if alert is None:

            return {

                "error":
                    "Alert not found"
            }


        return serialize_alert(
            alert
        )

    finally:

        db.close()

# ============================================================
# GET NETWORK FLOWS
# ============================================================

@app.get(
    "/api/v1/flows"
)
def get_flows(
    pcap: str | None = None,
):

    try:

        if pcap:

            selected_flow_service = FlowService(
                pcap
            )

        else:

            selected_flow_service = flow_service

        flows = (
            selected_flow_service.extract_flows()
        )

        return {

            "count":
                len(flows),

            "pcap":
                str(
                    selected_flow_service.pcap_file
                ),

            "flows":
                flows,
        }

    except FileNotFoundError as error:

        return {

            "count":
                0,

            "pcap":
                pcap
                if pcap
                else str(
                    flow_service.pcap_file
                ),

            "flows":
                [],

            "error":
                str(error),
        }

# ============================================================
# WEBSOCKET ENDPOINT
# ============================================================

@app.websocket(
    "/ws/live"
)
async def websocket_endpoint(
    websocket: WebSocket
):

    await manager.connect(
        websocket
    )

    try:

        while True:

            await websocket.receive_text()

    except WebSocketDisconnect:

        manager.disconnect(
            websocket
        )

    except Exception:

        manager.disconnect(
            websocket
        )


# ============================================================
# GET PCAP REPLAY SCENARIOS
# ============================================================

@app.get(
    "/api/v1/stream/scenarios"
)
def list_stream_scenarios():

    return {
        "count": len(
            get_scenarios()
        ),
        "scenarios": get_scenarios(),
    }


# ============================================================
# START LIVE PCAP STREAM
# ============================================================

@app.post(
    "/api/v1/stream/start"
)
async def start_stream(
    request: StreamStartRequest
):

    # --------------------------------------------------------
    # Check whether another replay is running
    # --------------------------------------------------------

    if live_stream.running:

        return {
            "status":
                "already_running",

            "message":
                "A PCAP stream is already running."
        }

    # --------------------------------------------------------
    # Resolve requested scenario
    # --------------------------------------------------------

    try:

        scenario = get_scenario(
            request.scenario
        )

    except KeyError as error:

        return {
            "status":
                "error",

            "message":
                str(error),

            "available_scenarios":
                get_scenarios(),
        }

    # --------------------------------------------------------
    # Verify PCAP exists
    # --------------------------------------------------------

    if not scenario["exists"]:

        return {
            "status":
                "error",

            "message":
                "Scenario PCAP file does not exist.",

            "scenario":
                scenario,
        }

    # --------------------------------------------------------
    # Start replay
    # --------------------------------------------------------

    pcap_file = scenario[
        "pcap"
    ]

    asyncio.create_task(
        live_stream.stream_pcap(
            pcap_file
        )
    )

    return {

        "status":
            "started",

        "scenario":
            scenario["id"],

        "name":
            scenario["name"],

        "description":
            scenario["description"],

        "pcap":
            pcap_file,

        "websocket":
            "/ws/live",
    }