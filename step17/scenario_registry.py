from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parent.parent


SCENARIOS = {
    "normal": {
        "name": "Normal Traffic",
        "description": "Benign baseline TCP traffic.",
        "pcap": PROJECT_ROOT / "step9" / "generated" / "normal.pcap",
    },

    "syn_flood": {
        "name": "SYN Flood",
        "description": "Synthetic TCP SYN flood traffic.",
        "pcap": PROJECT_ROOT / "step9" / "generated" / "syn_flood.pcap",
    },

    "port_scan": {
        "name": "Port Scan",
        "description": "Synthetic reconnaissance across multiple destination ports.",
        "pcap": PROJECT_ROOT / "step9" / "generated" / "port_scan.pcap",
    },

    "dns_burst": {
        "name": "DNS Burst",
        "description": "Synthetic burst of DNS traffic for DNS anomaly analysis.",
        "pcap": PROJECT_ROOT / "step9" / "generated" / "dns_burst.pcap",
    },

    "c2_beacon": {
        "name": "C2 Beacon",
        "description": "Periodic command-and-control beacon traffic.",
        "pcap": PROJECT_ROOT
        / "step20"
        / "c2_engine"
        / "generated"
        / "beacon.pcap",
    },

    "tls_client_hello": {
        "name": "TLS Client Hello",
        "description": "Synthetic TLS ClientHello traffic for passive TLS intelligence.",
        "pcap": PROJECT_ROOT
        / "step20"
        / "tls_engine"
        / "generated"
        / "tls_client_hello.pcap",
    },
}


def get_scenarios() -> list[dict]:
    results = []

    for scenario_id, scenario in SCENARIOS.items():

        pcap_path = Path(
            scenario["pcap"]
        )

        results.append(
            {
                "id": scenario_id,
                "name": scenario["name"],
                "description": scenario["description"],
                "pcap": str(pcap_path),
                "exists": pcap_path.exists(),
            }
        )

    return results


def get_scenario(
    scenario_id: str,
) -> dict:

    scenario = SCENARIOS.get(
        scenario_id
    )

    if scenario is None:
        raise KeyError(
            f"Unknown scenario: {scenario_id}"
        )

    pcap_path = Path(
        scenario["pcap"]
    )

    return {
        "id": scenario_id,
        "name": scenario["name"],
        "description": scenario["description"],
        "pcap": str(pcap_path),
        "exists": pcap_path.exists(),
    }