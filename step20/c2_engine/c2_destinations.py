from collections import Counter
from typing import Any

from scapy.all import IP, TCP, UDP


def analyze_destination_behavior(
    packets: list,
) -> list[dict[str, Any]]:

    communications = Counter()

    for packet in packets:

        if not packet.haslayer(IP):
            continue

        source_ip = packet[IP].src
        destination_ip = packet[IP].dst

        destination_port = 0

        if packet.haslayer(TCP):
            destination_port = int(
                packet[TCP].dport
            )

        elif packet.haslayer(UDP):
            destination_port = int(
                packet[UDP].dport
            )

        communications[
            (
                source_ip,
                destination_ip,
                destination_port,
            )
        ] += 1

    source_destinations = {}

    for (
        source_ip,
        destination_ip,
        destination_port,
    ), count in communications.items():

        if source_ip not in source_destinations:
            source_destinations[source_ip] = {}

        if (
            destination_ip
            not in source_destinations[source_ip]
        ):
            source_destinations[source_ip][
                destination_ip
            ] = Counter()

        source_destinations[source_ip][
            destination_ip
        ][destination_port] += count

    results = []

    for (
        source_ip,
        destinations,
    ) in source_destinations.items():

        total_communications = sum(
            sum(
                ports.values()
            )
            for ports in destinations.values()
        )

        unique_destinations = len(
            destinations
        )

        destination_totals = Counter()

        for (
            destination_ip,
            ports,
        ) in destinations.items():

            destination_totals[
                destination_ip
            ] = sum(
                ports.values()
            )

        dominant_destination = (
            destination_totals.most_common(1)[0]
            if destination_totals
            else (None, 0)
        )

        dominant_ip = dominant_destination[0]
        dominant_count = dominant_destination[1]

        dominant_ports = (
            destinations.get(
                dominant_ip,
                Counter(),
            )
        )

        unique_destination_ports = len(
            dominant_ports
        )

        dominant_port = (
            dominant_ports.most_common(1)[0]
            if dominant_ports
            else (None, 0)
        )

        dominant_port_number = (
            dominant_port[0]
        )

        dominant_port_count = (
            dominant_port[1]
        )

        if total_communications > 0:
            destination_concentration = (
                dominant_count
                / total_communications
            )
        else:
            destination_concentration = 0.0

        if dominant_count > 0:
            destination_port_concentration = (
                dominant_port_count
                / dominant_count
            )
        else:
            destination_port_concentration = 0.0

        results.append(
            {
                "source_ip": source_ip,
                "total_communications": (
                    total_communications
                ),
                "unique_destinations": (
                    unique_destinations
                ),
                "dominant_destination": (
                    dominant_ip
                ),
                "dominant_destination_count": (
                    dominant_count
                ),
                "destination_concentration": round(
                    destination_concentration,
                    4,
                ),
                "unique_destination_ports": (
                    unique_destination_ports
                ),
                "dominant_destination_port": (
                    dominant_port_number
                ),
                "dominant_destination_port_count": (
                    dominant_port_count
                ),
                "destination_port_concentration": round(
                    destination_port_concentration,
                    4,
                ),
            }
        )

    return results