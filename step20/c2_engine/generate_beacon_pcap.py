from pathlib import Path

from scapy.all import IP, TCP, wrpcap


OUTPUT_DIR = Path(
    "step20/c2_engine/generated"
)

BEACON_FILE = (
    OUTPUT_DIR / "beacon.pcap"
)


def generate_beacon():
    packets = []

    source_ip = "192.168.100.70"
    destination_ip = "192.168.100.200"

    source_port = 50000
    destination_port = 443

    start_time = 1000000.0
    interval = 30.0

    for index in range(10):

        packet = (
            IP(
                src=source_ip,
                dst=destination_ip,
            )
            / TCP(
                sport=source_port,
                dport=destination_port,
                flags="PA",
            )
        )

        packet.time = (
            start_time
            + index * interval
        )

        packets.append(packet)

    wrpcap(
        str(BEACON_FILE),
        packets,
    )

    print(
        f"Generated {len(packets)} beacon packets"
    )

    print(
        f"Output: {BEACON_FILE}"
    )


if __name__ == "__main__":
    OUTPUT_DIR.mkdir(
        parents=True,
        exist_ok=True,
    )

    generate_beacon()