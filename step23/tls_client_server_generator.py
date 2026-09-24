from pathlib import Path

from scapy.all import Ether, IP, TCP, wrpcap
from scapy.layers.tls.all import (
    TLS,
    TLSClientHello,
    TLSServerHello,
)
from scapy.layers.tls.extensions import (
    TLS_Ext_SupportedVersion_SH,
)


OUTPUT_DIR = Path("step23/generated")
OUTPUT_FILE = OUTPUT_DIR / "tls_client_server.pcap"


def build_client_hello():
    client_hello = TLSClientHello()

    return (
        Ether()
        /
        IP(
            src="10.30.30.10",
            dst="203.0.113.100",
        )
        /
        TCP(
            sport=49152,
            dport=443,
            flags="PA",
            seq=1,
            ack=1,
        )
        /
        TLS(
            version=0x0303,
        )
        /
        client_hello
    )


def build_server_hello():
    server_hello = TLSServerHello(
        version=0x0303,
        cipher=49195,
        ext=[
            TLS_Ext_SupportedVersion_SH(
                version=0x0303
            )
        ],
    )

    return (
        Ether()
        /
        IP(
            src="203.0.113.100",
            dst="10.30.30.10",
        )
        /
        TCP(
            sport=443,
            dport=49152,
            flags="PA",
            seq=1,
            ack=1,
        )
        /
        TLS(
            version=0x0303,
        )
        /
        server_hello
    )


def main():
    OUTPUT_DIR.mkdir(
        parents=True,
        exist_ok=True,
    )

    client_packet = build_client_hello()
    server_packet = build_server_hello()

    packets = [
        client_packet,
        server_packet,
    ]

    wrpcap(
        str(OUTPUT_FILE),
        packets,
    )

    print(
        f"Created: {OUTPUT_FILE}"
    )

    print(
        f"Packets: {len(packets)}"
    )


if __name__ == "__main__":
    main()