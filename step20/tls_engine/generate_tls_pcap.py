from pathlib import Path

from scapy.all import Ether, IP, TCP, Raw, wrpcap
from scapy.layers.tls.all import (
    TLS,
    TLSClientHello,
    TLS_Ext_ServerName,
    TLS_Ext_ALPN,
    ServerName,
    ProtocolName,
)


OUTPUT_FILE = Path(
    "step20/tls_engine/generated/tls_client_hello.pcap"
)


def build_tls_client_hello():
    client_hello = TLSClientHello(
        version="TLS 1.2",
        ciphers=[
            0xC02B,
            0xC023,
            0xC02F,
            0xC027,
            0x009E,
            0x0067,
            0x009C,
            0x003C,
            0xC009,
            0xC013,
            0x0033,
            0x002F,
            0x000A,
        ],
    )

    server_name = TLS_Ext_ServerName(
        servernames=[
            ServerName(
                nametype=0,
                servername=b"example.com",
            )
        ]
    )

    alpn = TLS_Ext_ALPN(
        protocols=[
            ProtocolName(protocol=b"h2"),
            ProtocolName(protocol=b"http/1.1"),
        ]
    )

    client_hello.ext = [
        server_name,
        alpn,
    ]

    # Build the TLS handshake bytes.
    handshake_bytes = bytes(client_hello)

    # TLS record:
    #   0x16       = Handshake
    #   0x0303     = TLS 1.2
    #   2 bytes    = handshake payload length

    record_header = (
        b"\x16"
        + b"\x03\x03"
        + len(handshake_bytes).to_bytes(2, "big")
    )

    tls_bytes = record_header + handshake_bytes

    packet = (
        Ether(
            src="02:00:00:00:10:01",
            dst="02:00:00:00:10:02",
        )
        / IP(
            src="192.168.100.80",
            dst="192.168.100.200",
            id=1,
        )
        / TCP(
            sport=50000,
            dport=443,
            seq=1000,
            ack=1000,
            flags="PA",
        )
        / Raw(load=tls_bytes)
    )

    return packet


def main():
    OUTPUT_FILE.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    packet = build_tls_client_hello()

    wrpcap(
        str(OUTPUT_FILE),
        [packet],
    )

    print("=" * 60)
    print("TLS CLIENT HELLO PCAP GENERATED")
    print("=" * 60)
    print(f"Output: {OUTPUT_FILE}")
    print("Packets: 1")
    print()
    packet.show()


if __name__ == "__main__":
    main()