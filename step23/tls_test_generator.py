from scapy.all import IP, TCP, Raw, wrpcap
from scapy.layers.tls.record import TLS
from scapy.layers.tls.handshake import TLSClientHello
from scapy.layers.tls.extensions import (
    TLS_Ext_ServerName,
    ServerName,
    TLS_Ext_ALPN,
)

OUTPUT = "step23/generated/tls_clienthello.pcap"


def build_tls_clienthello():
    client_hello = TLSClientHello(
        version=0x0303,
        ext=[
            TLS_Ext_ServerName(
                servernames=[
                    ServerName(
                        nametype=0,
                        servername="example.com"
                    )
                ]
            ),
            TLS_Ext_ALPN(
                protocols=[
                    b"h2",
                ]
            ),
        ],
    )

    tls = TLS(
        version=0x0303,
        msg=[client_hello],
    )

    packet = (
        IP(
            src="10.30.30.10",
            dst="203.0.113.100",
        )
        /
        TCP(
            sport=49152,
            dport=443,
            flags="PA",
            seq=1000,
            ack=1000,
        )
        /
        tls
    )

    return packet


def main():
    packet = build_tls_clienthello()

    wrpcap(
        OUTPUT,
        [packet]
    )

    print("TLS PCAP generated")
    print(f"Output: {OUTPUT}")
    print(f"Packets: 1")


if __name__ == "__main__":
    main()