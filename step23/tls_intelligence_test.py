import sys
from pathlib import Path
from pprint import pprint

from scapy.all import rdpcap


# Add project root to Python import path
PROJECT_ROOT = Path(__file__).resolve().parent.parent

if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))


from step20.tls_engine.tls_intelligence import (
    analyze_tls_intelligence,
)


PCAP_FILE = PROJECT_ROOT / "step23" / "generated" / "tls_clienthello.pcap"


def main():

    print("=" * 70)
    print("TLS INTELLIGENCE TEST")
    print("=" * 70)

    packets = rdpcap(str(PCAP_FILE))

    print(f"PCAP: {PCAP_FILE}")
    print(f"Packets: {len(packets)}")
    print()

    result = analyze_tls_intelligence(
        list(packets)
    )

    print("TLS INTELLIGENCE RESULT")
    print("-" * 70)

    pprint(result)

    print()
    print("=" * 70)


if __name__ == "__main__":
    main()