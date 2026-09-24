from pathlib import Path

from scapy.all import rdpcap

from step20.c2_engine.c2_features import analyze_c2_timing
from step20.c2_engine.c2_destinations import analyze_destination_behavior
from step20.c2_engine.c2_detector import calculate_c2_behavior_score


PCAP_DIR = Path("step22/generated")


def analyze_pcap(filename: str):

    path = PCAP_DIR / filename

    packets = rdpcap(str(path))

    print()
    print("=" * 70)
    print(filename.upper())
    print("=" * 70)

    print(
        f"Packets loaded : {len(packets)}"
    )

    timing_records = analyze_c2_timing(
        packets
    )

    destination_records = analyze_destination_behavior(
        packets
    )

    print()
    print("C2 TIMING")
    print("-" * 70)

    for record in timing_records:

        print(
            f"Source            : "
            f"{record.get('source_ip')}"
        )

        print(
            f"Destination       : "
            f"{record.get('destination_ip')}"
        )

        print(
            f"Communications    : "
            f"{record.get('communication_count')}"
        )

        print(
            f"Average interval  : "
            f"{record.get('average_interval')}"
        )

        print(
            f"Minimum interval  : "
            f"{record.get('minimum_interval')}"
        )

        print(
            f"Maximum interval  : "
            f"{record.get('maximum_interval')}"
        )

        print(
            f"Interval std      : "
            f"{record.get('interval_std')}"
        )

        print(
            f"Coefficient var   : "
            f"{record.get('coefficient_of_variation')}"
        )

        print(
            f"Periodicity score : "
            f"{record.get('periodicity_score')}"
        )

    print()
    print("DESTINATION BEHAVIOR")
    print("-" * 70)

    for record in destination_records:

        print(
            f"Source                     : "
            f"{record.get('source_ip')}"
        )

        print(
            f"Total communications       : "
            f"{record.get('total_communications')}"
        )

        print(
            f"Unique destinations       : "
            f"{record.get('unique_destinations')}"
        )

        print(
            f"Dominant destination       : "
            f"{record.get('dominant_destination')}"
        )

        print(
            f"Destination concentration : "
            f"{record.get('destination_concentration')}"
        )

        print(
            f"Unique destination ports   : "
            f"{record.get('unique_destination_ports')}"
        )

        print(
            f"Dominant destination port  : "
            f"{record.get('dominant_destination_port')}"
        )

        print(
            f"Port concentration         : "
            f"{record.get('destination_port_concentration')}"
        )

    print()
    print("C2 CLASSIFICATION")
    print("-" * 70)

    results = []

    for timing in timing_records:

        timing_source = timing.get(
            "source_ip"
        )

        timing_destination = timing.get(
            "destination_ip"
        )

        matching_destination = None

        for destination in destination_records:

            if (
                destination.get("source_ip")
                == timing_source
                and
                destination.get("dominant_destination")
                == timing_destination
            ):

                matching_destination = destination
                break

        if matching_destination is None:

            continue

        result = calculate_c2_behavior_score(
            timing,
            matching_destination
        )

        results.append(
            result
        )

        print(
            f"Source            : "
            f"{timing_source}"
        )

        print(
            f"Destination       : "
            f"{timing_destination}"
        )

        print(
            f"C2 score          : "
            f"{result.get('c2_behavior_score')}"
        )

        print(
            f"Classification     : "
            f"{result.get('classification')}"
        )

        print()

        evidence = result.get(
            "evidence",
            []
        )

        if evidence:

            print("Evidence:")

            for item in evidence:

                print(
                    f"  {item}"
                )

        else:

            print(
                "Evidence          : None"
            )

    if not results:

        print(
            "No matching C2 timing/destination pairs."
        )


if __name__ == "__main__":

    print("=" * 70)
    print("STEP 22 - C2 INTELLIGENCE VALIDATION")
    print("=" * 70)

    analyze_pcap(
        "normal_dns.pcap"
    )

    analyze_pcap(
        "c2_beacon.pcap"
    )

    analyze_pcap(
        "port_scan.pcap"
    )

    print()
    print("=" * 70)
    print(
        "C2 INTELLIGENCE VALIDATION COMPLETE"
    )
    print("=" * 70)