from typing import Any

from scapy.layers.inet import TCP
from scapy.layers.tls.all import TLS, TLSClientHello, TLSServerHello


def _safe_int(value: Any, default: int = 0) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def _extract_version(tls_packet: TLS) -> str:
    version = getattr(tls_packet, "version", None)

    if version == 0x0301:
        return "TLS 1.0"

    if version == 0x0302:
        return "TLS 1.1"

    if version == 0x0303:
        return "TLS 1.2"

    if version == 0x0304:
        return "TLS 1.3"

    return str(version) if version is not None else "UNKNOWN"


def _extract_sni(client_hello: TLSClientHello) -> str | None:
    extensions = getattr(client_hello, "ext", None)

    if not extensions:
        return None

    for extension in extensions:
        extension_name = extension.__class__.__name__

        if "ServerName" in extension_name:
            servernames = getattr(
                extension,
                "servernames",
                None,
            )

            if servernames:
                for server_name in servernames:
                    name = getattr(
                        server_name,
                        "servername",
                        None,
                    )

                    if isinstance(name, bytes):
                        return name.decode(
                            "utf-8",
                            errors="ignore",
                        )

                    if name:
                        return str(name)

    return None


def _extract_alpn(client_hello):
    protocols = []

    extensions = getattr(client_hello, "ext", None)

    if not extensions:
        return protocols

    for extension in extensions:
        if "ALPN" not in extension.__class__.__name__:
            continue

        raw_protocols = getattr(extension, "protocols", None)

        if not raw_protocols:
            continue

        for protocol in raw_protocols:
            value = getattr(protocol, "protocol", protocol)

            if isinstance(value, bytes):
                try:
                    value = value.decode("utf-8")
                except UnicodeDecodeError:
                    value = value.decode(
                        "utf-8",
                        errors="replace",
                    )

            elif not isinstance(value, str):
                value = str(value)

            protocols.append(value)

    return protocols

def _extract_tls_from_tcp_payload(packet) -> TLS | None:
    """
    Try to decode TLS from a TCP payload.

    The packet may already contain a Scapy TLS layer,
    or it may contain a raw TLS record inside TCP.
    """

    if packet.haslayer(TLS):
        return packet[TLS]

    if not packet.haslayer(TCP):
        return None

    tcp_payload = packet[TCP].payload

    if not tcp_payload:
        return None

    try:
        raw_payload = bytes(tcp_payload)
    except Exception:
        return None

    if len(raw_payload) < 5:
        return None

    # TLS record content types:
    # 20 = Change Cipher Spec
    # 21 = Alert
    # 22 = Handshake
    # 23 = Application Data
    content_type = raw_payload[0]

    if content_type not in {
        20,
        21,
        22,
        23,
    }:
        return None

    # TLS versions normally begin with 0x03.
    if raw_payload[1] != 0x03:
        return None

    try:
        tls_packet = TLS(raw_payload)

        if tls_packet.haslayer(TLS):
            return tls_packet

    except Exception:
        return None

    return None


def analyze_tls_packet(packet) -> dict[str, Any]:
    """
    Extract passive TLS metadata from one packet.

    No TLS decryption is performed.
    """

    result = {
        "tls_detected": False,
        "tls_record_type": None,
        "tls_version": None,
        "client_hello": False,
        "server_hello": False,
        "cipher_suite_count": 0,
        "cipher_suites": [],
        "sni": None,
        "alpn": [],
    }

    tls_packet = _extract_tls_from_tcp_payload(packet)

    if tls_packet is None:
        return result

    result["tls_detected"] = True
    result["tls_record_type"] = _safe_int(
        getattr(tls_packet, "type", None),
        0,
    )
    result["tls_version"] = _extract_version(
        tls_packet
    )

    if tls_packet.haslayer(TLSClientHello):
        client_hello = tls_packet[TLSClientHello]

        result["client_hello"] = True

        ciphers = getattr(
            client_hello,
            "ciphers",
            None,
        )

        if ciphers:
            result["cipher_suite_count"] = len(
                ciphers
            )

            result["cipher_suites"] = [
                str(cipher)
                for cipher in ciphers
            ]

        result["sni"] = _extract_sni(
            client_hello
        )

        result["alpn"] = _extract_alpn(
            client_hello
        )

    if tls_packet.haslayer(TLSServerHello):
        result["server_hello"] = True

    return result


def analyze_tls_packets(
    packets: list,
) -> list[dict[str, Any]]:
    """
    Analyze TLS metadata across packets.
    """

    results = []

    for packet in packets:
        analysis = analyze_tls_packet(packet)

        if analysis["tls_detected"]:
            results.append(analysis)

    return results


def calculate_tls_statistics(
    packets: list,
) -> dict[str, Any]:
    """
    Aggregate TLS metadata across a packet collection.
    """

    tls_results = analyze_tls_packets(
        packets
    )

    if not tls_results:
        return {
            "tls_detected": False,
            "tls_packet_count": 0,
            "client_hello_count": 0,
            "server_hello_count": 0,
            "tls_versions": [],
            "cipher_suite_counts": [],
            "sni_values": [],
            "alpn_values": [],
        }

    tls_versions = sorted(
        {
            result["tls_version"]
            for result in tls_results
            if result["tls_version"]
        }
    )

    sni_values = sorted(
        {
            result["sni"]
            for result in tls_results
            if result["sni"]
        }
    )

    alpn_values = sorted(
        {
            protocol
            for result in tls_results
            for protocol in result["alpn"]
        }
    )

    cipher_suite_counts = [
        result["cipher_suite_count"]
        for result in tls_results
        if result["cipher_suite_count"] > 0
    ]

    return {
        "tls_detected": True,
        "tls_packet_count": len(
            tls_results
        ),
        "client_hello_count": sum(
            result["client_hello"]
            for result in tls_results
        ),
        "server_hello_count": sum(
            result["server_hello"]
            for result in tls_results
        ),
        "tls_versions": tls_versions,
        "cipher_suite_counts": cipher_suite_counts,
        "sni_values": sni_values,
        "alpn_values": alpn_values,
    }