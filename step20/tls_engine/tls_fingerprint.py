from __future__ import annotations

import hashlib
from typing import Any

from scapy.layers.tls.all import TLSClientHello


def _safe_int(value: Any, default: int = 0) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def extract_cipher_suite_ids(
    client_hello: TLSClientHello,
) -> list[int]:
    """
    Extract numeric TLS cipher-suite identifiers
    from a ClientHello.
    """

    ciphers = getattr(
        client_hello,
        "ciphers",
        None,
    )

    if not ciphers:
        return []

    cipher_ids = []

    for cipher in ciphers:
        cipher_id = getattr(
            cipher,
            "val",
            None,
        )

        if cipher_id is None:
            try:
                cipher_id = int(cipher)
            except (TypeError, ValueError):
                continue

        cipher_ids.append(
            _safe_int(cipher_id)
        )

    return cipher_ids


def extract_extension_ids(
    client_hello: TLSClientHello,
) -> list[int]:
    """
    Extract numeric TLS extension identifiers
    from a ClientHello.
    """

    extensions = getattr(
        client_hello,
        "ext",
        None,
    )

    if not extensions:
        return []

    extension_ids = []

    for extension in extensions:
        extension_type = getattr(
            extension,
            "type",
            None,
        )

        extension_id = getattr(
            extension_type,
            "val",
            None,
        )

        if extension_id is None:
            try:
                extension_id = int(
                    extension_type
                )
            except (
                TypeError,
                ValueError,
            ):
                continue

        extension_ids.append(
            _safe_int(extension_id)
        )

    return extension_ids


def extract_supported_groups(
    client_hello: TLSClientHello,
) -> list[int]:
    """
    Extract supported groups if the ClientHello
    contains a supported-groups extension.

    Returns an empty list when the extension
    is not present.
    """

    extensions = getattr(
        client_hello,
        "ext",
        None,
    )

    if not extensions:
        return []

    for extension in extensions:
        name = extension.__class__.__name__

        if "SupportedGroups" not in name:
            continue

        groups = getattr(
            extension,
            "groups",
            None,
        )

        if not groups:
            return []

        result = []

        for group in groups:
            group_id = getattr(
                group,
                "val",
                None,
            )

            if group_id is None:
                try:
                    group_id = int(group)
                except (
                    TypeError,
                    ValueError,
                ):
                    continue

            result.append(
                _safe_int(group_id)
            )

        return result

    return []


def extract_ec_point_formats(
    client_hello: TLSClientHello,
) -> list[int]:
    """
    Extract EC point formats if the ClientHello
    contains the corresponding extension.

    Returns an empty list when unavailable.
    """

    extensions = getattr(
        client_hello,
        "ext",
        None,
    )

    if not extensions:
        return []

    for extension in extensions:
        name = extension.__class__.__name__

        if "SupportedPointFormat" not in name:
            continue

        formats = getattr(
            extension,
            "ecpl",
            None,
        )

        if formats is None:
            formats = getattr(
                extension,
                "formats",
                None,
            )

        if not formats:
            return []

        result = []

        for point_format in formats:
            format_id = getattr(
                point_format,
                "val",
                None,
            )

            if format_id is None:
                try:
                    format_id = int(
                        point_format
                    )
                except (
                    TypeError,
                    ValueError,
                ):
                    continue

            result.append(
                _safe_int(format_id)
            )

        return result

    return []


def build_ja3_string(
    client_hello: TLSClientHello,
) -> str:
    """
    Build a JA3-style fingerprint string.

    Format:

        TLSVersion,
        CipherSuites,
        Extensions,
        SupportedGroups,
        ECPointFormats
    """

    version = _safe_int(
        getattr(
            client_hello,
            "version",
            0,
        )
    )

    cipher_ids = extract_cipher_suite_ids(
        client_hello
    )

    extension_ids = extract_extension_ids(
        client_hello
    )

    supported_groups = extract_supported_groups(
        client_hello
    )

    ec_point_formats = extract_ec_point_formats(
        client_hello
    )

    return ",".join(
        [
            str(version),
            "-".join(
                str(value)
                for value in cipher_ids
            ),
            "-".join(
                str(value)
                for value in extension_ids
            ),
            "-".join(
                str(value)
                for value in supported_groups
            ),
            "-".join(
                str(value)
                for value in ec_point_formats
            ),
        ]
    )


def calculate_ja3_hash(
    ja3_string: str,
) -> str:
    """
    Calculate the MD5 hash of the JA3-style
    fingerprint string.
    """

    return hashlib.md5(
        ja3_string.encode("utf-8")
    ).hexdigest()


def analyze_tls_fingerprint(
    client_hello: TLSClientHello,
) -> dict[str, Any]:
    """
    Generate passive TLS fingerprint metadata.
    """

    ja3_string = build_ja3_string(
        client_hello
    )

    ja3_hash = calculate_ja3_hash(
        ja3_string
    )

    return {
        "tls_version": _safe_int(
            getattr(
                client_hello,
                "version",
                0,
            )
        ),
        "cipher_suite_ids":
            extract_cipher_suite_ids(
                client_hello
            ),
        "extension_ids":
            extract_extension_ids(
                client_hello
            ),
        "supported_groups":
            extract_supported_groups(
                client_hello
            ),
        "ec_point_formats":
            extract_ec_point_formats(
                client_hello
            ),
        "ja3_string": ja3_string,
        "ja3_hash": ja3_hash,
    }