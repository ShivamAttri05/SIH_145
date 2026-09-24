import asyncio
import json

import websockets


# ============================================================
# WEBSOCKET TEST CLIENT
# ============================================================

async def main():

    uri = (
        "ws://127.0.0.1:8000/ws/live"
    )

    print()
    print(
        "=" * 70
    )

    print(
        "STEP 17 — WEBSOCKET CLIENT"
    )

    print(
        "=" * 70
    )

    print()
    print(
        f"Connecting to: {uri}"
    )

    async with websockets.connect(
        uri
    ) as websocket:

        print(
            "WebSocket connected."
        )

        print(
            "Waiting for live detection events..."
        )

        print()

        while True:

            message = await (
                websocket.recv()
            )

            event = json.loads(
                message
            )

            print(
                "-" * 70
            )

            print(
                "LIVE EVENT RECEIVED"
            )

            print(
                "-" * 70
            )

            print("\nFULL EVENT:")
            print(json.dumps(event, indent=2))
            
            print(
                f"Source IP:       "
                f"{event.get('source_ip')}"
            )

            print(
                f"Threat Class:    "
                f"{event.get('threat_class')}"
            )

            print(
                f"Confidence:      "
                f"{event.get('confidence')}"
            )

            print(
                f"Risk Score:      "
                f"{event.get('risk_score')}"
            )

            print(
                f"Severity:        "
                f"{event.get('severity')}"
            )

            print()

            evidence = (
                event.get(
                    "evidence",
                    []
                )
            )

            if evidence:

                print(
                    "Evidence:"
                )

                for item in evidence:

                    print(
                        f"  {item}"
                    )

            print()


# ============================================================
# ENTRY POINT
# ============================================================

if __name__ == "__main__":

    asyncio.run(
        main()
    )