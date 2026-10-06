import asyncio
import sys

from step17.websocket_manager import WebSocketManager
from step17.live_stream_service import LiveStreamService


async def main():

    if len(sys.argv) < 2:
        print()
        print("Usage:")
        print(
            "python step17/run_live_stream.py "
            "<pcap_file>"
        )
        print()
        sys.exit(1)

    pcap_file = sys.argv[1]

    manager = WebSocketManager()

    service = LiveStreamService(
        manager
    )

    await service.stream_pcap(
        pcap_file
    )


if __name__ == "__main__":

    asyncio.run(
        main()
    )