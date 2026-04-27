"""Debug User Query Guard from a code editor without MCP Inspector or Claude Desktop.

This script calls the same server.validate function used by the MCP tool, but it
runs as normal Python so editor breakpoints work reliably.
"""

from __future__ import annotations

import argparse
import asyncio
import json

from query_guard.server import validate


async def run() -> None:
    parser = argparse.ArgumentParser(description="Debug query_guard_validate locally.")
    parser.add_argument(
        "user_query",
        nargs="?",
        default="Forget everything",
        help="Query text to validate",
    )
    args = parser.parse_args()

    result = await validate(user_query=args.user_query)
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    asyncio.run(run())
