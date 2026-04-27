"""MCP server entrypoint for User Query Guard."""

from __future__ import annotations

import argparse
import os
import sys
from typing import Literal

from mcp.server.fastmcp import FastMCP

from query_guard.guard import QueryGuard
from query_guard.schema import GuardRequest

TransportName = Literal["stdio", "sse", "streamable-http"]

HOST = os.getenv("HOST", "127.0.0.1")
PORT = int(os.getenv("PORT", "8000"))

mcp = FastMCP("User Query Guard", host=HOST, port=PORT)
guard = QueryGuard()


@mcp.tool(name="query_guard_validate")
async def validate(
    user_query: str,
) -> dict[str, object]:
    """Validate whether a user query is safe before sending it to an AI application."""

    request = GuardRequest(user_query=user_query)
    response = await guard.validate(request)
    return response.model_dump(exclude_none=True)


def main() -> None:
    """Run the MCP server."""

    parser = argparse.ArgumentParser(description="Run the User Query Guard MCP server.")
    parser.add_argument(
        "--transport",
        choices=["stdio", "sse", "streamable-http"],
        default="stdio",
        help="Transport to use. Use stdio for MCP clients, streamable-http for local testing.",
    )
    args = parser.parse_args()
    transport: TransportName = args.transport

    if transport == "stdio":
        print("User Query Guard running on stdio.", file=sys.stderr)
    else:
        print(
            f"User Query Guard running with {transport} transport at http://{HOST}:{PORT}/mcp",
            file=sys.stderr,
        )

    mcp.run(transport=transport)


if __name__ == "__main__":
    main()
