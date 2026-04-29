"""MCP server entrypoint for User Query Guard."""

from __future__ import annotations

import argparse
import json
import os
import sys
from typing import Literal, cast

from mcp.server.fastmcp import FastMCP

from query_guard.guard import QueryGuard
from query_guard.schema import GuardRequest, LLMProvider

TransportName = Literal["stdio", "sse", "streamable-http"]

HOST = os.getenv("HOST", "127.0.0.1")
PORT = int(os.getenv("PORT", "8000"))

mcp = FastMCP("User Query Guard", host=HOST, port=PORT)
guard = QueryGuard()


def _env_value(name: str) -> str | None:
    value = os.getenv(name)
    return value or None


def _env_llm_provider() -> LLMProvider | None:
    value = _env_value("QUERY_GUARD_LLM_PROVIDER")
    if value is None:
        return None
    return cast(LLMProvider, value)


def _env_json_dict(name: str) -> dict[str, str] | None:
    value = _env_value(name)
    if value is None:
        return None

    parsed = json.loads(value)
    if not isinstance(parsed, dict) or not all(
        isinstance(key, str) and isinstance(item, str) for key, item in parsed.items()
    ):
        raise ValueError(f"{name} must be a JSON object with string keys and string values.")
    return parsed


@mcp.tool(name="query_guard_validate")
async def validate(
    user_query: str,
    llm_provider: LLMProvider | None = None,
    model_name: str | None = None,
    api_key: str | None = None,
    azure_endpoint: str | None = None,
    azure_api_version: str | None = None,
    azure_headers: dict[str, str] | None = None,
) -> dict[str, object]:
    """Validate whether a user query is safe before sending it to an AI application."""

    request = GuardRequest(
        user_query=user_query,
        llm_provider=llm_provider or _env_llm_provider(),
        model_name=model_name or _env_value("QUERY_GUARD_MODEL_NAME"),
        api_key=api_key or _env_value("QUERY_GUARD_API_KEY"),
        azure_endpoint=azure_endpoint or _env_value("QUERY_GUARD_AZURE_ENDPOINT"),
        azure_api_version=azure_api_version
        or _env_value("QUERY_GUARD_AZURE_API_VERSION")
        or "2024-02-15-preview",
        azure_headers=azure_headers or _env_json_dict("QUERY_GUARD_AZURE_HEADERS"),
    )
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
