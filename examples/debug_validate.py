"""Debug User Query Guard from a code editor without MCP Inspector or Claude Desktop.

This script calls the same server.validate function used by the MCP tool, but it
runs as normal Python so editor breakpoints work reliably.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import os

from query_guard.server import validate


async def run() -> None:
    parser = argparse.ArgumentParser(description="Debug query_guard_validate locally.")
    parser.add_argument(
        "user_query",
        nargs="?",
        default="hello",
        help="Query text to validate",
    )
    parser.add_argument(
        "--llm-provider",
        choices=["groq", "gemini", "openai", "azure_openai"],
        default=os.getenv("QUERY_GUARD_LLM_PROVIDER"),
        help="Optional LLM provider for safe rule results.",
    )
    parser.add_argument(
        "--model-name",
        default=os.getenv("QUERY_GUARD_MODEL_NAME"),
        help="Optional model name. For Azure OpenAI, use the deployment name.",
    )
    parser.add_argument(
        "--api-key",
        default=os.getenv("QUERY_GUARD_API_KEY"),
        help="Optional provider API key.",
    )
    parser.add_argument(
        "--azure-endpoint",
        default=os.getenv("QUERY_GUARD_AZURE_ENDPOINT"),
        help="Optional Azure OpenAI endpoint, for example https://name.openai.azure.com.",
    )
    parser.add_argument(
        "--azure-api-version",
        default=os.getenv("QUERY_GUARD_AZURE_API_VERSION", "2024-02-15-preview"),
        help="Optional Azure OpenAI API version.",
    )
    parser.add_argument(
        "--azure-headers",
        default=os.getenv("QUERY_GUARD_AZURE_HEADERS"),
        help='Optional Azure-only custom headers as JSON, for example {"x-custom": "value"}.',
    )
    args = parser.parse_args()
    azure_headers = json.loads(args.azure_headers) if args.azure_headers else None

    result = await validate(
        user_query=args.user_query,
        llm_provider=args.llm_provider,
        model_name=args.model_name,
        api_key=args.api_key,
        azure_endpoint=args.azure_endpoint,
        azure_api_version=args.azure_api_version,
        azure_headers=azure_headers,
    )
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    asyncio.run(run())
