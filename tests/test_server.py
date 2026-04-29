import pytest

from query_guard.server import _env_json_dict, validate


@pytest.mark.asyncio
async def test_validate_uses_rules_only_without_env_or_params(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("QUERY_GUARD_LLM_PROVIDER", raising=False)
    monkeypatch.delenv("QUERY_GUARD_MODEL_NAME", raising=False)
    monkeypatch.delenv("QUERY_GUARD_API_KEY", raising=False)
    monkeypatch.delenv("QUERY_GUARD_AZURE_ENDPOINT", raising=False)
    monkeypatch.delenv("QUERY_GUARD_AZURE_API_VERSION", raising=False)
    monkeypatch.delenv("QUERY_GUARD_AZURE_HEADERS", raising=False)

    result = await validate(user_query="hello")

    assert result["is_valid"] is True
    assert result["category"] == "safe"
    assert result["reason"] == "No block rules matched, so the query is considered safe."


def test_env_json_dict_reads_azure_headers(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("QUERY_GUARD_AZURE_HEADERS", '{"x-ms-client-request-id": "test"}')

    result = _env_json_dict("QUERY_GUARD_AZURE_HEADERS")

    assert result == {"x-ms-client-request-id": "test"}
