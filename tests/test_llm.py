import pytest

from query_guard.llm import LLMConfig, LLMValidationError, LLMValidator


def test_openai_request_uses_chat_completions_endpoint() -> None:
    payload, url, headers = LLMValidator()._build_request(
        "hello",
        LLMConfig(provider="openai", model_name="gpt-4o-mini", api_key="secret"),
    )

    assert url == "https://api.openai.com/v1/chat/completions"
    assert headers["Authorization"] == "Bearer secret"
    assert payload["model"] == "gpt-4o-mini"


def test_groq_request_uses_openai_compatible_endpoint() -> None:
    payload, url, headers = LLMValidator()._build_request(
        "hello",
        LLMConfig(provider="groq", model_name="llama-3.1-8b-instant", api_key="secret"),
    )

    assert url == "https://api.groq.com/openai/v1/chat/completions"
    assert headers["Authorization"] == "Bearer secret"
    assert payload["model"] == "llama-3.1-8b-instant"


def test_gemini_request_uses_generate_content_endpoint() -> None:
    payload, url, headers = LLMValidator()._build_request(
        "hello",
        LLMConfig(provider="gemini", model_name="gemini-1.5-flash", api_key="secret"),
    )

    assert url == (
        "https://generativelanguage.googleapis.com/v1beta/models/"
        "gemini-1.5-flash:generateContent?key=secret"
    )
    assert headers["Content-Type"] == "application/json"
    assert payload["generationConfig"] == {"responseMimeType": "application/json"}


def test_azure_request_uses_deployment_endpoint() -> None:
    payload, url, headers = LLMValidator()._build_request(
        "hello",
        LLMConfig(
            provider="azure_openai",
            model_name="deployment",
            api_key="secret",
            azure_endpoint="https://example.openai.azure.com/",
            azure_api_version="2024-10-21",
        ),
    )

    assert url == (
        "https://example.openai.azure.com/openai/deployments/deployment/"
        "chat/completions?api-version=2024-10-21"
    )
    assert headers["api-key"] == "secret"
    assert payload["model"] == "deployment"


def test_azure_request_includes_custom_headers() -> None:
    _, _, headers = LLMValidator()._build_request(
        "hello",
        LLMConfig(
            provider="azure_openai",
            model_name="deployment",
            api_key="secret",
            azure_endpoint="https://example.openai.azure.com",
            azure_headers={
                "x-ms-client-request-id": "request-123",
                "Ocp-Apim-Subscription-Key": "apim-secret",
            },
        ),
    )

    assert headers["x-ms-client-request-id"] == "request-123"
    assert headers["Ocp-Apim-Subscription-Key"] == "apim-secret"
    assert headers["api-key"] == "secret"


def test_custom_headers_do_not_apply_to_openai_request() -> None:
    _, _, headers = LLMValidator()._build_request(
        "hello",
        LLMConfig(
            provider="openai",
            model_name="gpt-4o-mini",
            api_key="secret",
            azure_headers={"x-ms-client-request-id": "request-123"},
        ),
    )

    assert "x-ms-client-request-id" not in headers


def test_azure_request_requires_endpoint() -> None:
    with pytest.raises(LLMValidationError):
        LLMValidator()._build_request(
            "hello",
            LLMConfig(provider="azure_openai", model_name="deployment", api_key="secret"),
        )


@pytest.mark.asyncio
async def test_validate_returns_completion_endpoint_url(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def fake_post_json(
        self: LLMValidator,
        url: str,
        headers: dict[str, str],
        payload: dict[str, object],
    ) -> dict[str, object]:
        return {
            "choices": [
                {
                    "message": {
                        "content": (
                            '{"is_valid": true, "category": "safe", '
                            '"risk_score": 0.0, "reason": "ok"}'
                        )
                    }
                }
            ]
        }

    monkeypatch.setattr(LLMValidator, "_post_json", fake_post_json)

    result = await LLMValidator().validate(
        "hello",
        LLMConfig(provider="openai", model_name="gpt-4o-mini", api_key="secret"),
    )

    assert result.completion_endpoint_url == "https://api.openai.com/v1/chat/completions"


def test_parse_invalid_llm_response_adds_safe_response() -> None:
    result = LLMValidator()._parse_guard_response(
        '{"is_valid": false, "category": "jailbreak", "risk_score": 0.9, "reason": "bypass"}'
    )

    assert result.is_valid is False
    assert result.category == "jailbreak"
    assert result.safe_response == (
        "I can't help with jailbreak attempts or bypassing safety controls."
    )


def test_parse_safe_llm_response_normalizes_category() -> None:
    result = LLMValidator()._parse_guard_response(
        '{"is_valid": true, "category": "unknown", "risk_score": 0.1, "reason": "ok"}'
    )

    assert result.is_valid is True
    assert result.category == "safe"
