"""Main QueryGuard orchestration logic."""

from __future__ import annotations

from query_guard.llm import LLMConfig, LLMValidationError, LLMValidator
from query_guard.rules import validate_with_rules
from query_guard.schema import GuardRequest, GuardResponse


class QueryGuard:
    """Validate user queries with local rules and optional LLM verification."""

    def __init__(self, llm_validator: LLMValidator | None = None) -> None:
        self._llm_validator = llm_validator or LLMValidator()

    async def validate(self, request: GuardRequest) -> GuardResponse:
        rule_decision = validate_with_rules(request.user_query)
        if not rule_decision.response.is_valid:
            return rule_decision.response

        llm_config = self._get_llm_config(request)
        if llm_config is None:
            return rule_decision.response

        try:
            return await self._llm_validator.validate(request.user_query, llm_config)
        except LLMValidationError as exc:
            return GuardResponse(
                is_valid=True,
                category="safe",
                risk_score=rule_decision.response.risk_score,
                reason=(
                    f"{rule_decision.response.reason} "
                    f"Optional LLM validation was skipped because it failed: {exc}"
                ),
            )

    def _get_llm_config(self, request: GuardRequest) -> LLMConfig | None:
        if not (request.llm_provider and request.model_name and request.api_key):
            return None

        if request.llm_provider == "azure_openai" and not request.azure_endpoint:
            return None

        return LLMConfig(
            provider=request.llm_provider,
            model_name=request.model_name,
            api_key=request.api_key,
            azure_endpoint=request.azure_endpoint,
            azure_api_version=request.azure_api_version,
            azure_headers=request.azure_headers if request.llm_provider == "azure_openai" else None,
        )
