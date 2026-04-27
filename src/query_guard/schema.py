"""Public request and response schemas for User Query Guard."""

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_serializer

GuardCategory = Literal[
    "safe",
    "prompt_injection",
    "jailbreak",
    "system_prompt_extraction",
    "xss",
    "sql_injection",
    "sexual_content",
    "hate",
    "violence",
    "self_harm",
    "llm_poisoning",
    "unknown",
]


class GuardRequest(BaseModel):
    """Input accepted by query_guard_validate."""

    user_query: str = Field(min_length=1)


class GuardResponse(BaseModel):
    """Structured validation result returned by query_guard_validate."""

    model_config = ConfigDict(extra="forbid")

    is_valid: bool
    category: GuardCategory
    risk_score: float = Field(ge=0.0, le=1.0)
    reason: str = Field(min_length=1)
    safe_response: str | None = None

    @field_serializer("safe_response")
    def omit_empty_safe_response(self, value: str | None) -> str | None:
        return value or None


class RuleDecision(BaseModel):
    """Internal result from local rule evaluation."""

    matched: bool
    confident: bool
    response: GuardResponse
