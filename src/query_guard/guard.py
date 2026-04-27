"""Main QueryGuard orchestration logic."""

from __future__ import annotations

from query_guard.rules import validate_with_rules
from query_guard.schema import GuardRequest, GuardResponse


class QueryGuard:
    """Validate user queries with local rules only."""

    async def validate(self, request: GuardRequest) -> GuardResponse:
        rule_decision = validate_with_rules(request.user_query)
        return rule_decision.response
