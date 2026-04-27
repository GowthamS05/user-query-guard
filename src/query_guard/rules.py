"""Lightweight local detection rules for user queries."""

from __future__ import annotations

import re
from collections.abc import Iterable
from dataclasses import dataclass

from query_guard.schema import GuardCategory, GuardResponse, RuleDecision

SAFE_RESPONSE_BY_CATEGORY: dict[GuardCategory, str] = {
    "prompt_injection": "I can't follow instructions that try to override safety or system rules.",
    "jailbreak": "I can't help with jailbreak attempts or bypassing safety controls.",
    "system_prompt_extraction": "I can't help reveal system prompts or hidden instructions.",
    "xss": "I can't help create or execute malicious scripts.",
    "sql_injection": "I can't help craft SQL injection or database abuse payloads.",
    "profanity": "Please rephrase the request without abusive or profane language.",
    "sexual_content": "I can't help with explicit sexual requests.",
    "hate": "I can't help produce hateful or dehumanizing content.",
    "violence": "I can't help with violent harmful instructions.",
    "self_harm": (
        "I'm sorry you're dealing with this. Please contact local emergency services "
        "or a crisis hotline if you may be in immediate danger."
    ),
    "llm_poisoning": "I can't help poison model, agent, tool, or retrieval instructions.",
    "unknown": "I can't validate this request safely.",
    "safe": "",
}


@dataclass(frozen=True)
class Rule:
    category: GuardCategory
    patterns: tuple[re.Pattern[str], ...]
    risk_score: float
    reason: str

    def matches(self, query: str) -> bool:
        return any(pattern.search(query) for pattern in self.patterns)


def _compile(patterns: Iterable[str]) -> tuple[re.Pattern[str], ...]:
    return tuple(re.compile(pattern, re.IGNORECASE | re.DOTALL) for pattern in patterns)


def _keyword_patterns(keywords: Iterable[str]) -> tuple[re.Pattern[str], ...]:
    """Compile literal keywords with word boundaries where they are safe to use."""

    patterns: list[str] = []
    for keyword in keywords:
        escaped = re.escape(keyword.strip())
        if re.fullmatch(r"[\w\s-]+", keyword):
            escaped = escaped.replace(r"\ ", r"\s+").replace(r"\-", r"[-\s]+")
            patterns.append(rf"(?<!\w){escaped}(?!\w)")
        else:
            patterns.append(escaped)
    return _compile(patterns)


BLOCK_RULES: tuple[Rule, ...] = (
    Rule(
        category="system_prompt_extraction",
        patterns=(
            *_keyword_patterns(
                [
                    "system prompt",
                    "developer message",
                    "hidden instructions",
                    "initial instructions",
                    "internal prompt",
                    "private instructions",
                ]
            ),
            *_compile(
                [
                r"\b(sys(?:tem)?|syst[e]?m|syatem|developer|hidden)\s+(prompt|instruction|message)s?\b",
                (
                    r"\b(reveal|show|print|display|dump|leak|expose)\b.{0,60}"
                    r"\b(prompt|instruction|sys(?:tem)? message|syatem message)s?\b"
                ),
                r"\bwhat (are|were) your (initial|sys(?:tem)?|syatem|hidden) instructions\b",
                ]
            ),
        ),
        risk_score=0.95,
        reason="The query asks to reveal hidden system instructions.",
    ),
    Rule(
        category="prompt_injection",
        patterns=(
            *_keyword_patterns(
                [
                    "prompt injection",
                    "ignore previous instructions",
                    "ignore prior instructions",
                    "disregard previous instructions",
                    "override instructions",
                    "override safety",
                    "reveal secrets",
                    "dump secrets",
                    "environment variables",
                    "private key",
                    "ssh key",
                    "access token",
                    "secret key",
                ]
            ),
            *_compile(
                [
                r"\bignore (all )?(previous|prior|above|earlier) (instructions|rules|messages)\b",
                (
                    r"\bdisregard (all )?(previous|prior|above|earlier) "
                    r"(instructions|rules|messages)\b"
                ),
                r"\boverride (the )?(system|developer|safety) (prompt|instructions|rules)\b",
                r"\bact as if (the )?(rules|policy|instructions) do not apply\b",
                (
                    r"\b(use|call|invoke)\b.{0,60}\b(tool|function|plugin)\b.{0,80}"
                    r"\b(without permission|silently|secretly)\b"
                ),
                r"\bexfiltrate\b.{0,80}\b(data|secret|credential|api key|token|file)\b",
                r"\bsteal\b.{0,80}\b(data|secret|credential|api key|token|file)\b",
                ]
            ),
        ),
        risk_score=0.9,
        reason="The query attempts to override instructions or abuse connected tools.",
    ),
    Rule(
        category="prompt_injection",
        patterns=_compile(
            [
                r"\b(rm\s+-rf\s+/|rm\s+-rf\s+\*|del\s+/f\s+/q)\b",
                r"\b(curl|wget)\b.{0,80}\|\s*(sh|bash|zsh|python|python3)\b",
                r";\s*(cat|less|more|type)\s+/(etc/passwd|etc/shadow)\b",
                r"\b(cat|less|more|type)\s+/(etc/passwd|etc/shadow)\b",
                r"\b(base64\s+-d|chmod\s+\+x)\b.{0,120}\b(sh|bash|zsh)\b",
            ]
        ),
        risk_score=0.92,
        reason="The query contains command injection or destructive shell command patterns.",
    ),
    Rule(
        category="prompt_injection",
        patterns=_compile(
            [
                r"(\.\./){2,}",
                r"\b(read|show|print|dump|open|cat)\b.{0,80}\b(~/.ssh/id_rsa|/etc/shadow|/etc/passwd)\b",
                r"\b(read|show|print|dump|open|cat)\b.{0,80}\b(\.env|environment variables?)\b",
                (
                    r"\b(show|print|dump|list)\b.{0,80}"
                    r"\b(api keys?|access tokens?|secret keys?|credentials)\b"
                ),
                (
                    r"\b(send|post|upload|exfiltrate)\b.{0,80}"
                    r"\b(secrets?|credentials?|tokens?|api keys?)\b.{0,80}"
                    r"\b(webhook|url|server)\b"
                ),
            ]
        ),
        risk_score=0.92,
        reason="The query attempts path traversal, local file access, or secret exfiltration.",
    ),
    Rule(
        category="prompt_injection",
        patterns=_compile(
            [
                r"\b(fake|phishing|spoofed?)\b.{0,80}\b(login|sign[- ]?in|password|otp|2fa|mfa)\b",
                (
                    r"\b(steal|harvest|capture|collect)\b.{0,80}"
                    r"\b(passwords?|otp|2fa codes?|mfa codes?|credentials?)\b"
                ),
                r"\btrick\b.{0,80}\b(users?|people|victims?)\b.{0,80}\b(passwords?|otp|credentials?)\b",
                r"\bcredential harvesting\b",
            ]
        ),
        risk_score=0.9,
        reason="The query appears to request phishing or credential theft.",
    ),
    Rule(
        category="violence",
        patterns=_compile(
            [
                r"\b(ransomware|keylogger|rootkit|trojan|spyware|stealer|botnet)\b",
                (
                    r"\b(steal|dump|exfiltrate)\b.{0,80}"
                    r"\b(browser cookies?|session cookies?|chrome cookies?)\b"
                ),
                r"\b(encrypt|lock)\b.{0,80}\b(files?|drive|disk)\b.{0,80}\b(ransom|payment|bitcoin|crypto)\b",
                r"\b(persistence|privilege escalation)\b.{0,80}\b(malware|payload|backdoor)\b",
                r"\b(reverse shell|bind shell)\b",
            ]
        ),
        risk_score=0.93,
        reason="The query requests malware, credential theft, or unauthorized system access.",
    ),
    Rule(
        category="prompt_injection",
        patterns=_compile(
            [
                r"\b(169\.254\.169\.254|metadata\.google\.internal)\b",
                r"\b(fetch|curl|wget|request)\b.{0,80}\b(metadata|meta-data|iam credentials?)\b",
                (
                    r"\b(scan|probe|enumerate)\b.{0,80}"
                    r"\b(localhost|127\.0\.0\.1|internal network|private network)\b"
                ),
                r"\b(ssrf|server[- ]side request forgery)\b",
            ]
        ),
        risk_score=0.9,
        reason="The query appears to request SSRF or internal network probing.",
    ),
    Rule(
        category="jailbreak",
        patterns=(
            *_keyword_patterns(
                [
                    "jailbreak",
                    "do anything now",
                    "dan mode",
                    "developer mode",
                    "unrestricted mode",
                    "bypass safety",
                    "bypass policy",
                    "no safety restrictions",
                ]
            ),
            *_compile(
                [
                r"\b(DAN|do anything now)\b",
                r"\bpretend you are unrestricted\b",
                r"\bno (safety|ethical|policy) restrictions\b",
                ]
            ),
        ),
        risk_score=0.9,
        reason="The query appears to be a jailbreak attempt.",
    ),
    Rule(
        category="prompt_injection",
        patterns=_compile(
            [
                # ...existing code...
                r"\bforget (everything|all you know|all prior knowledge|whatever you know)\b",
                r"\bwhatever you know\b.{0,40}\b(share|show|give|provide|print|reveal)\b",
                r"\bshow\b.{0,40}\b(response|output|result)\b.{0,40}\b(html|markdown|json|xml)\b",
            ]
        ),
        risk_score=0.9,
        reason="The query attempts to override instructions, extract knowledge.",
    ),
    Rule(
        category="llm_poisoning",
        patterns=(
            *_keyword_patterns(
                [
                    "indirect prompt injection",
                    "malicious context injection",
                    "malicious rag injection",
                    "poison rag",
                    "poison retrieval",
                    "poison memory",
                    "poison embeddings",
                ]
            ),
            *_compile(
                [
                r"\bpoison\b.{0,80}\b(model|llm|rag|retrieval|embedding|agent|memory)\b",
                (
                    r"\bwhen (an|the) (ai|assistant|agent|model) reads this\b.{0,120}"
                    r"\b(ignore|exfiltrate|leak|override)\b"
                ),
                (
                    r"\badd this to (your|the) "
                    r"(memory|context|retrieval|knowledge base)\b.{0,120}"
                    r"\b(ignore|leak|exfiltrate|override)\b"
                ),
                r"\bmalicious (document|context|retrieval|rag) (injection|payload)\b",
                ]
            ),
        ),
        risk_score=0.9,
        reason="The query attempts to poison model, agent, or retrieval behavior.",
    ),
    Rule(
        category="xss",
        patterns=(
            *_keyword_patterns(
                [
                    "<script",
                    "javascript:",
                    "document.cookie",
                    "onerror=",
                    "onload=",
                    "alert(",
                ]
            ),
            *_compile(
                [
                r"<\s*script\b[^>]*>.*?<\s*/\s*script\s*>",
                r"\bon\w+\s*=\s*['\"][^'\"]*['\"]",
                r"<\s*img\b[^>]*\bonerror\s*=",
                ]
            ),
        ),
        risk_score=0.92,
        reason="The query contains a script-like injection payload.",
    ),
    Rule(
        category="sql_injection",
        patterns=(
            *_keyword_patterns(
                [
                    "union select",
                    "drop table",
                    "sql injection",
                    "sqlmap",
                    "xp_cmdshell",
                    "' or 1=1",
                    "\" or 1=1",
                ]
            ),
            *_compile(
                [
                r"('|%27)\s*(or|and)\s*('|%27)?\s*\d+\s*=\s*\d+",
                r";\s*(drop|delete|truncate|alter)\s+(table|database)\b",
                r"--\s*$",
                ]
            ),
        ),
        risk_score=0.9,
        reason="The query contains SQL injection style input.",
    ),
    Rule(
        category="sexual_content",
        patterns=(
            *_keyword_patterns(
                [
                    "hardcore porn",
                    "explicit sex",
                    "graphic sex",
                    "erotic roleplay",
                    "sexual content involving minors",
                ]
            ),
            *_compile(
                [
                r"\b(porn|pornographic|explicit sex|hardcore|erotic roleplay)\b",
                r"\b(write|generate|describe)\b.{0,50}\b(explicit|graphic)\b.{0,50}\b(sex|sexual)\b",
                ]
            ),
        ),
        risk_score=0.88,
        reason="The query requests explicit sexual content.",
    ),
    Rule(
        category="profanity",
        patterns=(
            *_keyword_patterns(
                [
                    "fuck",
                    "fucks",
                    "fucked",
                    "fucker",
                    "fucking",
                    "fuk",
                    "fck",
                ]
            ),
            *_compile(
                [
                    r"(?<!\w)f[\W_]*u[\W_]*c[\W_]*k(?:e[rd]?|ing|s)?(?!\w)",
                    r"(?<!\w)f[\W_]*u[\W_]*k(?:e[rd]?|ing|s)?(?!\w)",
                    r"(?<!\w)f[\W_]*c[\W_]*k(?:e[rd]?|ing|s)?(?!\w)",
                    r"(?<!\w)f[\W_]{2,}k?(?!\w)",
                ]
            ),
        ),
        risk_score=0.7,
        reason="The query contains abusive or profane language.",
    ),
    Rule(
        category="hate",
        patterns=(
            *_keyword_patterns(
                [
                    "hate speech",
                    "racial slur",
                    "ethnic cleansing",
                    "dehumanizing propaganda",
                ]
            ),
            *_compile(
                [
                r"\b(genocide|exterminate|eliminate)\b.{0,60}\b(race|religion|ethnic|minority|immigrants)\b",
                r"\bwrite\b.{0,50}\b(hate speech|racist slur|dehumanizing)\b",
                r"\bwhy (are|is)\b.{0,80}\b(inferior|subhuman)\b",
                ]
            ),
        ),
        risk_score=0.86,
        reason="The query appears to request hateful harmful content.",
    ),
    Rule(
        category="violence",
        patterns=(
            *_keyword_patterns(
                [
                    "bomb making",
                    "explosive recipe",
                    "homemade explosive",
                    "molotov cocktail",
                    "kill someone",
                    "assassination plan",
                    "make a weapon",
                ]
            ),
            *_compile(
                [
                r"\bhow to\b.{0,80}\b(kill|murder|assassinate|maim)\b",
                r"\bmake\b.{0,40}\b(bomb|explosive|molotov|weapon)\b",
                r"\bthreaten\b.{0,60}\b(with violence|to kill|to hurt)\b",
                ]
            ),
        ),
        risk_score=0.9,
        reason="The query requests violent harmful content.",
    ),
    Rule(
        category="self_harm",
        patterns=(
            *_keyword_patterns(
                [
                    "kill myself",
                    "end my life",
                    "commit suicide",
                    "suicide method",
                    "self harm instructions",
                    "best way to die",
                ]
            ),
            *_compile(
                [
                r"\bhow (do|can) i\b.{0,60}\b(kill myself|end my life|commit suicide)\b",
                r"\bencourage\b.{0,60}\b(suicide|self-harm|self harm)\b",
                r"\bbest way to\b.{0,60}\b(self-harm|self harm|die by suicide)\b",
                ]
            ),
        ),
        risk_score=0.95,
        reason="The query asks for self-harm encouragement or instructions.",
    ),
)


def validate_with_rules(user_query: str) -> RuleDecision:
    """Validate a query locally with lightweight deterministic block rules."""

    normalized = user_query.strip()
    lowered = normalized.lower()

    for rule in BLOCK_RULES:
        if rule.matches(lowered):
            return RuleDecision(
                matched=True,
                confident=True,
                response=GuardResponse(
                    is_valid=False,
                    category=rule.category,
                    risk_score=rule.risk_score,
                    reason=rule.reason,
                    safe_response=SAFE_RESPONSE_BY_CATEGORY[rule.category],
                ),
            )

    return RuleDecision(
        matched=False,
        confident=True,
        response=GuardResponse(
            is_valid=True,
            category="safe",
            risk_score=0.0,
            reason="No block rules matched, so the query is considered safe.",
        ),
    )
