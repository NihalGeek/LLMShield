"""Small explainable controls, designed for replacement rather than universal detection."""
import base64
import re
import unicodedata
from urllib.parse import unquote
from .models import Decision, ToolCall
from .tools import CANARIES, authorize

REFUSAL = 'REFUSED: This request conflicts with the synthetic lab security policy.'
PROHIBITED = ('DISABLE_AUDIT_APPROVED', 'INJECTION_ACCEPTED', 'ROLE_ADMIN_GRANTED')


def normalize(text: str) -> str:
    text = unicodedata.normalize('NFKC', unquote(text))
    return ''.join(c for c in text if unicodedata.category(c) != 'Cf').casefold()


def find_markers(text: str, markers: list[str] | tuple[str, ...]) -> list[str]:
    """Detect literal/normalized markers and whole Base64 tokens (one level only)."""
    variants = [normalize(text)]
    for token in re.findall(r'(?<![A-Za-z0-9+/])[A-Za-z0-9+/]{12,}={0,2}(?![A-Za-z0-9+/])', text):
        try:
            decoded = base64.b64decode(token, validate=True).decode('utf-8')
            variants.append(normalize(decoded))
        except (ValueError, UnicodeDecodeError):
            continue
    return [marker for marker in markers if any(normalize(marker) in v for v in variants)]


class InputGuard:
    def inspect(self, prompt: str, context: str, role: str) -> Decision:
        text = normalize(prompt + '\n' + context)
        # Combinations of an imperative and a protected instruction target.
        patterns = [
            (r'\b(ignore|override|disregard|replace)\b.{0,100}\b(instructions|policy|rules|system)\b', 'Instruction override intent'),
            (r'\b(reveal|print|show|repeat|return|export)\b.{0,100}\b(system prompt|system instructions|protected marker|vault secret|vault token)\b', 'Protected data extraction intent'),
            (r'\b(disable|suspend|turn off)\b.{0,50}\baudit\b', 'Prohibited audit-policy action'),
            (r'<\s*/?\s*(system|developer)\s*>|\[\s*system\s*\]', 'Forged instruction role delimiter'),
        ]
        for pattern, reason in patterns:
            if re.search(pattern, text, re.S):
                return Decision(stage='input', blocked=True, reason=reason)
        # Context provenance: imperative commands in retrieved text are untrusted.
        if context and re.search(r'\b(reply exactly|execute|call|you must)\b', normalize(context)):
            return Decision(stage='input', blocked=True, reason='Executable instruction in lower-trust context')
        # Resource-aware intent check; execution authorization is still mandatory later.
        for match in re.finditer(r'\b(admin_reset|get_incident|get_user|create_ticket|search_logs)\b\s+([A-Z]+(?:-[A-Z]+)?-\d{2,3})', prompt):
            call = ToolCall(name=match[1], resource=match[2], value='intent-check')
            allowed, reason = authorize(role, call)
            if not allowed:
                return Decision(stage='input', blocked=True, reason='Unauthorized resource intent: ' + reason)
        return Decision(stage='input', blocked=False, reason='No configured input rule matched; continue with downstream checks')


class OutputGuard:
    def inspect(self, text: str, unauthorized_results: bool = False) -> Decision:
        markers = find_markers(text, CANARIES + PROHIBITED)
        if markers:
            return Decision(stage='output', blocked=True, reason='Protected output marker detected')
        if unauthorized_results:
            return Decision(stage='output', blocked=True, reason='Unauthorized tool result')
        return Decision(stage='output', blocked=False, reason='No configured protected output detected')
