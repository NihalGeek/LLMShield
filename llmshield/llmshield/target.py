from .audit import AuditLog
from .guardrails import InputGuard, OutputGuard, REFUSAL
from .models import Mode, Response, Decision
from .providers import Provider
from .tools import SyntheticTools


class Target:
    def __init__(self, provider: Provider, audit: AuditLog | None = None):
        self.provider = provider
        self.audit = audit
        self.input_guard = InputGuard()
        self.output_guard = OutputGuard()

    def log(self, event, **fields):
        if self.audit:
            self.audit.emit(event, **fields)

    def chat(self, prompt: str, mode: Mode, context: str = '') -> Response:
        # Identity belongs to the application, never the model/user prompt.
        role = 'analyst'
        guarded = mode == Mode.GUARDED
        decisions = []
        if guarded:
            decision = self.input_guard.inspect(prompt, context, role)
            decisions.append(decision)
            self.log('guardrail_decision', mode=mode, **decision.model_dump())
            if decision.blocked:
                return Response(text=REFUSAL, decisions=decisions)
        proposal = self.provider.generate(prompt, context)
        store = SyntheticTools()
        attempts = []
        chunks = [proposal.text]
        for call in proposal.tool_calls:
            attempt = store.execute(call, role, guarded)
            attempts.append(attempt)
            decision = Decision(stage='tool', blocked=not attempt.executed, reason=attempt.reason)
            decisions.append(decision)
            self.log('tool_authorization', mode=mode, name=attempt.name, resource=attempt.resource,
                     authorized=attempt.authorized, executed=attempt.executed, role=role)
            if attempt.executed:
                chunks.append(attempt.result)
            else:
                chunks.append(REFUSAL)
        raw = '\n'.join(chunks)
        result = raw
        if guarded:
            decision = self.output_guard.inspect(raw, any(a.executed and not a.authorized for a in attempts))
            decisions.append(decision)
            self.log('guardrail_decision', mode=mode, **decision.model_dump())
            if decision.blocked:
                result = REFUSAL
        return Response(text=result, raw_text=raw, attempts=attempts, decisions=decisions)
