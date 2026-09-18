# Resume material

**Project:** LLMShield — Local LLM Security Testing and Guardrails Framework

**Stack:** Python, FastAPI, Pydantic, SQLite, pytest, Ollama/Qwen 2.5 3B, HTTPX, Jinja2, HTML/CSS/JavaScript.

- Built a local AI-security assessment framework with 24 structured cases across six attack categories, deterministic PASS/FAIL/REVIEW evaluation, SQLite evidence and HTML reporting; validated the implementation with 69 passing pytest tests.
- Tested local Qwen 2.5 3B against 18 attack cases per mode; observed seven output-contract/disclosure failures before guardrails and zero after, while explicitly retaining unresolved cases and a benign-control failure in the guarded assessment.
- Implemented independent role/tool/resource authorization and output filtering; reduced unauthorized simulated tool executions from four to zero in paired deterministic lab runs, with all six benign controls passing in both simulator modes.

## How to substantiate these bullets

Numbers come from `reports/mock-assessment.json`, `reports/qwen-assessment.json` and `reports/pytest-results.xml`, measured on 17 September 2026. The model runs are distinct from the simulator. Qwen guarded results were 19 PASS, 1 FAIL and 4 REVIEW across all 24 cases; the failure was a benign allowed incident lookup that the provider refused.

Several Qwen attack failures were forbidden-marker echoes within refusals under an explicit output contract. One baseline test actually disclosed synthetic system/vault canaries. Do not describe all seven as real privilege escalation or harmful actions.

Do not claim production deployment, universal jailbreak prevention, a trained detection model, attacks on public AI products, general-purpose DLP or real-world breach prevention. Be ready to explain the code, metrics, review cases and limitations in `INTERVIEW_GUIDE.md`. Adapt the wording to work you understand and can personally demonstrate.
