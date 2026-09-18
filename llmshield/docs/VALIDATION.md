# Validation record

Validated on 17 September 2026 on Windows with the actual installed Python 3.12.6 and Ollama 0.34.1. Python and Ollama were absent from PATH but found under the user's installed Programs directories. A project-local virtual environment contains the installed dependencies. No new model download was needed.

## Completed checks

- Ran the deliberately vulnerable simulator target and confirmed synthetic secret disclosure; guarded mode refused it.
- Executed the same 24-case suite in both modes for the mock and local `qwen2.5:3b`, with separate saved artifacts.
- Recomputed report metrics from persisted result rows and checked exact agreement with stored metrics.
- Ran 69 pytest tests covering loading, schema rejection, all evaluator categories, canary normalization, independent tool/resource permissions, hostile providers, input/output controls, request isolation, persistence, paired retests, report escaping, local-provider restrictions and HTTP endpoints.
- Started the real Uvicorn service bound to `127.0.0.1:8765`.
- Used the browser to run an assessment, observe completion, inspect a finding, view saved Qwen results from history, and render the live report.
- Performed a separate live HTTP end-to-end check; details and run IDs are in `reports/live-validation.json`.
- Checked persistence after restarting the actual server; the live validation artifact records the outcome.

## Evidence files

- `reports/pytest-results.xml`: automated test result and duration.
- `reports/mock-assessment.json` and `.html`: paired deterministic simulation evidence.
- `reports/qwen-assessment.json` and `.html`: paired real local-model evidence.
- `reports/live-validation.json`: actual HTTP checks and restart persistence.
- Runtime-only `data/llmshield.sqlite3` and `data/security.jsonl`: all executed runs and structured audit events, ignored by Git.

The original inference responses and verdicts were preserved. A later presentation refinement added attack context and more precise impact/remediation to derived findings, and report metrics were checked again. The guardrail diagnostic leak fix does not change provider prompts or evaluator outcomes; its serialized API regression test passes.

## Observed limitations, not hidden failures

Qwen guarded results include one benign failure and four reviews. An allowed incident read was refused by the model in both modes. These are assessment findings, not failures in the regression suite. Several baseline attack failures are forbidden marker echoes in refusals, not evidence of executed harmful actions. The report explains that exact contract.

Pytest emits two dependency deprecation warnings from Starlette/AnyIO's TestClient integration. All tests pass. No warning is suppressed. Tests use HTTPX MockTransport for provider boundary checks and never depend on a paid or remote LLM.

Automated PDF export, multi-turn attacks, production identity, durable task scheduling and a trained guardrail detector are not implemented. HTML is the delivered report format; it can be printed to PDF manually. See the README for direct Windows commands, model selection, the single-process database constraint and reproduction details.
