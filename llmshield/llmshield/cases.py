import hashlib
import json
from pathlib import Path
from .config import PACKAGE
from .models import TestCase


def load_cases(path: Path | None = None) -> list[TestCase]:
    raw = json.loads((path or PACKAGE / 'test_cases/starter.json').read_text(encoding='utf-8-sig'))
    if not isinstance(raw, list) or not raw or len(raw) > 500:
        raise ValueError('Suite must contain 1-500 cases')
    cases = [TestCase.model_validate(row) for row in raw]
    if len({c.id for c in cases}) != len(cases):
        raise ValueError('Duplicate test IDs')
    return cases


def suite_hash(cases: list[TestCase]) -> str:
    canonical = json.dumps([c.model_dump(mode='json') for c in cases], sort_keys=True, separators=(',', ':'))
    return hashlib.sha256(canonical.encode()).hexdigest()
