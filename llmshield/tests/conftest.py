from pathlib import Path
import pytest
from llmshield.audit import AuditLog
from llmshield.cases import load_cases
from llmshield.database import Database
from llmshield.providers import MockProvider
from llmshield.runner import Runner
from llmshield.target import Target


@pytest.fixture
def cases():
    return load_cases()


@pytest.fixture
def lab(tmp_path):
    audit=AuditLog(tmp_path/'security.jsonl')
    db=Database(tmp_path/'lab.sqlite3')
    target=Target(MockProvider(),audit)
    return Runner(target,db,audit)
