from __future__ import annotations

from enum import StrEnum
from typing import Literal
from pydantic import BaseModel, ConfigDict, Field, model_validator


class Mode(StrEnum):
    VULNERABLE = 'vulnerable'
    GUARDED = 'guarded'


class Verdict(StrEnum):
    PASS = 'PASS'
    FAIL = 'FAIL'
    REVIEW = 'REVIEW'


class Category(StrEnum):
    INJECTION = 'prompt_injection'
    LEAKAGE = 'system_prompt_leakage'
    EXPOSURE = 'sensitive_data_exposure'
    JAILBREAK = 'jailbreak'
    TOOL = 'tool_misuse'
    HIERARCHY = 'instruction_hierarchy'


class StrictModel(BaseModel):
    model_config = ConfigDict(extra='forbid')


class ToolCall(StrictModel):
    name: str = Field(min_length=1, max_length=64)
    resource: str = Field(default='', max_length=80)
    value: str = Field(default='', max_length=200)


class Proposal(StrictModel):
    text: str = Field(max_length=8000)
    tool_calls: list[ToolCall] = Field(default_factory=list, max_length=4)


class Criteria(StrictModel):
    forbidden_text: list[str] = Field(default_factory=list)
    required_text: list[str] = Field(default_factory=list)
    required_tools: list[str] = Field(default_factory=list)
    accept_refusal: bool = True


class TestCase(StrictModel):
    id: str = Field(pattern=r'^[A-Z]+-[0-9]{3}$')
    name: str = Field(min_length=1, max_length=150)
    category: Category
    description: str
    prompt: str = Field(min_length=1, max_length=6000)
    context: str = Field(default='', max_length=6000)
    expected_behavior: str
    severity: Literal['critical', 'high', 'medium', 'low']
    kind: Literal['attack', 'benign'] = 'attack'
    canary_values: list[str] = Field(default_factory=list)
    allowed_tools: list[str] = Field(default_factory=list)
    forbidden_tools: list[str] = Field(default_factory=list)
    success_criteria: Criteria

    @model_validator(mode='after')
    def unambiguous(self):
        if set(self.allowed_tools) & set(self.forbidden_tools):
            raise ValueError('A tool cannot be both allowed and forbidden')
        if any(not x for x in self.canary_values + self.success_criteria.forbidden_text + self.success_criteria.required_text):
            raise ValueError('Empty evidence markers are not allowed')
        return self


class Decision(StrictModel):
    stage: Literal['input', 'output', 'tool']
    blocked: bool
    reason: str


class ToolAttempt(StrictModel):
    name: str
    resource: str
    role: str
    authorized: bool
    executed: bool
    reason: str
    result: str = ''


class Response(StrictModel):
    text: str
    raw_text: str = ''
    attempts: list[ToolAttempt] = Field(default_factory=list)
    decisions: list[Decision] = Field(default_factory=list)
    error: str | None = None


class Evaluation(StrictModel):
    verdict: Verdict
    evidence: list[str]


class ChatRequest(StrictModel):
    prompt: str = Field(min_length=1, max_length=6000)
    context: str = Field(default='', max_length=6000)
    mode: Mode = Mode.GUARDED


class AssessmentRequest(StrictModel):
    modes: list[Mode] = Field(default_factory=lambda: [Mode.VULNERABLE, Mode.GUARDED], min_length=1, max_length=2)
    category: Category | None = None

    @model_validator(mode='after')
    def unique(self):
        if len(set(self.modes)) != len(self.modes):
            raise ValueError('Modes must be unique')
        return self
