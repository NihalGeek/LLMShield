import json
import pytest
from llmshield.database import Database
from llmshield.models import Mode, Response, Verdict
from llmshield.reporting import render_report, SCOPE
from llmshield.runner import metrics


def test_paired_assessment_persistence_and_retest(lab,cases):
    runs=lab.assess(cases,[Mode.VULNERABLE,Mode.GUARDED])
    baseline,guarded=runs
    assert baseline['suite_hash']==guarded['suite_hash']
    assert baseline['metrics']['failed']>0
    assert guarded['metrics']['failed']==0
    assert guarded['metrics']['review']==1
    assert baseline['metrics']['unauthorized_tool_executions']==4
    assert guarded['metrics']['unauthorized_tool_executions']==0
    assert guarded['metrics']['benign_failures']==0
    assert len(baseline['findings'])==baseline['metrics']['failed']
    assert all('attack_context' in f for f in baseline['findings'])
    assert all(f['retest_status']=='PASS_ON_GUARDED_RETEST' for f in baseline['findings'])
    reopened=Database(lab.database.path)
    assert len(reopened.get_run(baseline['id'])['results'])==24
    with reopened.connect() as db:
        assert db.execute('SELECT count(*) FROM tool_attempts').fetchone()[0]>0
        assert db.execute('SELECT count(*) FROM guardrail_decisions').fetchone()[0]>0
        assert db.execute('SELECT count(*) FROM test_cases').fetchone()[0]==24
    events=[json.loads(line)['event'] for line in (lab.database.path.parent/'security.jsonl').read_text().splitlines()]
    assert 'tool_authorization' in events and 'guardrail_decision' in events and 'test_finished' in events


def test_provider_errors_are_persisted_as_review(lab,cases):
    def unavailable(*args): raise TimeoutError('provider offline')
    lab.target.provider.generate=unavailable
    run=lab.assess([cases[0]],[Mode.VULNERABLE])[0]
    assert run['metrics']['errors']==1
    assert run['metrics']['review']==1
    assert run['metrics']['passed']==0
    assert not run['findings']


def test_metrics_denominators():
    def row(kind,verdict,blocked=False):
        return dict(kind=kind,verdict=verdict,category='prompt_injection',severity='medium',evidence=[],
                    response=Response(text='x',decisions=[{'stage':'input','blocked':blocked,'reason':'test'}]).model_dump())
    m=metrics([row('attack','FAIL'),row('attack','PASS',True),row('attack','REVIEW'),row('benign','FAIL')])
    assert m['attack_success_rate']==33.33
    assert m['blocked_attack_rate']==33.33
    assert m['benign_failure_rate']==100
    assert metrics([])['attack_success_rate'] is None


def test_report_escape_scope_and_pair_integrity(lab,cases):
    case=cases[0].model_copy(update={'name':'<script>alert(1)</script>'})
    runs=lab.assess([case],[Mode.VULNERABLE,Mode.GUARDED])
    html=render_report(runs)
    assert SCOPE in html
    assert '<script>alert(1)</script>' not in html
    assert '&lt;script&gt;' in html
    assert 'Deterministic simulator' in html
    assert '94.44' not in html  # no hard-coded whole-suite metrics
    assert runs[0]['suite_hash'] in html
    runs[1]['provider']='another-provider'
    with pytest.raises(ValueError): render_report(runs)


def test_recover_interrupted_run(lab,cases):
    from llmshield.cases import suite_hash
    lab.database.start(dict(id='interrupted',group_id='group',mode='vulnerable',provider='mock',suite_hash=suite_hash(cases),started_at='now',status='running',total=24),cases)
    lab.database.recover()
    run=lab.database.get_run('interrupted')
    assert run['status']=='interrupted'
    with pytest.raises(ValueError): render_report([run])
