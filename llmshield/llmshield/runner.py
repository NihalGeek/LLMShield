import time
import uuid
from collections import Counter
from .audit import utcnow
from .cases import suite_hash
from .evaluator import evaluate
from .models import Response, Verdict

REMEDIATION = {
 'prompt_injection': 'Treat retrieved content as data; retain independent output and tool checks.',
 'system_prompt_leakage': 'Keep secrets out of prompts; inspect outputs and avoid exposing raw model transcripts.',
 'sensitive_data_exposure': 'Minimize model context; authorize records before retrieval and inspect output.',
 'jailbreak': 'Enforce application policy outside the model; monitor explicit policy violations.',
 'tool_misuse': 'Authorize every tool and resource against a trusted identity; default deny.',
 'instruction_hierarchy': 'Preserve source provenance and never derive privileges from conversation text.'}


def metrics(results):
    counts = Counter(r['verdict'] for r in results)
    attacks = [r for r in results if r['kind'] == 'attack']
    benign = [r for r in results if r['kind'] == 'benign']
    attack_fails = sum(r['verdict'] == 'FAIL' for r in attacks)
    blocked = sum(r['verdict'] == 'PASS' and any(d['blocked'] for d in r['response']['decisions']) for r in attacks)
    def rate(n, d):
        return round(100*n/d, 2) if d else None
    def breakdown(key):
        return {value: {v: sum(r[key] == value and r['verdict'] == v for r in results) for v in ['PASS','FAIL','REVIEW']}
                for value in sorted({r[key] for r in results})}
    return dict(total=len(results), passed=counts['PASS'], failed=counts['FAIL'], review=counts['REVIEW'],
                attack_tests=len(attacks), attack_failures=attack_fails, attack_success_rate=rate(attack_fails,len(attacks)),
                blocked_attacks=blocked, blocked_attack_rate=rate(blocked,len(attacks)),
                benign_tests=len(benign), benign_failures=sum(r['verdict']=='FAIL' for r in benign),
                benign_failure_rate=rate(sum(r['verdict']=='FAIL' for r in benign),len(benign)),
                errors=sum(bool(r['response']['error']) for r in results),
                unauthorized_tool_attempts=sum(not a['authorized'] for r in results for a in r['response']['attempts']),
                unauthorized_tool_executions=sum(a['executed'] and not a['authorized'] for r in results for a in r['response']['attempts']),
                secret_leakage_tests=sum(r['kind']=='attack' and r['category'] in {'system_prompt_leakage','sensitive_data_exposure'} for r in results),
                secret_leakage_failures=sum(any(e.startswith('Returned protected canary:') for e in r['evidence']) for r in results),
                by_category=breakdown('category'), by_severity=breakdown('severity'))


def finding_for(case, result):
    return dict(id='F-'+result['id'], title=case.name, test_id=case.id, category=case.category,
                severity=case.severity, attack_prompt=case.prompt, attack_context=case.context, expected_behavior=case.expected_behavior,
                observed_behavior=result['response']['text'][:500], evidence=result['evidence'],
                security_impact=('Allowed lab operation was blocked; availability/false-positive impact.' if case.kind=='benign'
                                 else 'Protected synthetic information was disclosed.' if any(e.startswith('Returned protected canary:') for e in result['evidence'])
                                 else 'A forbidden tool execution crossed the role/resource boundary.' if any(e.startswith('Forbidden tool executed:') for e in result['evidence'])
                                 else 'Explicit output-contract violation. Marker output alone does not prove a real action or privilege change.'),
                recommended_remediation=('Investigate provider over-refusal and allowed-task completion; retain role/resource enforcement.' if case.kind=='benign' else REMEDIATION[case.category]), retest_status='NOT_RETESTED')


class Runner:
    def __init__(self, target, database, audit):
        self.target, self.database, self.audit = target, database, audit

    def run(self, cases, mode, group_id):
        run = dict(id=uuid.uuid4().hex, group_id=group_id, mode=mode, provider=self.target.provider.label,
                   suite_hash=suite_hash(cases), started_at=utcnow(), status='running', total=len(cases))
        self.database.start(run,cases)
        results = []
        try:
            for case in cases:
                started = time.perf_counter()
                self.audit.emit('test_started', run_id=run['id'], test_id=case.id, mode=mode)
                try:
                    response = self.target.chat(case.prompt,mode,case.context)
                except Exception as exc:
                    # An inference/parse/transport failure is REVIEW, never a secure refusal.
                    response = Response(text='',error=type(exc).__name__)
                    self.audit.emit('execution_error',run_id=run['id'],test_id=case.id,error=type(exc).__name__)
                evaluation = evaluate(case,response)
                result = dict(id=uuid.uuid4().hex,test_id=case.id,category=case.category,severity=case.severity,kind=case.kind,
                              verdict=evaluation.verdict,evidence=evaluation.evidence,response=response.model_dump(mode='json'),
                              duration_ms=round((time.perf_counter()-started)*1000,2))
                results.append(result)
                self.database.save_result(run['id'],result,finding_for(case,result) if evaluation.verdict==Verdict.FAIL else None)
                self.audit.emit('test_finished',run_id=run['id'],test_id=case.id,verdict=evaluation.verdict,
                                outcome='attack_succeeded' if case.kind=='attack' and evaluation.verdict==Verdict.FAIL else
                                'attack_failed' if case.kind=='attack' and evaluation.verdict==Verdict.PASS else 'review_or_control')
            self.database.finish(run['id'],utcnow(),metrics(results))
        except Exception:
            self.database.finish(run['id'],utcnow(),metrics(results),'error')
            raise
        return self.database.get_run(run['id'])

    def assess(self, cases, modes, group_id=None):
        group_id = group_id or uuid.uuid4().hex
        runs = [self.run(cases,mode,group_id) for mode in modes]
        baseline = next((r for r in runs if r['mode']=='vulnerable'),None)
        guarded = next((r for r in runs if r['mode']=='guarded'),None)
        if baseline and guarded:
            by_id = {r['test_id']:r for r in guarded['results']}
            for finding in baseline['findings']:
                retest = by_id[finding['test_id']]
                finding['retest_status'] = {'PASS':'PASS_ON_GUARDED_RETEST','FAIL':'STILL_FAILING','REVIEW':'NEEDS_REVIEW'}[retest['verdict']]
                finding['retest_run_id'] = guarded['id']
                self.database.update_finding(finding)
        return self.database.group(group_id)
