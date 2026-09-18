'use strict';
const $ = id => document.getElementById(id);
const names = {
  prompt_injection: 'Prompt injection', system_prompt_leakage: 'System prompt leakage',
  sensitive_data_exposure: 'Sensitive data exposure', jailbreak: 'Jailbreak / policy bypass',
  tool_misuse: 'Tool misuse', instruction_hierarchy: 'Instruction hierarchy'
};
function el(tag, text, className) {
  const node = document.createElement(tag);
  if (text !== undefined) node.textContent = String(text);
  if (className) node.className = className;
  return node;
}
const percent = value => value == null ? 'N/A' : value.toFixed(2) + '%';
async function api(path, body) {
  const response = await fetch(path, body ? {
    method: 'POST', headers: {'Content-Type': 'application/json', 'X-LLMShield-Lab': '1'},
    body: JSON.stringify(body)
  } : {});
  const data = await response.json();
  if (!response.ok) throw new Error(typeof data.detail === 'string' ? data.detail : JSON.stringify(data.detail));
  return data;
}
function setRunning(running) {
  document.body.dataset.running = String(running);
  $('run').disabled = running;
  $('run-label').textContent = running ? 'Assessment running…' : 'Run security assessment';
  $('mode').disabled = running;
  $('category').disabled = running;
}
function metric(label, value, note, cls) {
  const card = el('div', undefined, 'metric');
  card.append(el('span', label), el('strong', value, cls), el('small', note));
  return card;
}
function findingDetail(finding) {
  const box = $('detail-content');
  const heading = el('h2', finding.title);
  heading.id = 'finding-title';
  box.replaceChildren(el('span', finding.severity + ' / ' + finding.category, 'eyebrow'), heading);
  const details = [
    ['Finding ID', finding.id], ['Test / prompt', finding.test_id + '\n' + finding.attack_prompt],
    ['Untrusted context', finding.attack_context || '(none)'], ['Expected behavior', finding.expected_behavior],
    ['Observed behavior', finding.observed_behavior], ['Evidence', finding.evidence.join('\n')],
    ['Security impact', finding.security_impact], ['Recommended remediation', finding.recommended_remediation],
    ['Retest status', finding.retest_status]
  ];
  for (const [label, value] of details) box.append(el('h3', label), el('pre', value));
  $('detail').showModal();
}
function showAssessment(data, selectedId) {
  const runs = data.runs.filter(run => run.status === 'completed');
  if (!runs.length) {
    $('status').textContent = 'No completed runs in this assessment yet.';
    return;
  }
  const selected = runs.find(run => run.id === selectedId) || runs.find(run => run.mode === 'guarded') || runs[0];
  const metrics = selected.metrics;
  $('selected-mode').textContent = selected.mode + ' · ' + selected.provider;
  $('metrics').replaceChildren(
    metric('Total tests', metrics.total, metrics.attack_tests + ' attacks + ' + metrics.benign_tests + ' controls'),
    metric('Passed', metrics.passed, 'Observed safe behavior', 'pass'),
    metric('Failed', metrics.failed, 'Policy or control failure', 'fail'),
    metric('Needs review', metrics.review, 'Unresolved evidence', 'review'),
    metric('Attack success', percent(metrics.attack_success_rate), selected.mode + ' mode')
  );
  $('comparison').replaceChildren();
  for (const run of runs) {
    const label = el('div', undefined, 'bar-label');
    label.append(el('span', run.mode), el('strong', percent(run.metrics.attack_success_rate)));
    const bar = el('div', undefined, 'bar');
    const fill = el('i', undefined, 'fail');
    fill.style.width = (run.metrics.attack_success_rate || 0) + '%';
    bar.append(fill);
    $('comparison').append(label, bar, el('div', run.metrics.attack_failures + '/' + run.metrics.attack_tests +
      ' attacks succeeded · ' + run.metrics.review + ' total reviews', 'small'));
  }
  $('severity').replaceChildren();
  for (const [name, counts] of Object.entries(metrics.by_severity)) {
    const label = el('div', undefined, 'bar-label');
    label.append(el('span', name), el('span', counts.PASS + ' pass / ' + counts.FAIL + ' fail / ' + counts.REVIEW + ' review'));
    const bar = el('div', undefined, 'bar');
    const total = counts.PASS + counts.FAIL + counts.REVIEW;
    for (const verdict of ['PASS', 'FAIL', 'REVIEW']) {
      const fill = el('i', undefined, verdict.toLowerCase());
      fill.style.width = (total ? 100 * counts[verdict] / total : 0) + '%';
      bar.append(fill);
    }
    $('severity').append(label, bar);
  }
  $('categories').replaceChildren();
  for (const [name, counts] of Object.entries(metrics.by_category)) {
    const row = el('tr');
    row.append(el('td', names[name] || name));
    for (const verdict of ['PASS', 'FAIL', 'REVIEW']) row.append(el('td', counts[verdict], verdict));
    $('categories').append(row);
  }
  $('finding-rows').replaceChildren();
  let count = 0;
  for (const run of runs) {
    for (const finding of run.findings) {
      count++;
      const row = el('tr');
      const title = el('td');
      const button = el('button', finding.title, 'link-button');
      button.addEventListener('click', () => findingDetail(finding));
      title.append(button);
      const severity = el('td');
      severity.append(el('span', finding.severity, 'badge ' + finding.severity));
      row.append(el('td', finding.test_id), title, el('td', run.mode), severity,
        el('td', finding.retest_status.replaceAll('_', ' ')));
      $('finding-rows').append(row);
    }
  }
  $('finding-count').textContent = count + ' FINDINGS';
  if (!count) {
    const row = el('tr');
    const cell = el('td', 'No deterministic failures in this assessment. Check REVIEW results in the report.');
    cell.colSpan = 5;
    row.append(cell);
    $('finding-rows').append(row);
  }
  $('report').href = '/api/reports/' + data.group_id;
  $('report').classList.toggle('hidden', data.status !== 'completed');
  $('scope').textContent = selected.provider.startsWith('mock:')
    ? 'DETERMINISTIC SIMULATOR — These are pipeline demonstrations, not evidence of actual LLM robustness.'
    : 'LOCAL MODEL — Observations apply only to ' + selected.provider + ' and this test suite. REVIEW means unresolved.';
  $('status').textContent = 'Assessment ' + data.group_id.slice(0, 8) + ' · ' + data.status + ' · Suite ' + selected.suite_hash.slice(0, 12);
}
async function history() {
  const runs = await api('/api/runs');
  $('history-rows').replaceChildren();
  for (const run of runs) {
    const row = el('tr');
    const metrics = run.metrics;
    row.append(el('td', new Date(run.started_at).toLocaleString()), el('td', run.provider), el('td', run.mode),
      el('td', run.status), el('td', run.status === 'completed' ? metrics.passed + ' / ' + metrics.failed + ' / ' + metrics.review : '—'));
    const cell = el('td');
    const button = el('button', 'Inspect ↗', 'link-button');
    button.addEventListener('click', async () => {
      try {
        showAssessment(await api('/api/assessments/' + run.group_id), run.id);
        $('metrics').scrollIntoView({behavior: window.matchMedia('(prefers-reduced-motion: reduce)').matches ? 'instant' : 'smooth', block: 'start'});
      } catch (error) { $('status').textContent = error.message; }
    });
    cell.append(button);
    row.append(cell);
    $('history-rows').append(row);
  }
  return runs;
}
async function poll(id) {
  const data = await api('/api/assessments/' + id);
  const progress = data.runs.reduce((count, run) => count + run.results.length, 0);
  $('status').textContent = 'Assessment running · ' + progress + ' case executions recorded. Local model inference may take a few minutes.';
  if (data.status === 'running') {
    setTimeout(() => poll(id).catch(failed), 1000);
    return;
  }
  setRunning(false);
  await history();
  if (data.status === 'completed') showAssessment(data);
  else $('status').textContent = 'Assessment ' + data.status + '. Inspect run history and the security log.';
}
function failed(error) {
  setRunning(false);
  $('status').textContent = 'Error: ' + error.message;
}
$('run').addEventListener('click', async () => {
  try {
    setRunning(true);
    $('status').textContent = 'Starting local assessment…';
    const mode = $('mode').value;
    const result = await api('/api/assessments', {
      modes: mode === 'both' ? ['vulnerable', 'guarded'] : [mode], category: $('category').value || null
    });
    await poll(result.group_id);
  } catch (error) { failed(error); }
});
$('close-detail').addEventListener('click', () => $('detail').close());
document.querySelectorAll('.nav').forEach(link => link.addEventListener('click', () => {
  document.querySelectorAll('.nav').forEach(item => {
    item.classList.remove('active');
    item.removeAttribute('aria-current');
  });
  link.classList.add('active');
  link.setAttribute('aria-current', 'location');
}));
(async () => {
  try {
    const health = await api('/api/health');
    $('provider').textContent = health.provider;
    document.body.classList.add('connected');
    $('connection').textContent = 'Connected';
    for (const [value, name] of Object.entries(names)) {
      const option = el('option', name);
      option.value = value;
      $('category').append(option);
    }
    const runs = await history();
    const latest = runs.find(run => run.status === 'completed');
    if (latest) showAssessment(await api('/api/assessments/' + latest.group_id));
    else {
      $('status').textContent = 'No assessments yet. Run your first local security assessment.';
      $('metrics').replaceChildren(el('p', 'Your measured results will appear here.', 'small'));
    }
    const active = runs.find(run => run.status === 'running');
    if (active) {
      setRunning(true);
      poll(active.group_id).catch(failed);
    }
  } catch (error) { failed(error); }
})();
