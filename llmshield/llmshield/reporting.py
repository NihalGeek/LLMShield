from pathlib import Path
from jinja2 import Environment, FileSystemLoader, select_autoescape
from .config import PACKAGE
from .audit import utcnow

ENV = Environment(loader=FileSystemLoader(PACKAGE/'templates'),autoescape=select_autoescape(['html']))
SCOPE = 'This project was tested exclusively against a locally controlled intentionally vulnerable LLM application using synthetic data.'


def render_report(runs: list[dict]) -> str:
    if not runs:
        raise ValueError('No runs to report')
    if any(r['status'] != 'completed' for r in runs):
        raise ValueError('Report requires completed runs')
    if len({(r['suite_hash'],r['provider'],r['group_id']) for r in runs}) != 1:
        raise ValueError('Comparison requires the same suite, provider and assessment group')
    return ENV.get_template('report.html').render(runs=runs,scope=SCOPE,generated=utcnow())


def export_report(runs, path: Path):
    path.parent.mkdir(parents=True,exist_ok=True)
    path.write_text(render_report(runs),encoding='utf-8')
    return path
