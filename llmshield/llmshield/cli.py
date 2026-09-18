import argparse
import json
from pathlib import Path
from .audit import AuditLog
from .cases import load_cases
from .config import Settings
from .database import Database
from .models import Mode, Category
from .providers import make_provider
from .reporting import export_report
from .runner import Runner
from .target import Target


def main():
    parser=argparse.ArgumentParser(description='LLMShield controlled local security lab')
    commands=parser.add_subparsers(dest='command',required=True)
    serve=commands.add_parser('serve',help='Start loopback dashboard and target API')
    serve.add_argument('--port',type=int,default=8765)
    assess=commands.add_parser('assess',help='Run the built-in local target assessment')
    assess.add_argument('--mode',choices=['both','vulnerable','guarded'],default='both')
    assess.add_argument('--provider',choices=['mock','ollama'],default=None)
    assess.add_argument('--model',default=None)
    assess.add_argument('--category',choices=[c.value for c in Category])
    assess.add_argument('--suite',type=Path,help='Path to a custom local JSON suite')
    assess.add_argument('--report',type=Path,default=Path('reports/assessment.html'))
    args=parser.parse_args()
    if args.command=='serve':
        import uvicorn
        uvicorn.run('llmshield.api:create_app',factory=True,host='127.0.0.1',port=args.port,access_log=False)
        return
    settings=Settings.from_env()
    provider=make_provider(args.provider or settings.provider,args.model if args.model is not None else settings.model)
    try:
        cases=load_cases(args.suite)
        if args.category:
            cases=[c for c in cases if c.category==args.category]
        if not cases:
            parser.error('No cases match the selected category')
        audit=AuditLog(settings.data_dir/'security.jsonl')
        runner=Runner(Target(provider,audit),Database(settings.data_dir/'llmshield.sqlite3'),audit)
        modes=[Mode.VULNERABLE,Mode.GUARDED] if args.mode=='both' else [Mode(args.mode)]
        runs=runner.assess(cases,modes)
        export_report(runs,args.report)
        args.report.with_suffix('.json').write_text(json.dumps(runs,indent=2),encoding='utf-8')
        for run in runs:
            print(json.dumps({k:run[k] for k in ['id','group_id','mode','provider','metrics']}),flush=True)
        print('Report: '+str(args.report.resolve()))
    finally:
        if hasattr(provider,'close'):
            provider.close()


if __name__=='__main__':
    main()
