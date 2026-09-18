"""Loopback operator interface. Do not expose this training service to a network."""
import threading
import uuid
from concurrent.futures import ThreadPoolExecutor
from contextlib import asynccontextmanager
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from starlette.middleware.trustedhost import TrustedHostMiddleware
from .audit import AuditLog
from .cases import load_cases
from .config import PACKAGE, Settings
from .database import Database
from .models import ChatRequest, AssessmentRequest
from .providers import make_provider
from .reporting import render_report
from .runner import Runner
from .target import Target


def create_app(settings: Settings | None = None, provider=None):
    settings=settings or Settings.from_env()
    @asynccontextmanager
    async def lifespan(app):
        app.state.db=Database(settings.data_dir/'llmshield.sqlite3')
        app.state.db.recover()
        app.state.audit=AuditLog(settings.data_dir/'security.jsonl')
        app.state.provider=provider or make_provider(settings.provider,settings.model)
        app.state.target=Target(app.state.provider,app.state.audit)
        app.state.runner=Runner(app.state.target,app.state.db,app.state.audit)
        app.state.cases=load_cases()
        app.state.lock=threading.Lock()
        app.state.jobs={}
        app.state.executor=ThreadPoolExecutor(max_workers=1,thread_name_prefix='assessment')
        yield
        app.state.executor.shutdown(wait=True)
        if hasattr(app.state.provider,'close'):
            app.state.provider.close()

    app=FastAPI(title='LLMShield local lab',version='1.0.0',lifespan=lifespan,
                docs_url=None,redoc_url=None,openapi_url='/api/openapi.json')
    app.add_middleware(TrustedHostMiddleware,allowed_hosts=['127.0.0.1','localhost'])

    @app.middleware('http')
    async def local_boundary(request: Request,call_next):
        if request.method not in {'GET','HEAD'}:
            origin=request.headers.get('origin')
            if origin and origin not in {'http://'+request.headers.get('host','')}:
                return JSONResponse({'detail':'Cross-origin requests are prohibited'},403)
            if request.headers.get('x-llmshield-lab')!='1':
                return JSONResponse({'detail':'X-LLMShield-Lab: 1 required'},403)
            if request.headers.get('sec-fetch-site')=='cross-site':
                return JSONResponse({'detail':'Cross-site requests are prohibited'},403)
            length=request.headers.get('content-length')
            if length is None or not length.isdigit() or int(length)>32768:
                return JSONResponse({'detail':'A valid Content-Length of at most 32768 is required'},413)
            # Consume the bounded body; reject a lying Content-Length as well.
            body=bytearray()
            async for chunk in request.stream():
                body.extend(chunk)
                if len(body)>32768:
                    return JSONResponse({'detail':'Request too large'},413)
            request._body=bytes(body)
        response=await call_next(request)
        response.headers['Content-Security-Policy']="default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; object-src 'none'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'"
        response.headers['X-Content-Type-Options']='nosniff'
        response.headers['Referrer-Policy']='no-referrer'
        response.headers['Cache-Control']='no-store'
        return response

    app.mount('/static',StaticFiles(directory=PACKAGE/'static'),name='static')

    @app.get('/',response_class=HTMLResponse)
    def dashboard():
        return (PACKAGE/'templates/dashboard.html').read_text(encoding='utf-8-sig')

    @app.get('/api/health')
    def health():
        return {'status':'ok','provider':app.state.provider.label,'scope':'synthetic-local-only'}

    @app.get('/api/cases')
    def cases():
        return [c.model_dump(mode='json') for c in app.state.cases]

    @app.post('/api/chat')
    def chat(body: ChatRequest):
        if not app.state.lock.acquire(blocking=False):
            raise HTTPException(409,'An assessment or chat request is already running')
        try:
            response=app.state.target.chat(body.prompt,body.mode,body.context)
            # Raw provider output and tool results are for the assessment audit, not chat consumers.
            return {'text':response.text,'decisions':[d.model_dump() for d in response.decisions],
                    'tools':[{'name':a.name,'authorized':a.authorized,'executed':a.executed} for a in response.attempts]}
        except Exception as exc:
            app.state.audit.emit('chat_error',error=type(exc).__name__)
            raise HTTPException(502,'Local provider failed; inspect provider availability') from exc
        finally:
            app.state.lock.release()

    @app.post('/api/assessments',status_code=202)
    def assess(body: AssessmentRequest):
        if not app.state.lock.acquire(blocking=False):
            raise HTTPException(409,'An assessment or chat request is already running')
        group_id=uuid.uuid4().hex
        selected=[c for c in app.state.cases if body.category is None or c.category==body.category]
        app.state.jobs[group_id]={'group_id':group_id,'status':'running'}
        def work():
            try:
                app.state.runner.assess(selected,body.modes,group_id)
                app.state.jobs[group_id]['status']='completed'
            except Exception as exc:
                app.state.jobs[group_id].update(status='error',error=type(exc).__name__)
                app.state.audit.emit('assessment_error',group_id=group_id,error=type(exc).__name__)
            finally:
                app.state.lock.release()
        app.state.executor.submit(work)
        return app.state.jobs[group_id]

    @app.get('/api/assessments/{group_id}')
    def assessment(group_id: str):
        runs=app.state.db.group(group_id)
        if group_id not in app.state.jobs and not runs:
            raise HTTPException(404,'Assessment not found')
        job=app.state.jobs.get(group_id,{'group_id':group_id,'status':'completed' if all(r['status']=='completed' for r in runs) else 'interrupted'})
        return {**job,'runs':runs}

    @app.get('/api/runs')
    def runs():
        return app.state.db.list_runs()

    @app.get('/api/runs/{run_id}')
    def run(run_id: str):
        result=app.state.db.get_run(run_id)
        if result is None:
            raise HTTPException(404,'Run not found')
        return result

    @app.get('/api/reports/{group_id}',response_class=HTMLResponse)
    def report(group_id: str):
        runs=app.state.db.group(group_id)
        if not runs:
            raise HTTPException(404,'Assessment not found')
        if any(r['status']!='completed' for r in runs) or app.state.jobs.get(group_id,{}).get('status')=='running':
            raise HTTPException(409,'Assessment is not complete')
        return render_report(runs)

    return app
