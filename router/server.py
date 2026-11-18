"""Loopback dashboard with session authentication and CSRF/origin checks."""
import difflib
import hmac
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import platform
import re
import secrets
import shutil
import socket
import time
import urllib.parse

from . import VERSION
from .checks import detect
from .engine import validate_project
from .providers import normalize_base, request, profile_request, validate_model, ProviderError
from .store import ident
from .workspace import private, safe, linked, Workspace

WEB = Path(__file__).resolve().parent.parent / 'web'


def folder_bytes(path):
    total=0
    if not path.is_dir() or path.is_symlink():return total
    for base,dirs,names in os.walk(path,followlinks=False):
        dirs[:]=[name for name in dirs if not (Path(base)/name).is_symlink()]
        for name in names:
            item=Path(base)/name
            try:
                if not item.is_symlink():total+=item.stat().st_size
            except OSError:pass
    return total


def storage_report(store):
    runs=[]
    for run in store.all('run'):
        run_id=run.get('id','')
        if not isinstance(run_id,str) or not re.fullmatch(r'[a-f0-9]{32}',run_id):continue
        runs.append({'id':run_id,'status':run.get('status'),'bytes':folder_bytes(store.folder/'runs'/run_id)})
    backups=folder_bytes(store.folder/'backups')
    worktrees=folder_bytes(store.folder/'git-worktrees')
    database=sum((store.folder/name).stat().st_size for name in ('router.sqlite3','router.sqlite3-wal','router.sqlite3-shm') if (store.folder/name).is_file())
    runs_bytes=sum(row['bytes'] for row in runs)
    return {'runs_bytes':runs_bytes,'worktrees_bytes':worktrees,'backups_bytes':backups,'database_bytes':database,
            'total_bytes':runs_bytes+worktrees+backups+database,'runs':runs}


def diagnostic_report(store):
    """Return aggregate troubleshooting data without user content, secrets, or paths."""
    runs=store.all('run')
    statuses={}
    totals={'runs':len(runs),'steps':0,'calls':0,'input_tokens':0,'output_tokens':0}
    for run in runs:
        status=run.get('status')
        if isinstance(status,str) and len(status)<=32:
            statuses[status]=statuses.get(status,0)+1
        for source,target in (('step','steps'),('calls','calls')):
            value=run.get(source)
            if type(value) is int and value>=0:totals[target]+=value
        usage=run.get('usage')
        if isinstance(usage,dict):
            for source,target in (('input_tokens','input_tokens'),('output_tokens','output_tokens')):
                value=usage.get(source)
                if type(value) is int and value>=0:totals[target]+=value
    return {'format_version':1,'lowforge_version':VERSION,
            'runtime':{'os':platform.system(),'os_release':platform.release(),
                       'python':platform.python_version(),'architecture':platform.machine()},
            'configuration_counts':{'models':len(store.all('model')),'projects':len(store.all('project'))},
            'runs':totals,'run_statuses':statuses,
            'privacy':'No prompts, logs, model/provider IDs, credentials, or filesystem paths included.'}


class Server(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = os.name != 'nt'

    def server_bind(self):
        if os.name == 'nt':
            self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_EXCLUSIVEADDRUSE, 1)
        super().server_bind()

    def __init__(self, address, engine):
        super().__init__(address, Handler)
        self.engine, self.store = engine, engine.store
        self.token = secrets.token_urlsafe(32)

    @property
    def url(self):
        return 'http://127.0.0.1:' + str(self.server_port)


class Handler(BaseHTTPRequestHandler):
    server_version = 'LowForge/1.0'

    def log_message(self, *args):
        pass  # Never log the initial URL fragment or credentials.

    def send(self, status, payload, mime='application/json; charset=utf-8'):
        body = json.dumps(payload, ensure_ascii=False).encode('utf-8') if isinstance(payload, (dict, list)) else payload
        self.send_response(status)
        self.send_header('Content-Type', mime)
        self.send_header('Content-Length', str(len(body)))
        self.send_header('Cache-Control', 'no-store')
        self.send_header('X-Content-Type-Options', 'nosniff')
        self.send_header('X-Frame-Options', 'DENY')
        self.send_header('Content-Security-Policy', "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'")
        self.end_headers()
        self.wfile.write(body)

    def valid_host(self):
        return self.headers.get('Host') in (f'127.0.0.1:{self.server.server_port}', f'localhost:{self.server.server_port}')

    def authorized(self):
        value = self.headers.get('Authorization', '')
        origin = self.headers.get('Origin')
        if origin and origin not in (self.server.url, f'http://localhost:{self.server.server_port}'):
            return False
        return self.valid_host() and hmac.compare_digest(value, 'Bearer ' + self.server.token)

    def do_GET(self):
        if not self.valid_host():
            return self.send(403, {'error': 'Недозволений Host'})
        parsed = urllib.parse.urlsplit(self.path)
        path = parsed.path
        if path in ('/', '/app.js', '/app.css'):
            name = 'index.html' if path == '/' else path[1:]
            mime = {'index.html': 'text/html; charset=utf-8', 'app.js': 'text/javascript; charset=utf-8', 'app.css': 'text/css; charset=utf-8'}[name]
            return self.send(200, (WEB / name).read_bytes(), mime)
        if not self.authorized():
            return self.send(401, {'error': 'Потрібен токен з термінала LowForge'})
        store = self.server.store
        try:
            if path == '/api/state':
                runs = store.all('run')[:50]
                # Reports and full goals are loaded on demand.
                runs = [{k: v for k, v in r.items() if k not in ('project_config', 'report','checks','verification','review')} for r in runs]
                return self.send(200, {'version': VERSION, 'models': store.all('model'), 'projects': store.all('project'),
                                       'runs': runs, 'active': self.server.engine.active, 'data_dir': str(store.folder)})
            if path == '/api/storage':
                return self.send(200,storage_report(store))
            if path == '/api/diagnostics':
                return self.send(200,diagnostic_report(store))
            query = urllib.parse.parse_qs(parsed.query)
            run = store.get('run', query.get('id', [''])[0])
            if path == '/api/run':
                folder=store.folder/'runs'/run['id']/'checkpoints'
                run['checkpoint_steps']=sorted(int(p.name[-4:]) for p in folder.glob('step-[0-9][0-9][0-9][0-9]') if p.is_dir()) if folder.exists() else []
                return self.send(200, {'run': run, 'events': store.events(run['id'])})
            if path == '/api/check':
                name=query.get('check',[''])[0]
                if name not in {c.get('report_file') for c in run.get('checks',[])}:
                    raise ValueError('Невідома перевірка')
                return self.send(200,json.loads(safe(store.folder/'runs'/run['id']/'checks',name).read_text(encoding='utf-8')))
            if path == '/api/diff':
                result = []
                folder = store.folder / 'runs' / run['id']
                for name in run.get('changed', []):
                    old = safe(folder / 'backup', name)
                    # For an unpublished candidate, the source snapshot is still in the project.
                    if run['status'] != 'done':
                        old = safe(run['project_config']['root'], name)
                    new = safe(folder / 'work', name)
                    def read(p):
                        return p.read_text(encoding='utf-8-sig', errors='replace').splitlines(keepends=True) if p.is_file() else []
                    result.extend(difflib.unified_diff(read(old), read(new), fromfile='a/' + name, tofile='b/' + name))
                    if sum(map(len, result)) > 500000:
                        result.append('\n[Diff обмежено 500000 символами]\n')
                        break
                return self.send(200, {'diff': ''.join(result)})
            return self.send(404, {'error': 'Не знайдено'})
        except (ValueError, OSError) as error:
            return self.send(400, {'error': str(error)})

    def do_POST(self):
        if not self.authorized():
            return self.send(401, {'error': 'Недозволений запит або токен'})
        if self.headers.get('Content-Type', '').split(';')[0] != 'application/json':
            return self.send(415, {'error': 'Потрібен application/json'})
        try:
            length = int(self.headers.get('Content-Length', '0'))
            if not 0 < length <= 1024 * 1024:
                return self.send(413, {'error': 'Некоректний розмір запиту'})
            data = json.loads(self.rfile.read(length))
            if not isinstance(data, dict):
                raise ValueError('Потрібен JSON-об’єкт')
            result = self.action(urllib.parse.urlsplit(self.path).path, data)
            self.send(200, result)
        except (ValueError, OSError, ProviderError, KeyError, TypeError) as error:
            self.send(400, {'error': str(error)[:6000]})

    def action(self, path, data):
        engine, store = self.server.engine, self.server.store
        if path == '/api/mcp/catalog':
            project=validate_project(data,store.folder)
            from .mcp import catalog
            return {'servers':catalog(project['mcp_servers'],project['root'])}
        if path == '/api/backup':
            return store.backup()
        if path == '/api/cleanup':
            days=data.get('older_than_days',30)
            if type(days) is not int or not 30<=days<=3650:
                raise ValueError('Очищення доступне для завершених запусків старше 30–3650 днів')
            cutoff=time.time()-days*86400
            removed=[];freed=0;skipped=0
            with engine.lock:
                if engine.active:
                    raise ValueError('Зачекайте завершення активної задачі')
                for run in store.all('run'):
                    run_id=run.get('id','')
                    stamp=run.get('finished',run.get('created',0))
                    if run.get('status')!='done' or type(stamp) not in (int,float) or stamp>=cutoff:
                        continue
                    if not isinstance(run_id,str) or not re.fullmatch(r'[a-f0-9]{32}',run_id):continue
                    target=store.folder/'runs'/run_id
                    if target.is_symlink() or target.resolve().parent!=(store.folder/'runs').resolve():
                        continue
                    if run.get('git_worktree'):
                        expected_path=store.folder/'git-worktrees'/run_id
                        try:
                            from .gitops import _contains_linked_path
                            worktree_path=Path(run['git_worktree'])
                            if _contains_linked_path(expected_path) or _contains_linked_path(worktree_path):
                                skipped+=1;continue
                            expected=expected_path.resolve()
                            worktree=worktree_path.resolve()
                            if worktree!=expected or run.get('git_branch')!='lowforge/'+run_id[:12]:
                                skipped+=1;continue
                            from .gitops import remove_task_worktree
                            project_config=run.get('project_config',{})
                            remove_task_worktree(project_config.get('source_root',''),worktree,run['git_branch'])
                        except (ValueError,OSError):
                            # Preserve both the run and its branch worktree if it has uncommitted data.
                            skipped+=1;continue
                    size=folder_bytes(target)
                    if target.exists():shutil.rmtree(target)
                    store.delete_run(run_id)
                    removed.append(run_id);freed+=size
            return {'removed':len(removed),'freed_bytes':freed,'skipped':skipped}
        if path == '/api/stop':
            return engine.stop()
        if path == '/api/start':
            return engine.start(data['id'], data.get('resume_id'))
        if path == '/api/publication':
            run_id=str(data.get('id',''))
            if not re.fullmatch(r'[a-f0-9]{32}',run_id):
                raise ValueError('Некоректний запуск')
            return engine.decide_publication(run_id,data.get('approve'))
        if path == '/api/rollback':
            with engine.lock:
                if engine.active:
                    raise ValueError('Зупиніть активну задачу перед відкатом')
                run=store.get('run',str(data.get('id','')))
                if run.get('status') not in ('interrupted','stopped','failed') or not run.get('rollback_available'):
                    raise ValueError('Для цього запуску немає доступного відкату')
                project=run.get('project_config',{})
                workspace=Workspace.resume(project['root'],store.folder/'runs'/run['id'])
                requested=data.get('step')
                if requested is None:
                    step=workspace.rollback_last()
                else:
                    workspace.rollback_to_step(requested)
                    step=requested
                checkpoints=store.folder/'runs'/run['id']/'checkpoints'
                message=(f'Крок {step} та наступні контрольні точки відкотили.' if requested is not None else f'Крок {step} відкотили.')
                run.update(status='failed',error=message+' Можна продовжити роботу з копії.',
                           step=max(0,step-1),next_step=step,changed=workspace.changes(),
                           rollback_available=any(checkpoints.glob('step-[0-9][0-9][0-9][0-9]')))
                run['feedback']=message+' Продовжуй з відновленого стану й повторно перевір вимоги.'
                store.put('run',run);store.log(run['id'],run['error'])
                return run
        if path == '/api/commit':
            with engine.lock:
                if engine.active:
                    raise ValueError('Зачекайте завершення активної задачі')
                run_id=str(data.get('id',''))
                if not re.fullmatch(r'[a-f0-9]{32}',run_id):
                    raise ValueError('Некоректний запуск')
                run=store.get('run',run_id)
                if run.get('status')!='done' or not run.get('changed'):
                    raise ValueError('Коміт доступний лише для завершеного запуску зі змінами')
                if run.get('git_commit'):
                    raise ValueError('Для цього запуску коміт уже створено')
                project=run.get('project_config',{})
                folder=store.folder/'runs'/run_id
                if folder.is_symlink() or folder.resolve().parent!=(store.folder/'runs').resolve():
                    raise ValueError('Папка запуску має некоректне посилання')
                if linked(folder/'work') or linked(folder/'backup'):
                    raise ValueError('Посилання у робочій або резервній копії заборонені')
                try:publication=json.loads((folder/'publication.json').read_text(encoding='utf-8'))
                except (OSError,ValueError) as error:raise ValueError('Немає підтвердженого журналу публікації') from error
                if publication.get('state')!='committed' or publication.get('changed')!=run['changed']:
                    raise ValueError('Журнал публікації не відповідає змінам запуску')
                from .gitops import create_user_commit
                result=create_user_commit(project['root'],folder/'work',folder/'backup',run['changed'],data.get('message',''))
                run['git_commit']=result['commit'];run['git_commit_paths']=result['paths'];store.put('run',run)
                store.log(run_id,'Користувач створив Git-коміт '+result['commit'][:12]+' для '+str(len(result['paths']))+' файлів.')
                return result
        if path == '/api/discover':
            allow_insecure_http=data.get('allow_insecure_http',False)
            if type(allow_insecure_http) is not bool:raise ValueError('allow_insecure_http має бути перемикачем')
            base = normalize_base(data['base'],allow_insecure_http)
            key = str(data.get('key', '')) or engine.keys.get(data.get('id'), '') or os.environ.get(str(data.get('key_env', '')), '')
            payload = request(base, '/models', key=key, timeout=8,allow_insecure_http=allow_insecure_http)
            if not isinstance(payload, dict) or not isinstance(payload.get('data'), list):
                raise ValueError('Сервер не повернув OpenAI-compatible список data')
            return {'models': [row['id'] for row in payload['data'] if isinstance(row, dict) and isinstance(row.get('id'), str)]}
        if path == '/api/probe':
            profile=validate_model(store.get('model',str(data.get('id',''))))
            key=engine.keys.get(profile['id']) or os.environ.get(profile['key_env'],'')
            started=time.monotonic()
            result=profile_request(profile,key,{
                'model':profile['model'],'messages':[{'role':'user','content':'Reply with the single word READY.'}],
                'max_tokens':64,'stream':False},timeout=min(profile['timeout'],90),
                )
            try:
                choice=result['choices'][0]
                content=choice['message']['content']
                if not isinstance(content,str) or not content.strip():raise ValueError('Модель повернула порожню відповідь')
            except (KeyError,TypeError,IndexError) as error:
                raise ValueError('Сервер доступний, але відповідь не відповідає формату chat/completions') from error
            usage=result.get('usage') or {}
            return {'ok':True,'profile':profile['name'],'model':profile['model'],'api_protocol':profile['api_protocol'],
                    'server_model':str(result.get('model',''))[:200],
                    'seconds':round(time.monotonic()-started,2),
                    'input_tokens':usage.get('prompt_tokens') if type(usage.get('prompt_tokens')) is int else None,
                    'output_tokens':usage.get('completion_tokens') if type(usage.get('completion_tokens')) is int else None}
        if path == '/api/detect':
            root = Path(str(data['root'])).resolve()
            if not root.is_dir():
                raise ValueError('Папку проєкту ще не створено. Для нового Python-проєкту вкажіть команду unittest вручну.')
            return {'commands': detect(root)}
        if path == '/api/model':
            model = validate_model(data)
            model.setdefault('id', ident())
            if 'key' in data:
                if data['key']:
                    engine.keys[model['id']] = str(data['key'])
                else:
                    engine.keys.pop(model['id'], None)
            store.put('model', model)
            return model
        if path == '/api/project':
            with engine.lock:
                project = validate_project(data, store.folder)
                project.setdefault('id', ident())
                if engine.active and store.get('run', engine.active)['project'] == project['id']:
                    raise ValueError('Зупиніть задачу перед редагуванням проєкту')
                store.put('project', project)
                return project
        if path == '/api/delete':
            kind = data.get('kind')
            if kind not in ('project', 'model'):
                raise ValueError('Недозволений тип запису')
            with engine.lock:
                if engine.active:
                    raise ValueError('Дочекайтеся завершення задачі')
                store.delete(kind, data['id'])
                engine.keys.pop(data['id'], None)
            return {'deleted': True}
        raise ValueError('Невідома дія')
