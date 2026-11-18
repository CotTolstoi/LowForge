"""Host-owned staged checks and evidence tied to the exact source snapshot."""
import ast
import fnmatch
import hashlib
from html.parser import HTMLParser
import json
from pathlib import Path
import posixpath
import re
import tempfile
import time
from urllib.parse import urlsplit, unquote

from .checks import detect, parse_commands, run_checks, excerpt, failure_feedback
from .redaction import redact
from .providers import Cancelled
from .workspace import atomic, files, safe

TEXT_FIELDS=('fast_commands','integration_commands','e2e_commands','acceptance_commands','required_files','criteria')
STAGE_LABELS={'fast':'Основні','integration':'Інтеграція','e2e':'Наскрізні / UI','acceptance':'Незалежні критерії'}


def settings(data):
    result={}
    editable=data.get('editable_test_files',[])
    if not isinstance(editable,list) or len(editable)>100:
        raise ValueError('editable_test_files must be a list of at most 100 exact relative paths')
    for path in editable:
        if (not isinstance(path,str) or not path or path.startswith(('/', '\\')) or ':' in path
                or '..' in path.replace('\\','/').split('/') or any(c in path for c in '*?[')):
            raise ValueError('editable_test_files requires exact project-relative paths, no traversal or globs')
    result['editable_test_files']=[p.replace('\\','/') for p in editable]
    authored=data.get('authored_test_files',[])
    if not isinstance(authored,list) or len(authored)>100:
        raise ValueError('authored_test_files must be a list of at most 100 exact relative paths')
    for path in authored:
        if (not isinstance(path,str) or not path or path.startswith(('/', '\\')) or ':' in path
                or '..' in path.replace('\\','/').split('/') or any(c in path for c in '*?[')
                or not is_test(path)):
            raise ValueError('authored_test_files requires exact test-file paths')
    result['authored_test_files']=[p.replace('\\','/') for p in authored]
    require_authored=data.get('require_authored_tests',False)
    if type(require_authored) is not bool:raise ValueError('require_authored_tests must be boolean')
    if require_authored and (not authored or not set(result['authored_test_files']).issubset(result['editable_test_files'])):
        raise ValueError('require_authored_tests needs authored_test_files explicitly included in editable_test_files')
    result['require_authored_tests']=require_authored
    identifiers=data.get('required_identifiers',[])
    if not isinstance(identifiers,list) or len(identifiers)>200:
        raise ValueError('required_identifiers must be a list of at most 200 exact identifiers')
    normalized=[]
    for item in identifiers:
        if not isinstance(item,dict) or set(item)-{'kind','name','path'} or item.get('kind') not in ('file','function','class','parameter','identifier'):
            raise ValueError('required_identifiers entries need kind=file/function/class/parameter/identifier')
        kind=item['kind'];path=item.get('path');name=item.get('name')
        if kind=='file':
            if not isinstance(path,str) or not path or path.startswith(('/', '\\')) or ':' in path or '..' in path.replace('\\','/').split('/') or any(c in path for c in '*?['):
                raise ValueError('required file paths must be exact project-relative paths')
            if name is not None:raise ValueError('file identifiers use path only')
            normalized.append({'kind':kind,'path':path.replace('\\','/')})
        else:
            if not isinstance(name,str) or not name.isidentifier():raise ValueError(f'{kind} identifiers need an exact language identifier')
            if path is not None and (not isinstance(path,str) or not path or path.startswith(('/', '\\')) or ':' in path or '..' in path.replace('\\','/').split('/') or any(c in path for c in '*?[')):
                raise ValueError('required identifier paths must be exact project-relative paths')
            normalized.append({'kind':kind,**({'path':path.replace('\\','/')} if path else {}),'name':name})
    result['required_identifiers']=normalized
    for key in TEXT_FIELDS:
        value=data.get(key,'')
        if not isinstance(value,str) or len(value)>30000:
            raise ValueError('Некоректне поле перевірок: '+key)
        result[key]=value
        if key.endswith('_commands'):parse_commands(value)
    for key in ('auto_verify','protect_tests'):
        value=data.get(key,True)
        if type(value) is not bool:raise ValueError(key+' має бути перемикачем')
        result[key]=value
    profile=data.get('verification_profile','standard')
    if profile not in ('standard','client'):raise ValueError('Невідомий профіль перевірок')
    result['verification_profile']=profile
    for pattern in lines(result['required_files']):
        if pattern.startswith(('/', '\\')) or ':' in pattern or '..' in pattern.replace('\\','/').split('/'):
            raise ValueError('Потрібен відносний шаблон required_files: '+pattern)
    if len(lines(result['required_files']))>100 or len(lines(result['criteria']))>30:
        raise ValueError('Не більше 100 шаблонів файлів і 30 критеріїв')
    criterion_ids={f'R{i}' for i,_ in enumerate(lines(result['criteria']),1)}
    specs=data.get('behavioral_test_specs',[])
    if not isinstance(specs,list) or len(specs)>30:
        raise ValueError('behavioral_test_specs must be a list of at most 30 declarative test specs')
    normalized_specs=[];spec_ids=set()
    for spec in specs:
        if not isinstance(spec,dict) or set(spec)!={'id','requirement_ids','module','symbol','cases'}:
            raise ValueError('behavioral test spec needs exactly id, requirement_ids, module, symbol and cases')
        ident=spec['id'];module=spec['module'];symbol=spec['symbol'];reqs=spec['requirement_ids'];cases=spec['cases']
        if not isinstance(ident,str) or not re.fullmatch(r'[A-Za-z][A-Za-z0-9_-]{0,63}',ident) or ident in spec_ids:
            raise ValueError('behavioral test ids must be unique simple identifiers')
        if (not isinstance(module,str) or not re.fullmatch(r'[A-Za-z_]\w*(?:\.[A-Za-z_]\w*)*',module)
                or not isinstance(symbol,str) or not symbol.isidentifier()):
            raise ValueError('behavioral tests require an exact Python module and symbol')
        if (not isinstance(reqs,list) or not reqs or any(not isinstance(r,str) or r not in criterion_ids for r in reqs)):
            raise ValueError('behavioral test requirement_ids must reference declared criteria R1..Rn')
        if not isinstance(cases,list) or not 1<=len(cases)<=50:
            raise ValueError('behavioral test cases must contain 1 to 50 cases')
        normalized_cases=[]
        for case in cases:
            if not isinstance(case,dict) or not set(case).issubset({'args','kwargs','expected','raises'}):
                raise ValueError('behavioral test cases accept only args, kwargs, expected or raises')
            if ('expected' in case)==('raises' in case):
                raise ValueError('each behavioral case needs exactly one of expected or raises')
            args=case.get('args',[]);kwargs=case.get('kwargs',{})
            if not isinstance(args,list) or not isinstance(kwargs,dict) or any(not isinstance(k,str) for k in kwargs):
                raise ValueError('behavioral test args must be a list and kwargs a string-keyed object')
            if 'raises' in case and case['raises'] not in ('ValueError','TypeError','KeyError','IndexError','OSError','RuntimeError'):
                raise ValueError('behavioral test raises must name an allowed built-in exception')
            try:json.dumps({'args':args,'kwargs':kwargs,'expected':case.get('expected')},ensure_ascii=False,allow_nan=False)
            except (TypeError,ValueError) as error:raise ValueError('behavioral test cases must contain finite JSON values') from error
            normalized_cases.append({'args':args,'kwargs':kwargs,**({'raises':case['raises']} if 'raises' in case else {'expected':case['expected']})})
        spec_ids.add(ident)
        normalized_specs.append({'id':ident,'requirement_ids':list(dict.fromkeys(reqs)),
                                 'module':module,'symbol':symbol,'cases':normalized_cases})
    result['behavioral_test_specs']=normalized_specs
    return result


def lines(text):
    return [line.strip() for line in text.splitlines() if line.strip()]


def criteria(project):
    return {f'R{i}':text for i,text in enumerate(lines(project.get('criteria','')),1)}


def identifiers_from_goal(goal, project_files=()):
    """Extract identifiers only from explicit inline-code tokens in the task text."""
    result=[];seen=set()
    def add(item):
        key=(item['kind'],item.get('path'),item.get('name'))
        if key not in seen:seen.add(key);result.append(item)
    # Fenced examples are contextual code, not declared API requirements.
    text=re.sub(r'(?ms)^\s*```[^\n]*\n.*?^\s*```\s*$', '', goal)
    suffixes=r'(?:pyw?|pyi|js|jsx|mjs|cjs|ts|tsx|html|css|json|ya?ml|go|rs|cs|java|c|cc|cpp|h|hpp|sql)'
    for match in re.finditer(r'(?<!`)`([^`\n]{1,200})`(?!`)',text):
        token=match.group(1).strip()
        if re.fullmatch(r'(?:[A-Za-z0-9_.-]+/)*[A-Za-z0-9_.-]+\.'+suffixes,token):
            if '/' not in token and is_test(token) and token not in project_files:
                candidates = [name for name in project_files if Path(name).name == token]
                if len(candidates) != 1:
                    continue
                token = candidates[0]
            add({'kind':'file','path':token})
            continue
        if not re.fullmatch(r'[A-Za-z_][A-Za-z0-9_]*',token):continue
        context=text[max(0,match.start()-45):match.start()].casefold()
        kind=('parameter' if re.search(r'\b(?:parameter|argument)\s*$',context) else
              'function' if re.search(r'\b(?:function|method)\s*$',context) else
              'class' if re.search(r'\bclass\s*$',context) else 'identifier')
        if kind == 'identifier' and not re.search(
                r'\b(?:identifier|symbol|constant|variable|keep|rename|implement|define|preserve)\s*$', context):
            continue
        add({'kind':kind,'name':token})
    return result


def stages(project):
    result={'fast':parse_commands(project.get('fast_commands') or project['commands'])}
    for name in ('integration','e2e','acceptance'):
        commands=parse_commands(project.get(name+'_commands',''))
        if commands:result[name]=commands
    # Legacy verification commands remain mandatory even when fast commands differ.
    legacy=parse_commands(project['commands'])
    if legacy!=result['fast']:result['regression']=legacy
    return result


def preflight(project):
    if project.get('verification_profile')=='client':
        missing=[k for k in ('integration_commands','e2e_commands','criteria','required_files') if not project.get(k,'').strip()]
        if missing:
            raise ValueError('Профіль складного клієнта потребує: '+', '.join(missing))
        if not project.get('review'):raise ValueError('Профіль складного клієнта потребує AI-рев’ю за критеріями')


def fingerprint(snapshot):
    return hashlib.sha256(json.dumps(snapshot,sort_keys=True).encode()).hexdigest()


def is_test(name):
    parts=Path(name).parts
    base=Path(name).name.lower()
    return any(p.lower() in ('test','tests','__tests__') for p in parts) or base.startswith('test_') or base.endswith('_test.py') or '.test.' in base or '.spec.' in base or base=='tests.js'


def is_test_runner(command):
    """Recognize explicit test runners; compilation/build commands do not qualify."""
    if not isinstance(command,(list,tuple)) or not command:return False
    exe=Path(str(command[0])).stem.casefold()
    args=[str(value).casefold() for value in command[1:]]
    if exe.startswith('python') or exe in ('{python}','py','pytest'):
        return exe=='pytest' or ('-m' in args and any(args[i+1:i+2] and args[i+1] in ('pytest','unittest') for i,x in enumerate(args[:-1]) if x=='-m'))
    if exe in ('npm','pnpm','yarn'):return 'test' in args
    if exe in ('cargo','go'):return 'test' in args
    if exe=='dotnet':return 'test' in args
    if exe in ('node','nodejs'):return '--test' in args
    return False


def prerequisites(root, commands):
    """Known entry points only; missing bootstrap files defer an intermediate check."""
    missing=[];root=Path(root)
    for command in commands:
        exe=Path(command[0]).stem.lower()
        paths=[]
        if exe in ('node','nodejs') and len(command)>1 and not command[1].startswith('-'):paths.append(command[1])
        if command[0]=='{python}' or exe.startswith('python'):
            if len(command)>1 and not command[1].startswith('-'):paths.append(command[1])
            if 'discover' in command and '-s' in command:
                index=command.index('-s')+1
                if index<len(command):paths.append(command[index])
            if '-m' in command:
                index=command.index('-m')+1
                if index<len(command) and command[index]=='pytest':
                    paths.extend(a for a in command[index+1:] if not a.startswith('-') and (a.endswith('.py') or a in ('test','tests')))
        if exe in ('npm','npm.cmd','pnpm','yarn'):paths.append('package.json')
        for value in paths:
            path=Path(value)
            if not path.is_absolute():path=root/path
            if not path.exists():missing.append(value)
    return list(dict.fromkeys(missing))


class Assets(HTMLParser):
    def __init__(self):super().__init__();self.paths=[]
    def handle_starttag(self,tag,attrs):
        attrs=dict(attrs)
        if tag=='script' and attrs.get('src'):self.paths.append(attrs['src'])
        if tag=='link' and 'stylesheet' in attrs.get('rel','').split() and attrs.get('href'):self.paths.append(attrs['href'])


def task_editable_tests(goal, paths):
    """Grant existing-test edits only from an explicit directive in the host goal."""
    result=set()
    for line in str(goal).splitlines():
        if re.search(r"\b(?:do not|don't|never|must not|without)\s+(?:\w+\s+){0,2}"
                     r'(?:modify|change|update|edit|adjust|rename)\b[^.;\n]*\btests?\b|'
                     r'не\s+(?:змін|оновл|редаг)',line,re.I):
            continue
        if not re.search(r'\b(?:update|modify|adjust|change|rename|edit)\b|онов\w*|змін\w*|редаг\w*',line,re.I):
            continue
        if not re.search(r'\btests?\b|тест\w*',line,re.I):continue
        named={p.replace('\\','/') for p in re.findall(r'`([^`\n]+)`',line)}
        named_tests={p for p in paths if is_test(p) and p in named}
        if named_tests:
            result.update(named_tests)
        elif re.search(r'\b(?:existing|project|current)\s+tests\b|наявн\w*\s+тест\w*',line,re.I):
            result.update(p for p in paths if is_test(p))
    return sorted(result)


class Verification:
    def __init__(self, workspace, project, stop, log, checker=run_checks, record=None, final_verifier=None):
        self.workspace,self.project,self.stop,self.log,self.checker=workspace,project,stop,log,checker
        self.record=record or (lambda item:None)
        self.final_verifier = final_verifier
        self.commands=stages(project)
        self.latest={};self.cache={};self.counter=0
        self.ast_block_attempts=0;self.ast_guard_events=[];self.last_ast_guard_events=[]
        self.metrics={'runs':0,'seconds':0.0,'failures':0}
        declared=task_editable_tests(project.get('goal',''),workspace.before)
        project['editable_test_files']=sorted(set(project.get('editable_test_files',[]))|set(declared))
        self.task_editable_tests=declared
        editable={p.casefold() for p in project.get('editable_test_files',[])}
        self.pinned={n:h for n,h in workspace.before.items() if project.get('protect_tests',True)
                     and is_test(n) and n.casefold() not in editable}

    def check(self, root, commands):
        if self.checker is run_checks:
            sandbox = None
            if self.project.get('command_sandbox') == 'docker':
                sandbox = {'backend':'docker','image':self.project['sandbox_image'],
                           'network':self.project.get('sandbox_network',False),
                           'extra_mounts':getattr(self,'_extra_mounts',[])}
            ok,report=self.checker(root,commands,self.project['check_timeout'],self.stop,self.log,sandbox=sandbox)
        else:
            ok,report=self.checker(root,commands,self.project['check_timeout'],self.stop,self.log)
        return ok,redact(report)

    def guard_actions(self, actions):
        if not isinstance(actions,list):raise ValueError('actions має бути масивом')
        for action in actions:
            if isinstance(action,dict) and action.get('type')!='read' and str(action.get('path','')).casefold() in {n.casefold() for n in self.pinned}:
                raise ValueError('Зміна початкового тесту заборонена: '+action['path']+'. Додайте окремий тест або вимкніть захист у налаштуваннях.')

    def guard_tests(self):
        current=files(self.workspace.work)
        if any(current.get(n)!=h for n,h in self.pinned.items()):
            raise ValueError('Початкові тести змінені під час перевірки. Перенесення заблоковано.')

    def static(self, final=False):
        problems=[];ast_findings=[];ast_warnings=[];root=self.workspace.work
        self.last_ast_guard_events=[]
        names=files(root) if final else self.workspace.changes()
        scripts=[]
        for name in names:
            path=safe(root,name)
            if not path.is_file():continue
            suffix=path.suffix.lower()
            if suffix in ('.py','.pyw','.json'):
                try:
                    text=self.workspace.text(name)
                    if suffix=='.json':json.loads(text)
                    else:ast.parse(text,filename=name)
                except (ValueError,SyntaxError,UnicodeError) as error:problems.append(name+': '+str(error))
            if suffix in ('.js','.mjs','.cjs'):scripts.append(['node','--check',name])
            if suffix=='.html':
                parser=Assets();parser.feed(self.workspace.text(name))
                for value in parser.paths:
                    url=urlsplit(value)
                    if url.scheme or url.netloc or any(c in value for c in '{}$'):continue
                    relative=posixpath.normpath((Path(name).parent/ unquote(url.path)).as_posix()) if not value.startswith('/') else unquote(url.path).lstrip('/')
                    try:exists=safe(root,relative).is_file()
                    except ValueError:exists=False
                    if not exists:problems.append(name+': відсутній ресурс '+value)
        if final:
            available=set(names)
            for requirement in self.project.get('required_identifiers',[]):
                path=requirement.get('path');kind=requirement['kind']
                if kind=='file':
                    try:present=safe(root,path).is_file()
                    except ValueError:present=False
                    if not present:ast_findings.append((requirement,path,[path],f'{path}: required file is missing'))
                    continue
                name=requirement['name']
                targets=[path] if path else [candidate for candidate in available if Path(candidate).suffix.lower() in ('.py','.pyw')]
                found=False
                for source in targets:
                    try:
                        if source not in available:raise FileNotFoundError(source)
                        tree=ast.parse(self.workspace.text(source),filename=source)
                    except (ValueError,OSError,UnicodeError,SyntaxError) as error:
                        problems.append(f'{source}: cannot validate required {kind} {name}: {error}')
                        continue
                    nodes=ast.walk(tree)
                    if kind=='function':found=any(isinstance(node,(ast.FunctionDef,ast.AsyncFunctionDef)) and node.name==name for node in nodes)
                    elif kind=='class':found=any(isinstance(node,ast.ClassDef) and node.name==name for node in nodes)
                    elif kind=='parameter':found=any(isinstance(node,ast.arg) and node.arg==name for node in nodes)
                    else:found=any((isinstance(node,(ast.FunctionDef,ast.AsyncFunctionDef,ast.ClassDef)) and node.name==name) or
                        (isinstance(node,(ast.Name,ast.arg)) and getattr(node,'id',getattr(node,'arg',None))==name) or
                        (isinstance(node,ast.Attribute) and node.attr==name) for node in nodes)
                    if found:break
                if not found:
                    candidate=path or 'project-python-files'
                    ast_findings.append((requirement,candidate,targets,
                                         f'{candidate}: required {kind} identifier {name!r} is missing'))
        if ast_findings:
            self.ast_block_attempts+=1
            disposition='blocked' if self.ast_block_attempts<=3 else 'warning'
            tree_hash=fingerprint(files(root))
            for requirement,candidate,targets,message in ast_findings:
                token=requirement.get('name') or requirement.get('path')
                event={'rule_id':('required_file_present' if requirement['kind']=='file'
                                  else 'declared_identifier_present'),'declared_token':token,
                       'candidate_path':candidate,'tree_hash':tree_hash,
                       'searched_paths':targets[:100],
                       'attempt':self.ast_block_attempts,'disposition':disposition}
                self.ast_guard_events.append(event)
                self.last_ast_guard_events.append(event)
                if disposition=='blocked':problems.append(message)
                else:ast_warnings.append(message)
        warning_report=('AST-захист вичерпав ліміт блокувань; попередження (не блокують завершення):\n' +
                        '\n'.join(ast_warnings)) if ast_warnings else ''
        if problems:return False,'Структурні помилки:\n'+'\n'.join(problems)
        if scripts:
            ok,report=self.check(root,scripts)
            return ok,report+('\n'+warning_report if warning_report else '')
        return True,'Синтаксис і локальні ресурси: OK'+('\n'+warning_report if warning_report else '')

    def required(self):
        names=files(self.workspace.work)
        missing=[]
        for pattern in lines(self.project.get('required_files','')):
            matches=[n for n in names if fnmatch.fnmatchcase(n.casefold(),pattern.replace('\\','/').casefold())]
            if not matches or not any(safe(self.workspace.work,n).stat().st_size for n in matches):missing.append(pattern)
        return missing

    def run(self, name, final=False, force=False, commands=None):
        commands=self.commands[name] if commands is None else commands
        self.guard_tests()
        snapshot=files(self.workspace.work);signature=fingerprint(snapshot)
        if not final and not force and (name,signature) in self.cache:
            self.latest[name]=self.cache[(name,signature)]
            return self.latest[name]
        missing=prerequisites(self.workspace.work,commands)
        if missing:
            ok=False;status='failed' if final else 'pending'
            report='Очікуються файли/каталоги для перевірки: '+', '.join(missing)
        else:
            ok,report=self.check(self.workspace.work,commands)
            self.guard_tests()
            if files(self.workspace.work)!=snapshot:
                ok=False;report+='\nПеревірка змінила файли проєкту. Потрібна нова перевірка стабільного знімка; результати попереднього не підтверджують нові файли.'
            status='passed' if ok else 'failed'
        item={'name':name,'label':STAGE_LABELS.get(name,'Повна регресія'),'ok':ok,'status':status,
              'signature':signature,'at':time.time(),'final':final,'commands':commands,'report':report,
              'test_runner':any(is_test_runner(command) for command in commands)}
        if ok:self.cache[(name,signature)]=item
        self.remember(item)
        return item

    def run_generated_behavior_tests(self):
        """Generate a tiny unittest module outside candidate files from declarative task cases."""
        specs=self.project.get('behavioral_test_specs',[])
        criterion_ids={f'R{i}' for i,_ in enumerate(lines(self.project.get('criteria','')),1)}
        covered={rid for spec in specs for rid in spec['requirement_ids']}
        missing=sorted(criterion_ids-covered)
        snapshot=files(self.workspace.work);signature=fingerprint(snapshot)
        if not specs or not criterion_ids or missing:
            report=('No existing project tests were found and generated behavioral tests are unavailable or incomplete.'+
                    ((' Uncovered criteria: '+', '.join(missing)+'.') if missing else ''))
            item={'name':'generated_behavior','label':'Згенеровані поведінкові тести','ok':False,
                  'status':'blocked','signature':signature,'at':time.time(),'final':True,
                  'commands':[],'report':report,'test_runner':True,
                  'generation':'declarative_task_specs','covered_requirements':sorted(covered)}
            self.remember(item)
            return item
        payload=json.dumps(specs,ensure_ascii=False,separators=(',',':'),allow_nan=False)
        source=("import builtins, importlib, json, os, sys, unittest\n"
                "sys.path.insert(0, os.getcwd())\n"
                "SPECS=json.loads("+repr(payload)+")\n"
                "class GeneratedBehaviorTests(unittest.TestCase):\n"
                "    def test_declared_behavior_cases(self):\n"
                "        for spec in SPECS:\n"
                "            function=getattr(importlib.import_module(spec['module']),spec['symbol'])\n"
                "            for index, case in enumerate(spec['cases']):\n"
                "                with self.subTest(spec=spec['id'],case=index):\n"
                "                    if 'raises' in case:\n"
                "                        error=getattr(builtins,case['raises'])\n"
                "                        with self.assertRaises(error): function(*case['args'],**case['kwargs'])\n"
                "                    else:\n"
                "                        self.assertEqual(function(*case['args'],**case['kwargs']),case['expected'])\n"
                "if __name__=='__main__': unittest.main(verbosity=2)\n")
        with tempfile.TemporaryDirectory(prefix='lowforge-behavior-',dir=self.workspace.folder) as temp_dir:
            test_path=Path(temp_dir)/'test_generated_behavior.py'
            test_path.write_text(source,encoding='utf-8')
            self._extra_mounts=[{'source':str(test_path.resolve()),
                                 'target':'/verification/test_generated_behavior.py','readonly':True}]
            try:
                commands=[['{python}',str(test_path.resolve())]]
                missing_files=prerequisites(self.workspace.work,commands)
                if missing_files:
                    ok=False;report='Generated test file disappeared: '+', '.join(missing_files)
                else:
                    ok,report=self.check(self.workspace.work,commands)
            finally:
                self._extra_mounts=[]
        self.guard_tests()
        if files(self.workspace.work)!=snapshot:
            ok=False;report+='\nGenerated tests modified candidate workspace; behavioral verification rejected.'
        item={'name':'generated_behavior','label':'Згенеровані поведінкові тести','ok':ok,
              'status':'passed' if ok else 'failed','signature':signature,'at':time.time(),
              'final':True,'commands':commands,
              'report':report,'test_runner':True,'generation':'declarative_task_specs',
              'covered_requirements':sorted(covered),'test_source_sha256':hashlib.sha256(source.encode()).hexdigest()}
        self.remember(item)
        return item

    def remember(self, item):
        self.latest[item['name']]=item
        self.counter+=1
        filename=f'check-{self.counter:04d}.json'
        atomic(self.workspace.folder/'checks'/filename,json.dumps(item,ensure_ascii=False).encode())
        self.record({k:v for k,v in item.items() if k!='report'}|{'report_file':filename})
        self.log(item['label']+': '+item['status']+(' · '+item['report'][:500] if item['status'] in ('pending', 'failed') else ''))

    def run_all(self, final=False, selection=None, force=False):
        started=time.monotonic()
        try:
            result=self._run_all(final,selection,force)
            if not result[0]:self.metrics['failures']+=1
            return result
        finally:
            self.metrics['runs']+=1
            self.metrics['seconds']=round(self.metrics['seconds']+time.monotonic()-started,3)

    def run_host_final(self):
        """Run a trusted host-supplied check, never a model-supplied command.

        The callback owns its process timeout/cancellation and must return
        (bool, report). It supplements, rather than replaces, project tests.
        """
        snapshot = files(self.workspace.work)
        try:
            if self.stop.is_set():
                raise Cancelled()
            value = self.final_verifier(self.workspace.work, self.project['check_timeout'], self.stop)
            if self.stop.is_set():
                raise Cancelled()
            if (not isinstance(value, tuple) or len(value) != 2
                    or type(value[0]) is not bool or not isinstance(value[1], str)):
                raise ValueError('Host final verifier must return (bool, str)')
            ok, report = value
        except Cancelled:
            raise
        except Exception as error:
            ok, report = False, 'Host final verification error: ' + redact(str(error))
        self.guard_tests()
        if files(self.workspace.work) != snapshot:
            ok = False
            report += '\nHost final verifier changed candidate files; verification rejected.'
        item = {'name':'host_final', 'label':'Host final verification', 'ok':ok,
                'status':'passed' if ok else 'failed', 'signature':fingerprint(snapshot),
                'at':time.time(), 'final':True, 'commands':[], 'test_runner':False,
                'report':redact(failure_feedback(report, 12000))}
        self.remember(item)
        return item

    def _run_all(self, final=False, selection=None, force=False):
        missing=self.required() if final else []
        snapshot=files(self.workspace.work)
        if missing:static_ok,static_report=False,'Не створені обов’язкові файли: '+', '.join(missing)
        else:static_ok,static_report=self.static(final)
        self.guard_tests()
        if files(self.workspace.work)!=snapshot:
            static_ok=False;static_report+='\nСтатична перевірка змінила файли проєкту.'
        self.remember({'name':'static','label':'Структура і синтаксис','ok':static_ok,
                       'status':'passed' if static_ok else 'failed','signature':fingerprint(snapshot),
                       'at':time.time(),'final':final,'commands':[],'report':static_report,
                       'ast_guard_events':list(self.last_ast_guard_events),
                       'ast_block_attempts':self.ast_block_attempts})
        if not static_ok:return False,static_report
        names=list(self.commands) if selection is None else selection
        existing_tests=any(is_test(name) for name in files(self.workspace.work))
        configured_test_runner=any(is_test_runner(command)
                                   for group in self.commands.values() for command in group)
        results=[]
        if final and not existing_tests:
            # Test commands with no test files are not evidence; skip them and use the
            # isolated host-generated cases below, while still running build/lint checks.
            for name in names:
                remaining=[command for command in self.commands[name] if not is_test_runner(command)]
                if remaining:
                    results.append(self.run(name,final,force,commands=remaining))
                else:
                    item={'name':name,'label':STAGE_LABELS.get(name,'Повна регресія'),
                          'ok':True,'status':'not_applicable','signature':fingerprint(snapshot),
                          'at':time.time(),'final':True,'commands':[],'report':
                          'Configured test runner skipped because the project contains no tests; '
                          'isolated generated behavior cases are the required evidence.',
                          'test_runner':False}
                    self.remember(item);results.append(item)
            results.append(self.run_generated_behavior_tests())
        else:
            results=[self.run(name,final,force) for name in names]
            if final and existing_tests and not configured_test_runner:
                detected=parse_commands(detect(self.workspace.work))
                discovered=[command for command in detected if is_test_runner(command)]
                if discovered:
                    results.append(self.run('discovered_existing_tests',True,True,commands=discovered))
        gate=[]
        if final:
            current_signature=fingerprint(files(self.workspace.work))
            passing_tests=[item for item in results if item.get('test_runner') and item.get('ok')
                           and item.get('signature')==current_signature]
            if existing_tests and not passing_tests:
                gate.append('Наявні проєктні тести не пройшли на поточному знімку; статус verified заборонено.')
            # Generated cases are advisory when the task has no complete declarative
            # specification. A genuine generated-test failure remains a hard failure.
            # Missing specs must not consume model repair turns or block publication.
        if final and self.project.get('require_authored_tests'):
            current=files(self.workspace.work)
            authored=self.project.get('authored_test_files',[])
            changed=[name for name in authored if self.workspace.before.get(name)!=current.get(name) and name in current]
            if not changed:gate.append('Жоден обов’язковий authored test файл не був створений або змінений.')
            test_results=[item for item in results if any(is_test_runner(command) for command in item['commands'])]
            signature=fingerprint(current)
            passing=[item for item in test_results if item['ok'] and item['signature']==signature]
            if not passing:gate.append('Не знайдено успішного запуску test runner на поточному fingerprint файлів.')
        hard_results=[r for r in results if not (
            r.get('name')=='generated_behavior' and r.get('status')=='blocked')]
        success=all(r['ok'] for r in hard_results) and not gate
        if final and success and self.final_verifier is not None:
            item = self.run_host_final()
            results.append(item)
            success = item['ok']
        if gate:static_report+='\nAuthored tests gate FAILED:\n'+'\n'.join(gate)
        return success,'\n\n'.join([static_report]+[r['label']+' ['+r['status']+']\n'+r['report'] for r in results])[-60000:]

    def current_failure_diagnostics(self, snapshot):
        """Retain actionable failures while the checked source is unchanged."""
        signature = fingerprint(snapshot)
        reports = [
            item['label'] + ':\n' + item['report']
            for item in self.latest.values()
            if item['status'] == 'failed' and item['signature'] == signature
        ]
        if not reports:
            return ''
        report = '\n\n'.join(reports)
        diagnostics = failure_feedback(report, 2400)
        locations = re.finditer(
            r'(?m)^\s*File "(?P<python>[^"\n]+)", line (?P<py_line>\d+)\b'
            r'|^(?P<script>[^\r\n]+\.(?:js|mjs|cjs)):(?P<js_line>\d+)(?::\d+)?\s*$',
            report,
        )
        excerpts = {}
        root = self.workspace.work.resolve()

        def add_excerpt(name, line, source, radius=2):
            if (name, line) in excerpts or not 1 <= line <= len(source):
                return
            start, end = max(1, line - radius), min(len(source), line + radius)
            numbered = [
                f'{number}: {excerpt(source[number - 1], 200 if number != line else 600)}'
                for number in range(start, end + 1)
            ]
            excerpts[name, line] = redact(f'{name}:{line}\n' + '\n'.join(numbered))

        for location in locations:
            raw_path = (location['python'] or location['script']).replace('\\', '/')
            if raw_path.startswith('/workspace/'):
                name = raw_path.removeprefix('/workspace/')
            else:
                path = Path(raw_path)
                if path.is_absolute():
                    if not path.is_relative_to(root):
                        continue
                    path = path.relative_to(root)
                name = path.as_posix()
            if name not in snapshot or is_test(name):
                continue
            line = int(location['py_line'] or location['js_line'])
            if (name, line) in excerpts:
                continue
            try:
                source = self.workspace.text(name).splitlines()
            except (OSError, ValueError):
                continue
            add_excerpt(name, line, source)
            if len(excerpts) == 2:
                break
        if len(excerpts) < 2:
            routes = list(dict.fromkeys(re.findall(r'(?<![\w/])/api/[\w./-]+', report)))[:3]
            candidates = sorted(
                (name for name in snapshot if not is_test(name)
                 and Path(name).suffix in ('.py', '.js', '.mjs', '.ts')),
                key=lambda name: (Path(name).suffix != '.py', name.count('/'), name),
            )
            for name in candidates[:24] if routes else []:
                try:
                    source = self.workspace.text(name).splitlines()
                except (OSError, ValueError):
                    continue
                for line, text in enumerate(source, 1):
                    if any(f'"{route}"' in text or f"'{route}'" in text for route in routes):
                        add_excerpt(name, line, source, radius=4)
                        if len(excerpts) == 2:
                            break
                if len(excerpts) == 2:
                    break
        if excerpts:
            diagnostics += '\n\nSource near reported locations:\n' + '\n\n'.join(excerpts.values())
        return diagnostics

    def evidence(self):
        signature=fingerprint(files(self.workspace.work))
        return {name:{k:v for k,v in item.items() if k not in ('commands','report')}|
                {'current':item['signature']==signature,'report':excerpt(item['report'],1800)} for name,item in self.latest.items()}
