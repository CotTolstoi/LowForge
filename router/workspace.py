"""Bounded source snapshots and conflict-checked, recoverable publication."""
import ast
import fnmatch
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import secrets
import stat
import subprocess
import time

class EditMatchError(ValueError):
    """An exact edit has zero or multiple matches; the batch is unchanged."""

SKIP = {'.git', '.hg', '.svn', '.lowforge', '.router', '.venv', 'venv', 'node_modules',
        '__pycache__', 'bin', 'obj', 'dist', 'build', 'target', '.next', '.pytest_cache', '.idea', '.vs',
        'test-results', 'playwright-report', 'blob-report', 'coverage', 'htmlcov', '.nyc_output', '.coverage'}
MAX_FILE = 512 * 1024
MAX_ASSET = 16 * 1024 * 1024
MAX_TOTAL = 64 * 1024 * 1024
MAX_TEXT_CACHE = 4 * 1024 * 1024
ARTIFACT_SUFFIXES={'.dll','.exe','.pdb','.pyc','.class','.jar','.map'}
SECRET_PATTERNS=(
    ('AWS access key',re.compile(r'\bAKIA[0-9A-Z]{16}\b')),
    ('private key',re.compile(r'-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----')),
    ('credential assignment',re.compile(r'''(?i)\b(?:api[_-]?key|client[_-]?secret|access[_-]?token|password|passwd)\b\s*[:=]\s*['"][^'"]{8,}['"]''')),
    ('bearer credential',re.compile(r'(?i)\bBearer\s+[A-Za-z0-9._~+/=-]{20,}')),
)
PLACEHOLDERS=('example','sample','changeme','change_me','your_','dummy','placeholder','<', 'xxxx')


def private(name):
    p = PurePosixPath(name.replace('\\', '/'))
    return any(part.casefold() in SKIP for part in p.parts) or any(
        part.lower().startswith('.env') and part.lower() not in ('.env.example', '.env.sample')
        for part in p.parts) or p.name.lower() in ('id_rsa', 'id_ed25519', 'credentials.json', 'secrets.json') or p.suffix.lower() in ('.pem', '.key', '.pfx')


def linked(path):
    if path.is_symlink() or (hasattr(path, 'is_junction') and path.is_junction()):
        return True
    try:
        # Path.is_junction is only available in Python 3.12+. Cover 3.10/3.11 too.
        return bool(getattr(path.lstat(), 'st_file_attributes', 0) & getattr(stat, 'FILE_ATTRIBUTE_REPARSE_POINT', 0x400))
    except FileNotFoundError:
        return False


def safe(root, name):
    if not isinstance(name, str) or not name or any(c in name for c in '\\:<>"|?*') or any(ord(c) < 32 for c in name):
        raise ValueError('Некоректний шлях; використовуйте відносні шляхи з /')
    parts = name.split('/')
    if any(part in ('', '.', '..') or part.endswith((' ', '.')) or re.match(r'(?i)^(CON|PRN|AUX|NUL|COM[1-9]|LPT[1-9])(?:\.|$)', part) for part in parts) or private(name):
        raise ValueError('Заборонений шлях: ' + name)
    root = Path(root).resolve()
    result = root
    for part in parts:
        result /= part
        if linked(result):
            raise ValueError('Посилання та junction заборонені: ' + name)
    if not result.resolve().is_relative_to(root):
        raise ValueError('Шлях виходить за межі проєкту')
    return result


def files(root):
    root = Path(root).resolve()
    total = 0
    result = {}
    for base, dirs, names in os.walk(root, followlinks=False):
        dirs[:] = sorted(d for d in dirs if not private((Path(base) / d).relative_to(root).as_posix()) and not linked(Path(base) / d))
        for name in sorted(names):
            path = Path(base) / name
            rel = path.relative_to(root).as_posix()
            if private(rel) or linked(path):
                continue
            size = path.stat().st_size
            # Large source files must never silently disappear from the model's view.
            if size > MAX_FILE:
                if path.suffix.lower() in ('.py', '.cs', '.js', '.ts', '.tsx', '.json', '.html', '.css', '.md', '.cpp', '.rs', '.go'):
                    raise ValueError('Завеликий вихідний файл (>512 KiB): ' + rel)
                if size > MAX_ASSET:
                    raise ValueError('Завеликий ресурс (>16 MiB): ' + rel)
            data = path.read_bytes()
            total += len(data)
            if total > MAX_TOTAL or len(result) >= 6000:
                raise ValueError('Проєкт завеликий; виберіть окрему папку компонента')
            result[rel] = hashlib.sha256(data).hexdigest()
    return result


def _copy_windows_dacl(source, destination):
    """Copy the existing target's DACL onto its replacement before publishing it."""
    if os.name != 'nt':
        return
    import ctypes
    from ctypes import wintypes
    advapi=ctypes.WinDLL('advapi32',use_last_error=True)
    kernel=ctypes.WinDLL('kernel32',use_last_error=True)
    pointer=ctypes.c_void_p
    get_info=advapi.GetNamedSecurityInfoW
    get_info.argtypes=[wintypes.LPWSTR,wintypes.DWORD,wintypes.DWORD,
                       ctypes.POINTER(pointer),ctypes.POINTER(pointer),
                       ctypes.POINTER(pointer),ctypes.POINTER(pointer),ctypes.POINTER(pointer)]
    get_info.restype=wintypes.DWORD
    set_info=advapi.SetNamedSecurityInfoW
    set_info.argtypes=[wintypes.LPWSTR,wintypes.DWORD,wintypes.DWORD,
                       pointer,pointer,pointer,pointer]
    set_info.restype=wintypes.DWORD
    local_free=kernel.LocalFree
    local_free.argtypes=[pointer]
    local_free.restype=pointer
    dacl=pointer();descriptor=pointer()
    result=get_info(str(source),1,0x00000004,None,None,ctypes.byref(dacl),None,ctypes.byref(descriptor))
    if result:
        raise OSError(result,'Could not read the existing target DACL')
    try:
        result=set_info(str(destination),1,0x00000004,None,None,dacl,None)
        if result:
            raise OSError(result,'Could not preserve the existing target DACL')
    finally:
        if descriptor:local_free(descriptor)


def atomic(path, data):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    if linked(path):
        raise ValueError('Заміна symlink або reparse target заборонена')
    existing_mode = None
    try:
        target_stat = path.lstat()
        if not stat.S_ISREG(target_stat.st_mode):
            raise ValueError('Атомарний запис дозволений лише у звичайний файл')
        existing_mode = stat.S_IMODE(target_stat.st_mode)
    except FileNotFoundError:
        pass
    flags = os.O_CREAT | os.O_EXCL | os.O_WRONLY
    tmp = None
    fd = None
    for _ in range(20):
        candidate = path.parent / ('.router-' + secrets.token_hex(12))
        try:
            # Unlike mkstemp (0600), os.open applies the process umask to 0666.
            fd = os.open(candidate, flags, 0o666)
            tmp = candidate
            if os.name != 'nt':
                # Re-apply the kernel-computed, umask-filtered mode explicitly.
                # Reading it from the created descriptor avoids changing the
                # process-global umask (which would race with other threads).
                created_mode = stat.S_IMODE(os.fstat(fd).st_mode)
                try:
                    os.fchmod(fd, created_mode)
                except BaseException:
                    os.close(fd)
                    fd = None
                    os.unlink(tmp)
                    tmp = None
                    raise
            break
        except FileExistsError:
            continue
    if fd is None or tmp is None:
        raise FileExistsError('Не вдалося створити унікальний тимчасовий файл')
    try:
        with os.fdopen(fd, 'wb') as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        if existing_mode is not None:
            if os.name == 'nt':
                _copy_windows_dacl(path,tmp)
            else:
                os.chmod(tmp, existing_mode)
        os.replace(tmp, path)
    finally:
        if tmp is not None and os.path.exists(tmp):
            os.unlink(tmp)


class Workspace:
    def __init__(self, root, folder, language_servers=None, mcp_servers=None):
        self.root = Path(root).resolve()
        self.folder = Path(folder).resolve()
        self.work = self.folder / 'work'
        self.backup = self.folder / 'backup'
        if not self.root.is_dir():
            raise ValueError('Папка проєкту не існує')
        if self.folder.is_relative_to(self.root) or self.root.is_relative_to(self.folder):
            raise ValueError('Папка даних роутера має бути поза проєктом')
        self.before = files(self.root)
        self._index_cache_key=None
        self._index_cache_value=''
        self._index_stat_signatures={}
        self._index_hashes={}
        self._text_cache={}
        self._text_cache_bytes=0
        self._git_cache=None
        self.language_servers=dict(language_servers or {})
        self.mcp_servers=list(mcp_servers or [])
        self._mcp_catalog_cache={}
        self.last_action_metrics=[]
        self.work.mkdir(parents=True)
        for name in self.before:
            dest = safe(self.work, name)
            dest.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(safe(self.root, name), dest)
        atomic(self.folder / 'snapshot.json', json.dumps(self.before, ensure_ascii=False).encode())

    def text(self, name):
        p = safe(self.work, name)
        stat=p.stat()
        if stat.st_size > MAX_FILE:
            raise ValueError('Файл завеликий: ' + name)
        signature=(stat.st_size,stat.st_mtime_ns,stat.st_ctime_ns)
        cached=self._text_cache.get(name)
        if cached and cached[0]==signature:
            self._text_cache.pop(name);self._text_cache[name]=cached
            return cached[1]
        if cached:self._text_cache_bytes-=self._text_cache.pop(name)[2]
        value=p.read_text(encoding='utf-8-sig')
        if stat.st_size<=MAX_TEXT_CACHE:
            while self._text_cache_bytes+stat.st_size>MAX_TEXT_CACHE:
                oldest=next(iter(self._text_cache));self._text_cache_bytes-=self._text_cache.pop(oldest)[2]
            self._text_cache[name]=(signature,value,stat.st_size)
            self._text_cache_bytes+=stat.st_size
        return value

    def search(self, query, paths=None, limit=20):
        """Rank bounded text matches across the current working copy."""
        if not isinstance(query, str) or not query.strip() or len(query) > 400:
            raise ValueError('search.query має містити від 1 до 400 символів')
        if type(limit) is not int or not 1<=limit<=50:
            raise ValueError('search.limit має бути цілим числом від 1 до 50')
        if paths is not None and (not isinstance(paths, list) or len(paths) > 20 or
                                  any(not isinstance(p, str) or len(p) > 200 for p in paths)):
            raise ValueError('search.paths має містити до 20 шаблонів файлів')
        phrase=query.strip().casefold()
        terms = list(dict.fromkeys(re.findall(r'[\wА-Яа-яІіЇїЄєҐґ]{2,}', phrase)))
        if not terms:
            terms = [query.casefold()]
        matches = []
        for name in self._index_snapshot():
            if paths and not any(fnmatch.fnmatchcase(name.casefold(), pattern.replace('\\', '/').casefold())
                                 for pattern in paths):
                continue
            try:
                content = self.text(name)
            except (ValueError, OSError, UnicodeError):
                continue
            lines = content.splitlines()
            found = []
            score = (12 if phrase in name.casefold() else 0) + 2*sum(term in name.casefold() for term in terms)
            for number, line in enumerate(lines, 1):
                folded = line.casefold()
                hits = sum(folded.count(term) for term in terms)
                if hits:
                    score += hits + (5 if phrase in folded else 0)
                    if re.match(r'\s*(?:async\s+)?(?:def|class|function|export|const|let|var)\b',line):score+=2
                    found.append(f'{number}: {line[:320]}')
            if found:
                matches.append((score, name, found[:4]))
        matches.sort(key=lambda row: (-row[0], row[1].casefold()))
        if not matches:
            return 'Пошук не знайшов відповідних рядків.'
        return '\n'.join(f'[{name}] score={score}\n' + '\n'.join(lines)
                         for score, name, lines in matches[:limit])

    def symbols(self, query, paths=None, limit=100):
        """Locate exact identifier definitions and references in Python and JS/TS files."""
        if not isinstance(query,str) or not re.fullmatch(r'[A-Za-z_$][\w$]{0,99}',query):
            raise ValueError('symbols.query має бути назвою одного символу')
        if paths is not None and (not isinstance(paths,list) or len(paths)>20 or
                                  any(not isinstance(p,str) or len(p)>200 for p in paths)):
            raise ValueError('symbols.paths має містити до 20 шаблонів файлів')
        result=[]
        js_pattern=re.compile(r'(?<![\w$])'+re.escape(query)+r'(?![\w$])')
        for name in self._index_snapshot():
            suffix=Path(name).suffix.lower()
            if suffix not in ('.py','.pyw','.js','.mjs','.cjs','.ts','.tsx','.jsx'):
                continue
            if paths and not any(fnmatch.fnmatchcase(name.casefold(),p.replace('\\','/').casefold()) for p in paths):
                continue
            try:text=self.text(name)
            except (ValueError,OSError,UnicodeError):continue
            if suffix in ('.py','.pyw'):
                try:tree=ast.parse(text,filename=name)
                except SyntaxError as error:
                    result.append(f'{name}:{error.lineno}: Python syntax error; references unavailable')
                    continue
                source_lines=text.splitlines()
                for node in ast.walk(tree):
                    identifier=None
                    if isinstance(node,(ast.FunctionDef,ast.AsyncFunctionDef,ast.ClassDef)):identifier=node.name
                    elif isinstance(node,ast.Name):identifier=node.id
                    elif isinstance(node,ast.Attribute):identifier=node.attr
                    elif isinstance(node,ast.arg):identifier=node.arg
                    elif isinstance(node,ast.alias):identifier=node.asname or node.name.split('.')[0]
                    if identifier==query:
                        line=source_lines[node.lineno-1] if node.lineno<=len(source_lines) else ''
                        kind='definition' if isinstance(node,(ast.FunctionDef,ast.AsyncFunctionDef,ast.ClassDef)) else 'reference'
                        result.append(f'{name}:{node.lineno}:{getattr(node,"col_offset",0)+1} {kind}: {line.strip()[:240]}')
                        if len(result)>=limit:return '\n'.join(result)
            else:
                for number,line in enumerate(text.splitlines(),1):
                    if js_pattern.search(line):
                        result.append(f'{name}:{number} reference: {line.strip()[:240]}')
                        if len(result)>=limit:return '\n'.join(result)
        return '\n'.join(result) if result else 'Символ не знайдено.'

    def mcp_catalog(self,max_chars=12000):
        max_chars=max(500,min(int(max_chars),50000))
        if max_chars not in self._mcp_catalog_cache:
            from .mcp import catalog
            self._mcp_catalog_cache[max_chars]=catalog(self.mcp_servers,self.work,max_chars)
        return self._mcp_catalog_cache[max_chars]

    def _index_snapshot(self):
        """Reuse content hashes when an isolated file's size and timestamps are unchanged."""
        result={};signatures={};total=0
        for base,dirs,names in os.walk(self.work,followlinks=False):
            dirs[:]=sorted(d for d in dirs if not private((Path(base)/d).relative_to(self.work).as_posix())
                           and not linked(Path(base)/d))
            for name in sorted(names):
                path=Path(base)/name;relative=path.relative_to(self.work).as_posix()
                if private(relative) or linked(path):continue
                stat=path.stat();size=stat.st_size
                if size>MAX_FILE:
                    if path.suffix.lower() in ('.py','.cs','.js','.ts','.tsx','.json','.html','.css','.md','.cpp','.rs','.go'):
                        raise ValueError('Завеликий вихідний файл (>512 KiB): '+relative)
                    if size>MAX_ASSET:raise ValueError('Завеликий ресурс (>16 MiB): '+relative)
                total+=size
                if total>MAX_TOTAL or len(result)>=6000:raise ValueError('Проєкт завеликий; виберіть окрему папку компонента')
                signature=(size,stat.st_mtime_ns,stat.st_ctime_ns)
                if self._index_stat_signatures.get(relative)==signature:
                    digest=self._index_hashes[relative]
                else:
                    digest=hashlib.sha256(path.read_bytes()).hexdigest()
                result[relative]=digest;signatures[relative]=signature
        self._index_stat_signatures=signatures;self._index_hashes=result
        return result

    def index(self, max_chars=12000, snapshot=None):
        """Build a bounded symbol/import map to help the model navigate unfamiliar code."""
        snapshot=snapshot if snapshot is not None else self._index_snapshot()
        cache_key=(tuple(sorted(snapshot.items())),max_chars)
        if self._index_cache_key==cache_key:
            return self._index_cache_value
        rows=[]
        source_suffixes={'.py','.pyw','.js','.mjs','.cjs','.ts','.tsx','.jsx','.html','.sql'}
        for name in snapshot:
            suffix=Path(name).suffix.lower()
            basename=Path(name).name.lower()
            api_spec=basename in ('openapi.json','swagger.json','api-schema.json','openapi.yaml','openapi.yml','swagger.yaml','swagger.yml')
            package_config=basename=='package.json'
            schema_file=suffix=='.json' and (basename.endswith('.schema.json') or basename in ('schema.json','tsconfig.json'))
            config_file=(suffix in ('.json','.yaml','.yml','.toml') and
                         (basename in ('pyproject.toml','pytest.ini','tox.ini','setup.cfg','cargo.toml','composer.json',
                                       'docker-compose.yml','docker-compose.yaml','vite.config.json','tsconfig.json') or
                          basename.endswith(('.config.json','.config.yaml','.config.yml'))))
            docs_file=suffix=='.md' and (basename.startswith('readme') or name.casefold().startswith('docs/'))
            test_file=(any(part.casefold() in ('test','tests','__tests__') for part in Path(name).parts) or
                       basename.startswith('test_') or '.test.' in basename or '.spec.' in basename)
            if suffix not in source_suffixes and not api_spec and not package_config and not schema_file and not config_file and not docs_file:
                continue
            try:
                text=self.text(name)
            except (ValueError,OSError,UnicodeError):
                continue
            symbols=[]
            if Path(name).suffix.lower() in ('.py','.pyw'):
                try:
                    tree=ast.parse(text,filename=name)
                except SyntaxError as error:
                    rows.append(f'{name}: Python syntax error at line {error.lineno}')
                    continue
                for node in tree.body:
                    if isinstance(node,(ast.FunctionDef,ast.AsyncFunctionDef,ast.ClassDef)):
                        symbols.append(f'{node.name}@{node.lineno}')
                    elif isinstance(node,(ast.Import,ast.ImportFrom)):
                        module=(node.module or '') if isinstance(node,ast.ImportFrom) else ','.join(a.name for a in node.names)
                        if module:symbols.append('import '+module[:100])
                for node in ast.walk(tree):
                    if isinstance(node,ast.Constant) and isinstance(node.value,str) and node.value.startswith('/api/'):
                        symbols.append('route '+node.value[:120])
                    if test_file and isinstance(node,(ast.FunctionDef,ast.AsyncFunctionDef,ast.ClassDef)) and (node.name.startswith('test') or node.name.startswith('Test')):
                        symbols.append('test '+node.name[:100]+'@'+str(node.lineno))
            elif suffix=='.html':
                ids=list(dict.fromkeys(re.findall(r'\bid\s*=\s*[\'\"]([^\'\"]+)',text,re.I)))
                tabs=list(dict.fromkeys(re.findall(r'\bdata-tab\s*=\s*[\'\"]([^\'\"]+)',text,re.I)))
                symbols.extend('id #'+value for value in ids[:24])
                symbols.extend('tab '+value for value in tabs[:12])
            elif api_spec or package_config or schema_file or config_file:
                if suffix in ('.yaml','.yml'):
                    symbols.extend('API '+route[:120] for route in re.findall(r'(?m)^\s{2}(/[^:\s]+):\s*$',text)[:40])
                else:
                    try:document=json.loads(text)
                    except (ValueError,TypeError):document={}
                    if isinstance(document,dict):
                        if 'paths' in document and isinstance(document['paths'],dict):
                            for route,item in document['paths'].items():
                                if isinstance(item,dict):
                                    methods=[key.upper() for key in item if key.lower() in ('get','post','put','patch','delete')]
                                    symbols.extend(f'API {method} {route[:100]}' for method in methods[:8])
                        components=document.get('components',{})
                        schemas=components.get('schemas',{}) if isinstance(components,dict) else {}
                        if isinstance(schemas,dict):symbols.extend('schema '+str(key)[:80] for key in list(schemas)[:30])
                        for key in ('$defs','definitions'):
                            definitions=document.get(key,{})
                            if isinstance(definitions,dict):symbols.extend('schema '+str(name)[:80] for name in list(definitions)[:30])
                        if schema_file and isinstance(document.get('title'),str):symbols.append('schema title '+document['title'][:100])
                        scripts=document.get('scripts',{})
                        if isinstance(scripts,dict):symbols.extend('script '+str(key)[:80] for key in list(scripts)[:24])
                        if config_file:
                            symbols.extend('config key '+str(key)[:80] for key in list(document)[:30])
                if suffix in ('.toml','.yaml','.yml') or basename in ('pytest.ini','tox.ini','setup.cfg'):
                    symbols.extend('config section '+value[:80] for value in re.findall(r'(?m)^\s*\[([^\]]+)\]\s*$',text)[:30])
                    if suffix in ('.yaml','.yml'):
                        symbols.extend('config key '+value[:80] for value in re.findall(r'(?m)^([A-Za-z_][\w.-]*):',text)[:30])
            elif docs_file:
                symbols.extend('heading '+value[:120] for value in re.findall(r'(?m)^#{1,4}\s+(.+?)\s*#*\s*$',text)[:30])
                if not symbols:
                    first=next((line.strip() for line in text.splitlines() if line.strip()),'')
                    if first:symbols.append('document '+first[:120])
            elif suffix=='.sql':
                symbols.extend('db table '+value[:100] for value in re.findall(r'(?is)\bCREATE\s+TABLE\s+(?:IF\s+NOT\s+EXISTS\s+)?["`\[]?([\w.]+)',text)[:40])
                symbols.extend('db index '+value[:100] for value in re.findall(r'(?is)\bCREATE\s+(?:UNIQUE\s+)?INDEX\s+(?:IF\s+NOT\s+EXISTS\s+)?["`\[]?([\w.]+)',text)[:40])
            else:
                patterns=(r'^\s*(?:export\s+)?(?:default\s+)?(?:async\s+)?function\s+([\w$]+)',
                          r'^\s*(?:export\s+)?class\s+([\w$]+)',
                          r'^\s*(?:export\s+)?(?:const|let|var)\s+([\w$]+)\s*=',
                          r'^\s*import\s+(?:.+?\s+from\s+)?[\'\"]([^\'\"]+)')
                for number,line in enumerate(text.splitlines(),1):
                    for pattern in patterns:
                        match=re.search(pattern,line)
                        if match:
                            label='import '+match.group(1) if pattern==patterns[-1] else match.group(1)
                            if suffix in ('.jsx','.tsx') and pattern in (patterns[0],patterns[2]) and label[:1].isupper():
                                label='component '+label
                            symbols.append(f'{label[:100]}@{number}')
                            break
                    if test_file:
                        test_match=re.search(r'\b(?:describe|it|test)\s*\(\s*[\'\"]([^\'\"]+)',line)
                        if test_match:symbols.append('test '+test_match.group(1)[:100]+'@'+str(number))
            if symbols:
                rows.append(name+': '+', '.join(symbols[:40]))
        result='\n'.join(rows) if rows else 'Індекс символів не знайшов оголошень у підтримуваних мовах.'
        if len(result)>max_chars:
            result=result[:max_chars]+'\n[індекс обрізано; використайте search для точного пошуку]'
        self._index_cache_key=cache_key
        self._index_cache_value=result
        return result

    def git_context(self, max_chars=5000):
        """Read-only status summaries for the user's source tree; never expose diff contents."""
        if isinstance(self._git_cache,dict) and max_chars in self._git_cache:
            return self._git_cache[max_chars]
        if self._git_cache is None:self._git_cache={}
        if not shutil.which('git'):
            result='Git недоступний у PATH.'
            self._git_cache[max_chars]=result
            return result
        sections=[]
        commands=(('status',['status','--short','--branch','--untracked-files=no','--','.']),
                  ('зміни',['diff','--stat','--no-ext-diff','--no-textconv','--','.']),
                  ('підготовлені зміни',['diff','--cached','--stat','--no-ext-diff','--no-textconv','--','.']))
        for label,args in commands:
            try:
                result=subprocess.run(['git','-c','core.fsmonitor=false','-C',str(self.root),*args],capture_output=True,text=True,
                                      encoding='utf-8',errors='replace',timeout=4,shell=False)
            except (OSError,subprocess.SubprocessError):
                result='Не вдалося безпечно прочитати Git-стан (таймаут або помилка запуску).'
                self._git_cache[max_chars]=result
                return result
            if result.returncode:
                if label=='status' and ('not a git repository' in result.stderr.lower() or 'not a git repository' in result.stdout.lower()):
                    summary='Проєкт не є Git-репозиторієм.'
                    self._git_cache[max_chars]=summary
                    return summary
                summary='Git-діагностика недоступна: '+result.stderr[:300]
                self._git_cache[max_chars]=summary
                return summary
            sections.append(label+':\n'+(result.stdout.strip() or 'немає'))
        result='\n\n'.join(sections)
        result=result[:max_chars]+('\n[діагностику обрізано]' if len(result)>max_chars else '')
        self._git_cache[max_chars]=result
        return result

    def apply(self, actions):
        if not isinstance(actions, list) or not 1 <= len(actions) <= 12:
            raise ValueError('actions: від 1 до 12 дій')
        action_fields={
            'read':({'type','path','start_line','end_line'},{'type','path'}),
            'search':({'type','query','paths'},{'type','query'}),
            'symbols':({'type','query','paths'},{'type','query'}),
            'lsp':({'type','path','operation','line','character','query'},{'type','path','operation','line','character','query'}),
            'mcp':({'type','server','tool','arguments'},{'type','server','tool','arguments'}),
            'write':({'type','path','content'},{'type','path','content'}),
            'write_chunk':({'type','path','content','offset_bytes'},{'type','path','content','offset_bytes'}),
            'edit':({'type','path','old','new'},{'type','path','old','new'}),
            'delete':({'type','path'},{'type','path'})}
        # Validate all actions before the first mutation.
        pending = {}
        action_metrics=[]
        self.last_action_metrics=action_metrics
        pending_action={}
        reads = {}
        searches = []
        symbol_searches=[]
        lsp_requests=[]
        mcp_requests=[]
        def current(name):
            if name in pending:
                if pending[name] is None:
                    raise ValueError('Файл уже видалено попередньою дією: ' + name)
                return pending[name]
            return self.text(name)

        for action_index,action in enumerate(actions):
            action_started=time.monotonic()
            if not isinstance(action, dict):
                raise ValueError('Кожна дія має бути об’єктом')
            kind, name = action.get('type'), action.get('path')
            metric={'name':kind if isinstance(kind,str) else 'invalid','path':name if isinstance(name,str) else None,
                    'result_chars':0}
            action_metrics.append(metric)
            self.last_action_metrics=action_metrics[-100:]
            if not isinstance(kind,str) or kind not in action_fields:
                raise ValueError('Невідомий тип дії: '+str(kind)[:80])
            allowed,required=action_fields[kind]
            if set(action)-allowed or required-set(action):
                raise ValueError(f'{kind}: невідомі або відсутні поля дії')
            if kind == 'search':
                searches.append((action_index,action.get('query'), action.get('paths')))
                metric['seconds']=round(time.monotonic()-action_started,4)
                continue
            if kind == 'symbols':
                symbol_searches.append((action_index,action.get('query'),action.get('paths')))
                metric['seconds']=round(time.monotonic()-action_started,4)
                continue
            if kind == 'lsp':
                lsp_requests.append((action_index,action))
                metric['seconds']=round(time.monotonic()-action_started,4)
                continue
            if kind == 'mcp':
                mcp_requests.append((action_index,action))
                metric['seconds']=round(time.monotonic()-action_started,4)
                continue
            path = safe(self.work, name)
            if kind == 'read':
                content = current(name)
                source_lines = content.splitlines(keepends=True)
                metric['requested_start_line'] = action.get('start_line')
                metric['requested_end_line'] = action.get('end_line')
                actual_start, actual_end = 1, len(source_lines)
                if 'start_line' in action or 'end_line' in action:
                    start, end = action.get('start_line'), action.get('end_line')
                    start = 1 if start is None else start
                    end = len(source_lines) if end is None else end
                    if type(start) is not int or type(end) is not int or start < 1 or end < start:
                        raise ValueError('Некоректний діапазон рядків')
                    actual_start, actual_end = start, min(end, len(source_lines))
                    content = f'[LINES {start}-{end}]\n' + ''.join(source_lines[start-1:end])
                metric['returned_line_ranges'] = [[actual_start, actual_end]] if actual_end >= actual_start else []
                # Preserve every requested slice of one file in this action batch.
                # Returning only the last slice traps the model in repeated reads.
                if name in reads and reads[name] != content:
                    reads[name] += '\n\n' + content
                else:
                    reads[name] = content
                metric['result_chars']=len(content)
                metric['seconds']=round(time.monotonic()-action_started,4)
                continue
            if kind in ('write','write_chunk'):
                content = action.get('content')
                if not isinstance(content, str):
                    raise ValueError(kind+' потребує рядка content')
                if kind=='write_chunk':
                    offset=action.get('offset_bytes')
                    if type(offset) is not int or offset<0:
                        raise ValueError('write_chunk.offset_bytes має бути невід’ємним цілим числом')
                    existing=current(name) if offset else ''
                    current_bytes=existing.encode('utf-8')
                    if len(current_bytes)!=offset:
                        raise ValueError(f'write_chunk.offset_bytes не збігається з поточним розміром {len(current_bytes)} байтів')
                    content=existing+content
            elif kind == 'edit':
                old, new = action.get('old'), action.get('new')
                content = current(name)
                if not isinstance(old, str) or not old or not isinstance(new, str):
                    raise ValueError('edit requires a nonempty string old and a string new: ' + name)
                matches=content.count(old)
                if matches != 1:
                    raise EditMatchError(f'edit.old must occur exactly once: {name}; matches={matches}; '
                                     'no changes from this action batch were applied. Use the current observation '
                                     'or read the file, then submit an exact unique old string with a changed new value. '
                                     'Do not repeat the rejected edit or guess whitespace/escaping.')
                content = content.replace(old, new, 1)
            elif kind == 'delete':
                if (name in pending and pending[name] is None) or (name not in pending and not path.is_file()):
                    raise ValueError('Файл для видалення не існує: ' + name)
                content = None
            else:
                raise ValueError('Невідомий тип дії: ' + str(kind))
            if content is not None and len(content.encode('utf-8')) > MAX_FILE:
                raise ValueError('Завеликий вміст файла: ' + name)
            pending[name] = content
            pending_action[name]=action_index
            metric['seconds']=round(time.monotonic()-action_started,4)
        if mcp_requests and len(actions)!=1:
            raise ValueError('MCP-виклик має бути окремим кроком; перевірте результат перед наступною дією')
        if (searches or symbol_searches or lsp_requests) and pending:
            raise ValueError('Виконуйте пошук, символи й LSP окремим кроком до редагування файлів')
        if searches:
            for index, (action_index,query, paths) in enumerate(searches, 1):
                started=time.monotonic();value=self.search(query, paths)
                reads[f'search/{index}']=value
                action_metrics[action_index]['seconds']=round(action_metrics[action_index].get('seconds',0)+time.monotonic()-started,4)
                action_metrics[action_index]['result_chars']=len(value)
        for index,(action_index,query,paths) in enumerate(symbol_searches,1):
            started=time.monotonic();value=self.symbols(query,paths)
            reads[f'symbols/{index}']=value
            action_metrics[action_index]['seconds']=round(action_metrics[action_index].get('seconds',0)+time.monotonic()-started,4)
            action_metrics[action_index]['result_chars']=len(value)
        for index,(action_index,action) in enumerate(lsp_requests,1):
            started=time.monotonic()
            name=action.get('path')
            source_path=safe(self.work,name)
            suffix=source_path.suffix.lower()
            language=('python' if suffix=='.py' else 'typescript' if suffix in ('.ts','.tsx','.js','.jsx') else None)
            command=self.language_servers.get(language)
            if language is None or not command:
                value='LSP is not configured for this file type; configure it in project settings.'
                reads[f'lsp/{index}']=value
                action_metrics[action_index]['seconds']=round(time.monotonic()-started,4)
                action_metrics[action_index]['result_chars']=len(value)
                continue
            from .lsp import query as lsp_query
            try:
                reads[f'lsp/{index}']=lsp_query(command,self.work,name,action.get('operation'),language,
                    line=action.get('line'),character=action.get('character'),query=action.get('query',''))
            except (ValueError,TimeoutError,OSError,subprocess.SubprocessError) as error:
                reads[f'lsp/{index}']='LSP unavailable: '+str(error)[:1000]
            action_metrics[action_index]['seconds']=round(time.monotonic()-started,4)
            action_metrics[action_index]['result_chars']=len(reads[f'lsp/{index}'])
        for index,(action_index,action) in enumerate(mcp_requests,1):
            started=time.monotonic()
            from .mcp import call as mcp_call
            try:
                arguments=action.get('arguments','{}')
                if isinstance(arguments,str):arguments=json.loads(arguments)
                if not isinstance(arguments,dict):raise ValueError('MCP arguments мають бути JSON-об’єктом')
                reads[f'mcp/{index}']=mcp_call(self.mcp_servers,self.work,action.get('server'),
                    action.get('tool'),arguments)
            except (ValueError,TimeoutError,OSError) as error:
                reads[f'mcp/{index}']='MCP call failed: '+str(error)[:1000]
            action_metrics[action_index]['seconds']=round(time.monotonic()-started,4)
            action_metrics[action_index]['result_chars']=len(reads[f'mcp/{index}'])
        for name, content in pending.items():
            started=time.monotonic()
            path = safe(self.work, name)
            if content is None:
                if path.exists():
                    path.unlink()
            else:
                atomic(path, content.encode('utf-8'))
            action_index=pending_action.get(name)
            if action_index is not None:
                action_metrics[action_index]['seconds']=round(action_metrics[action_index].get('seconds',0)+time.monotonic()-started,4)
        for metric in action_metrics:
            metric['estimated_result_tokens']=(metric.get('result_chars',0)+3)//4
        self.last_action_metrics=action_metrics[-100:]
        return reads, list(pending)

    def checkpoint(self, step=0, feedback=''):
        """Persist a compact manifest for inspection and explicit run resume."""
        snapshot = files(self.work)
        atomic(self.folder / 'checkpoint.json', json.dumps({
            'version': 1, 'root': str(self.root), 'step': int(step),
            'snapshot': self.before, 'current': snapshot,
            'changed': sorted(n for n in self.before.keys() | snapshot.keys()
                              if self.before.get(n) != snapshot.get(n)),
            'feedback': str(feedback)[:4000]
        }, ensure_ascii=False).encode())

    def capture_step(self, actions, step):
        """Save pre-change copies for files a single model step may mutate."""
        names=list(dict.fromkeys(a.get('path') for a in actions
                                 if isinstance(a,dict) and a.get('type') in ('write','write_chunk','edit','delete')))
        if not names:
            return False
        folder=self.folder/'checkpoints'/f'step-{int(step):04d}'
        if folder.exists():
            shutil.rmtree(folder)
        folder.mkdir(parents=True)
        existed=[]
        for name in names:
            source=safe(self.work,name)
            if source.is_file():
                target=safe(folder,name)
                target.parent.mkdir(parents=True,exist_ok=True)
                shutil.copy2(source,target)
                existed.append(name)
        atomic(folder/'manifest.json',json.dumps({'step':int(step),'paths':names,'existed':existed},ensure_ascii=False).encode())
        return True

    def rollback_last(self):
        root=self.folder/'checkpoints'
        steps=sorted(root.glob('step-[0-9][0-9][0-9][0-9]')) if root.exists() else []
        if not steps:
            raise ValueError('Немає збереженого кроку для відкату')
        step=int(steps[-1].name[-4:])
        self.rollback_to_step(step)
        return step

    def rollback_to_step(self, step):
        """Restore the working copy to immediately before step, removing that step and later checkpoints."""
        if type(step) is not int or step<1:
            raise ValueError('Номер кроку має бути додатним цілим числом')
        root=self.folder/'checkpoints'
        folders=sorted(root.glob('step-[0-9][0-9][0-9][0-9]')) if root.exists() else []
        selected=[folder for folder in folders if int(folder.name[-4:])>=step]
        if not selected or not any(int(folder.name[-4:])==step for folder in selected):
            raise ValueError('Для вибраного кроку немає контрольної точки')
        restore={}
        for folder in reversed(selected):
            try:
                manifest=json.loads((folder/'manifest.json').read_text(encoding='utf-8'))
            except (OSError,ValueError,TypeError) as error:
                raise ValueError('Не вдалося прочитати контрольну точку '+folder.name) from error
            number=int(folder.name[-4:])
            if manifest.get('step')!=number or not isinstance(manifest.get('paths'),list):
                raise ValueError('Пошкоджений маніфест контрольної точки '+folder.name)
            existed=set(manifest.get('existed',[]))
            for name in manifest['paths']:
                target=safe(self.work,name)
                if name in existed:
                    source=safe(folder,name)
                    if not source.is_file():
                        raise ValueError('У контрольній точці відсутня копія '+name)
                    restore[name]=source.read_bytes()
                else:
                    restore[name]=None
        previous={}
        for name in restore:
            path=safe(self.work,name)
            if path.exists() and not path.is_file():
                raise ValueError('Не можна відновити файл поверх каталогу: '+name)
            previous[name]=path.read_bytes() if path.is_file() else None
        applied=[]
        try:
            for name,data in restore.items():
                path=safe(self.work,name)
                if data is None:
                    if path.exists():path.unlink()
                else:
                    path.parent.mkdir(parents=True,exist_ok=True)
                    atomic(path,data)
                applied.append(name)
        except Exception:
            for name in reversed(applied):
                path=safe(self.work,name);data=previous[name]
                if data is None:
                    if path.exists():path.unlink()
                else:
                    atomic(path,data)
            raise
        for folder in selected:shutil.rmtree(folder)
        self.checkpoint(step-1,f'Відновлено стан перед кроком {step}; наступний запуск має повторити його.')
        return [int(folder.name[-4:]) for folder in selected]

    @classmethod
    def resume(cls, root, folder, language_servers=None, mcp_servers=None):
        """Open a saved work copy only when its original project is unchanged."""
        self = cls.__new__(cls)
        self.root, self.folder = Path(root).resolve(), Path(folder).resolve()
        self.work, self.backup = self.folder / 'work', self.folder / 'backup'
        self._index_cache_key=None
        self._index_cache_value=''
        self._index_stat_signatures={}
        self._index_hashes={}
        self._text_cache={}
        self._text_cache_bytes=0
        self._git_cache=None
        self.language_servers=dict(language_servers or {})
        self.mcp_servers=list(mcp_servers or [])
        self._mcp_catalog_cache={}
        if not self.root.is_dir() or not self.work.is_dir():
            raise ValueError('Немає збереженої робочої копії для продовження')
        try:
            self.before = json.loads((self.folder / 'snapshot.json').read_text(encoding='utf-8'))
        except (OSError, ValueError, TypeError) as error:
            raise ValueError('Не вдалося прочитати знімок перерваної задачі') from error
        if not isinstance(self.before, dict) or files(self.root) != self.before:
            raise ValueError('Вихідний проєкт змінився після переривання; продовження заблоковане для захисту файлів')
        self.checkpoint()
        return self

    def changes(self):
        after = files(self.work)
        return sorted(n for n in self.before.keys() | after.keys() if self.before.get(n) != after.get(n))

    def publication_warnings(self):
        """Return bounded, value-free warnings about candidate files before publication."""
        warnings=[]
        for name in self.changes():
            path=safe(self.work,name)
            if not path.is_file():continue
            size=path.stat().st_size
            if size>1024*1024:
                warnings.append(f'Великий файл: {name} ({size//1024} KiB)')
            if path.suffix.lower() in ARTIFACT_SUFFIXES:
                warnings.append(f'Можливий build-артефакт: {name}')
            if size>MAX_FILE:continue
            try:lines=path.read_text(encoding='utf-8-sig').splitlines()
            except (OSError,UnicodeError):continue
            for number,line in enumerate(lines,1):
                folded=line.casefold()
                if any(pattern.search(line) for _,pattern in SECRET_PATTERNS):
                    if any(marker in folded for marker in PLACEHOLDERS):continue
                    labels=[label for label,pattern in SECRET_PATTERNS if pattern.search(line)]
                    warnings.append(f'Можливий секрет ({", ".join(labels)}): {name}:{number}')
                    if len(warnings)>=100:return warnings
        return warnings

    def syntax(self):
        errors = []
        for name in self.changes():
            path = safe(self.work, name)
            if path.is_file() and path.suffix == '.py':
                try:
                    ast.parse(self.text(name), filename=name)
                except SyntaxError as error:
                    errors.append(str(error))
        return '\n'.join(errors)

    def publish(self):
        changed = self.changes()
        current = files(self.root)
        # All source changes invalidate test evidence, including independent user edits.
        if current != self.before:
            raise ValueError('Конфлікт: вихідні файли змінилися під час виконання. Робочу копію збережено.')
        for name in changed:
            path = safe(self.root, name)
            if path.exists() and name not in self.before:
                raise ValueError('Конфлікт із наявним файлом: ' + name)
        self.backup.mkdir(parents=True, exist_ok=True)
        journal = {'state': 'prepared', 'root': str(self.root), 'changed': changed,
                   'existed': [n for n in changed if safe(self.root, n).exists()]}
        for name in journal['existed']:
            dest = safe(self.backup, name)
            dest.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(safe(self.root, name), dest)
        atomic(self.folder / 'publication.json', json.dumps(journal, ensure_ascii=False).encode())
        applied = []
        try:
            for name in changed:
                dest, source = safe(self.root, name), safe(self.work, name)
                applied.append(name)
                if source.exists():
                    atomic(dest, source.read_bytes())
                elif dest.exists():
                    dest.unlink()
        except Exception:
            for name in reversed(applied):
                dest = safe(self.root, name)
                if name in journal['existed']:
                    atomic(dest, safe(self.backup, name).read_bytes())
                elif dest.exists():
                    dest.unlink()
            journal['state'] = 'rolled_back'
            atomic(self.folder / 'publication.json', json.dumps(journal).encode())
            raise
        journal['state'] = 'committed'
        atomic(self.folder / 'publication.json', json.dumps(journal).encode())
        return changed
