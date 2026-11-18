"""Only host-configured commands run, with process-tree cancellation."""
import json
import os
from pathlib import Path
import re
import shlex
import shutil
import signal
import subprocess
import sys
import tempfile
import time

from .providers import Cancelled


def excerpt(text,limit):
    if len(text)<=limit:return text
    marker='\n[Середину виводу скорочено; збережено початок і кінець]\n'
    half=max(0,(limit-len(marker))//2)
    return text[:half]+marker+text[-half:]


def failure_feedback(report, limit=10000):
    """Keep a diagnostic for each unittest failure before including verbose output."""
    report = report.replace('\r\n', '\n')
    blocks = list(re.finditer(
        r'(?ms)^(?:FAIL|ERROR): [^\n]+\n-{10,}\n(.*?)(?=^[=-]{10,}\s*$|\Z)',
        report,
    ))
    if not blocks:
        return excerpt(report, limit)
    titles = [block.group().splitlines()[0][:240] for block in blocks]
    prefix = report[:blocks[0].start()]
    exceptions = re.findall(r'(?m)^Application exception: .+$', prefix)
    if not exceptions and 'Traceback (most recent call last):' in prefix:
        exceptions = [
            'Application exception: ' + line
            for line in re.findall(r'(?m)^(?:[A-Za-z_][\w.]*(?:Error|Exception)|re\.error): [^\n]+', prefix)
        ]
    primary = '\n'.join(dict.fromkeys(line[:200] for line in exceptions[-2:]))
    if primary:
        frames = re.findall(r'(?m)^ *File "/workspace/[^"\n]+", line \d+(?:, in [^\n]+)?', prefix)
        if frames and len(frames[-1]) <= 240:
            primary += '\n' + frames[-1]
    header = (primary + '\n' if primary and len(primary) < limit // 3 else '') + 'Unittest failure diagnostics:\n'
    share = (limit - len(header) - sum(len(title) + 24 for title in titles)) // len(blocks)
    if share < 120:
        return excerpt(header + '\n'.join(titles), limit)
    diagnostics = []
    for title, block in zip(titles, blocks):
        body = block.group(1).strip()
        # Assertions can embed an entire generated file on one line. Retain
        # the exception and expected value before budgeting traceback frames.
        line_limit = max(120, share // 2)
        body = '\n'.join(
            line if len(line) <= line_limit else
            line[:line_limit * 3 // 4] + ' [...line shortened...] ' + line[-line_limit // 4:]
            for line in body.splitlines()
        )
        if len(body) > share:
            # Traceback endings contain the exception type and assertion message.
            body = body[:share // 4] + '\n[...traceback shortened...]\n' + body[-(share * 3 // 4 - 32):]
        diagnostics.append(title + '\n----------\n' + body + '\n==========')
    return header + '\n'.join(diagnostics)


def parse_commands(text):
    if not isinstance(text, str):
        raise ValueError('Команди мають бути текстом')
    result = []
    for line in text.splitlines():
        if not line.strip():
            continue
        lexer = shlex.shlex(line, posix=True)
        lexer.whitespace_split = True
        lexer.commenters = ''
        lexer.escape = ''
        args = list(lexer)
        if not args or len(args) > 80 or any('\x00' in a for a in args):
            raise ValueError('Некоректна команда перевірки')
        result.append(args)
    if len(result) > 20:
        raise ValueError('Не більше 20 команд перевірки')
    return result


def detect(root):
    root = Path(root)
    result = []
    # Detection only suggests commands. The user saves the commands before running.
    # Test files identify Python projects even with a src/ package layout and
    # without packaging metadata or Python files at the repository root.
    if list((root / 'tests').glob('test*.py')):
        is_pytest = any(re.search(r'\b(?:import pytest|from pytest)\b', p.read_text(encoding='utf-8', errors='replace')) for p in (root / 'tests').glob('*.py'))
        result.append('{python} -m pytest -q' if is_pytest else '{python} -m unittest discover -s tests -v')
    solutions = sorted(root.glob('*.sln')) + sorted(root.glob('*.slnx'))
    projects = sorted(root.glob('*.csproj'))
    for target in (solutions or projects)[:3]:
        result.extend([f'dotnet build "{target.name}" --nologo', f'dotnet test "{target.name}" --nologo'])
    if (root / 'package.json').exists():
        try:
            scripts = json.loads((root / 'package.json').read_text(encoding='utf-8-sig')).get('scripts', {})
            result.extend('npm run ' + key for key in ('typecheck', 'build', 'test') if scripts.get(key) and 'no test specified' not in scripts[key])
        except (ValueError, AttributeError, TypeError):
            pass
    if (root / 'Cargo.toml').exists():
        result.append('cargo test')
    if (root / 'go.mod').exists():
        result.append('go test ./...')
    return '\n'.join(result)


def kill(process):
    if process.poll() is not None:
        return
    if os.name == 'nt':
        terminated=_terminate_windows_tree(process.pid)
        if not terminated:
            try:
                subprocess.run(['taskkill', '/PID', str(process.pid), '/T', '/F'], capture_output=True, timeout=3,
                               creationflags=subprocess.CREATE_NO_WINDOW)
            except (OSError,subprocess.SubprocessError):
                pass
    else:
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
    try:
        process.wait(timeout=10)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait(timeout=10)


def _terminate_windows_tree(root_pid):
    """Terminate a process and its descendants without relying on taskkill permissions."""
    if os.name!='nt':return False
    import ctypes
    from ctypes import wintypes

    class ProcessEntry(ctypes.Structure):
        _fields_=[('dwSize',wintypes.DWORD),('cntUsage',wintypes.DWORD),
                  ('th32ProcessID',wintypes.DWORD),('th32DefaultHeapID',ctypes.c_size_t),
                  ('th32ModuleID',wintypes.DWORD),('cntThreads',wintypes.DWORD),
                  ('th32ParentProcessID',wintypes.DWORD),('pcPriClassBase',ctypes.c_long),
                  ('dwFlags',wintypes.DWORD),('szExeFile',wintypes.WCHAR*260)]

    kernel=ctypes.WinDLL('kernel32',use_last_error=True)
    kernel.CreateToolhelp32Snapshot.argtypes=[wintypes.DWORD,wintypes.DWORD]
    kernel.CreateToolhelp32Snapshot.restype=wintypes.HANDLE
    kernel.Process32FirstW.argtypes=[wintypes.HANDLE,ctypes.POINTER(ProcessEntry)]
    kernel.Process32FirstW.restype=wintypes.BOOL
    kernel.Process32NextW.argtypes=[wintypes.HANDLE,ctypes.POINTER(ProcessEntry)]
    kernel.Process32NextW.restype=wintypes.BOOL
    kernel.OpenProcess.argtypes=[wintypes.DWORD,wintypes.BOOL,wintypes.DWORD]
    kernel.OpenProcess.restype=wintypes.HANDLE
    kernel.TerminateProcess.argtypes=[wintypes.HANDLE,wintypes.UINT]
    kernel.TerminateProcess.restype=wintypes.BOOL
    kernel.CloseHandle.argtypes=[wintypes.HANDLE]
    kernel.CloseHandle.restype=wintypes.BOOL
    snapshot=kernel.CreateToolhelp32Snapshot(0x00000002,0)
    invalid=ctypes.c_void_p(-1).value
    if snapshot in (None,invalid):return False
    children={}
    try:
        entry=ProcessEntry();entry.dwSize=ctypes.sizeof(entry)
        if kernel.Process32FirstW(snapshot,ctypes.byref(entry)):
            while True:
                children.setdefault(entry.th32ParentProcessID,[]).append(entry.th32ProcessID)
                if not kernel.Process32NextW(snapshot,ctypes.byref(entry)):break
    finally:kernel.CloseHandle(snapshot)
    order=[];seen=set()
    def visit(pid):
        if pid in seen:return
        seen.add(pid)
        for child_pid in children.get(pid,[]):visit(child_pid)
        order.append(pid)
    visit(int(root_pid))
    terminated=False
    for pid in order:
        handle=kernel.OpenProcess(0x0001,False,pid)
        if handle:
            try:terminated=bool(kernel.TerminateProcess(handle,1)) or terminated
            finally:kernel.CloseHandle(handle)
    return terminated


def sandbox_command(root, command, image, allow_network=False, extra_mounts=None):
    """Run one configured check in a networkless, read-only Docker container."""
    workspace_source = str(Path(root).resolve())
    if ',' in workspace_source:
        raise ValueError('Шлях проєкту з комою не підтримується Docker bind mount')
    root = Path(root).resolve()
    command_args = list(command)
    extra_mounts=list(extra_mounts or [])
    extra_targets={}
    mount_args=[]
    for item in extra_mounts:
        if not isinstance(item,dict) or set(item)-{'source','target','readonly'}:
            raise ValueError('Некоректне додаткове монтування перевірки')
        raw_source=Path(item.get('source',''))
        if raw_source.is_symlink():
            raise ValueError('Додатковий тест не може бути symlink')
        extra_source=raw_source.resolve()
        target=item.get('target','')
        if (not extra_source.is_file() or extra_source.is_symlink() or ',' in str(extra_source) or
                not isinstance(target,str) or not target.startswith('/verification/') or
                '..' in target.split('/') or ',' in target):
            raise ValueError('Додатковий тест має бути файлом у /verification без посилань і traversal')
        extra_targets[str(extra_source)]=target
        suffix=',readonly' if item.get('readonly',True) else ''
        mount_args.extend(['--mount',f'type=bind,source={extra_source},target={target}{suffix}'])
    executable = command_args[0]
    if executable == '{python}':
        command_args[0] = 'python'
    elif os.path.isabs(executable) or re.match(r'^[A-Za-z]:[\\/]', executable):
        command_args[0] = Path(executable).name
        if command_args[0].lower().endswith(('.exe', '.cmd', '.bat')):
            command_args[0] = command_args[0].rsplit('.', 1)[0]
    for index, value in enumerate(command_args[1:], 1):
        if os.path.isabs(value) or re.match(r'^[A-Za-z]:[\\/]', value):
            target = Path(value).resolve()
            if str(target) in extra_targets:
                command_args[index]=extra_targets[str(target)]
            elif not target.is_relative_to(root):
                raise ValueError('Docker-перевірка не має доступу до зовнішнього шляху: ' + value)
            else:
                command_args[index] = '/workspace/' + target.relative_to(root).as_posix()
    args=['docker', 'run', '--rm']
    if not allow_network:args.append('--network=none')
    return args+['--cap-drop=ALL',
            '--security-opt=no-new-privileges', '--pids-limit=256', '--memory=2g', '--cpus=2',
            '--env', 'CI=1', '--env', 'PYTHONDONTWRITEBYTECODE=1', '--env', 'NO_COLOR=1',
            '--read-only', '--tmpfs', '/tmp:rw,nosuid,nodev,size=512m',
            '--mount', f'type=bind,source={workspace_source},target=/workspace',
            *mount_args, '--workdir', '/workspace', image, *command_args]


def run_checks(root, commands, timeout, stop, log, sandbox=None):
    if not commands:
        return False, 'Немає команд перевірки. Додайте команду тестів/збірки в налаштуваннях проєкту.'
    reports = []
    for command in commands:
        if stop.is_set():
            raise Cancelled()
        args = [sys.executable if a == '{python}' else a for a in command]
        cidfile = None
        cid_dir = None
        docker = bool(sandbox and sandbox.get('backend') == 'docker')
        if docker:
            cid_dir = tempfile.mkdtemp(prefix='lowforge-container-')
            cidfile = str(Path(cid_dir) / 'container.id')
            try:
                args = sandbox_command(root, command, sandbox['image'],bool(sandbox.get('network',False)),
                                       sandbox.get('extra_mounts',[]))
            except ValueError as error:
                try: os.unlink(cidfile)
                except OSError: pass
                try: os.rmdir(cid_dir)
                except OSError: pass
                return False, str(error)
            network_index=args.index('--network=none') if '--network=none' in args else args.index('--cap-drop=ALL')
            args[args.index('--rm')+1:network_index] = ['--cidfile', cidfile]
        executable = shutil.which(args[0])
        if not executable:
            if cidfile and os.path.exists(cidfile): os.unlink(cidfile)
            if cid_dir:
                try: os.rmdir(cid_dir)
                except OSError: pass
            return False, 'Інструмент не знайдено: ' + args[0]
        args[0] = executable
        label = subprocess.list2cmdline(command)
        log('Перевірка: ' + label)
        started = time.monotonic()
        with tempfile.TemporaryFile() as output:
            # Docker uses /workspace in the container. Its host process does
            # not need the potentially long Windows path as its cwd.
            host_cwd = Path(executable).resolve().parent if docker else root
            for attempt in range(2):
                try:
                    process = subprocess.Popen(args, cwd=host_cwd, stdout=output, stderr=subprocess.STDOUT,
                        stdin=subprocess.DEVNULL, env={**os.environ, 'PYTHONUTF8': '1', 'PYTHONDONTWRITEBYTECODE': '1', 'CI': '1', 'NO_COLOR': '1'},
                        creationflags=subprocess.CREATE_NO_WINDOW if os.name == 'nt' else 0,
                        start_new_session=os.name != 'nt')
                    break
                except OSError as error:
                    failure = f'$ {label}\nCheck launch error: {type(error).__name__} (errno={error.errno}, winerror={getattr(error, "winerror", None)}): {error.strerror}'
                    log(failure)
                    if attempt == 0 and not stop.is_set():
                        log('Retrying check launch once before requesting model changes.')
                        continue
                    if cid_dir:
                        try: os.rmdir(cid_dir)
                        except OSError: pass
                    if stop.is_set():
                        raise Cancelled()
                    return False, failure
            timed_out = False
            try:
                while process.poll() is None:
                    if stop.wait(.1):
                        raise Cancelled()
                    if time.monotonic() - started > timeout:
                        timed_out = True
                        break
                    if output.tell() > 16 * 1024 * 1024:
                        timed_out = True
                        break
            finally:
                if process.poll() is None:
                    kill(process)
                if cidfile:
                    try:
                        container_id=Path(cidfile).read_text(encoding='ascii').strip()
                        if container_id:
                            subprocess.run([executable,'rm','-f',container_id],capture_output=True,timeout=10,
                                creationflags=subprocess.CREATE_NO_WINDOW if os.name=='nt' else 0)
                    except (OSError,subprocess.SubprocessError):
                        pass
                    try: os.unlink(cidfile)
                    except OSError: pass
                    try: os.rmdir(cid_dir)
                    except OSError: pass
            output.seek(0, 2)
            size = output.tell()
            if size > 24000 and process.returncode and not timed_out:
                output.seek(0)
                raw = output.read(16 * 1024 * 1024).decode('utf-8', errors='replace')
                text = failure_feedback(raw, 10000)
            elif size>24000:
                output.seek(0);head=output.read(12000)
                output.seek(size-12000);tail=output.read(12000)
                text=head.decode('utf-8',errors='replace')+'\n[Середину виводу скорочено]\n'+tail.decode('utf-8',errors='replace')
            else:
                output.seek(0);text=output.read().decode('utf-8',errors='replace')
        no_tests = bool(re.search(r'Ran 0 tests|no tests ran|No test is available|Total tests:\s*0|no test files|0 passing', text, re.I))
        # dotnet test may exit 0 without even discovering a test project.
        if 'dotnet' in Path(command[0]).stem.lower() and 'test' in command and not re.search(r'(?:Passed|Failed|Skipped|Total tests):\s*\d+|Test Run (?:Successful|Failed)', text, re.I):
            no_tests = True
        good = process.returncode == 0 and not timed_out and not no_tests
        report = f'$ {label}\nexit={process.returncode}; seconds={time.monotonic()-started:.1f}\n{text}'
        if timed_out:
            report += '\nПеревищено таймаут або ліміт виводу.'
        if no_tests:
            report += '\nНе знайдено жодного тесту; це не успішна перевірка.'
        reports.append(report)
        log(report[-4000:])
        if not good:
            return False, '\n\n'.join(reports)[-30000:]
    return True, '\n\n'.join(reports)[-30000:]
