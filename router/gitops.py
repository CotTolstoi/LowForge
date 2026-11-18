"""Explicit, narrow Git actions initiated by the dashboard user."""
from pathlib import Path
import re
import shutil
import subprocess

from .workspace import linked, safe


def _contains_linked_path(path):
    """Reject a link or junction anywhere in the path, including its parents."""
    current=Path(path)
    while True:
        if linked(current):
            return True
        if current.parent==current:
            return False
        current=current.parent


def _git(root, *args, env=None, timeout=30):
    try:
        result = subprocess.run(['git', '-C', str(root), *args], capture_output=True,
                                text=True, encoding='utf-8', errors='replace', timeout=timeout)
    except (OSError,subprocess.SubprocessError) as error:
        raise ValueError('Git не вдалося виконати: '+str(error)[:500]) from None
    if result.returncode:
        detail=(result.stderr or result.stdout).strip()[:2000]
        raise ValueError('Git: '+(detail or 'команда завершилася помилкою'))
    return result.stdout.strip()


def create_task_worktree(root, worktree, branch):
    """Create a branch worktree only from a clean repository root."""
    root,worktree=Path(root),Path(worktree)
    if _contains_linked_path(root) or _contains_linked_path(worktree):
        raise ValueError('Git worktree не можна створити через symlink або junction')
    root=root.resolve();worktree=worktree.resolve()
    if not re.fullmatch(r'lowforge/[a-f0-9]{12}',str(branch)):
        raise ValueError('Некоректна назва ізольованої Git-гілки')
    if not shutil.which('git'):
        raise ValueError('Git не встановлено')
    if not root.is_dir():
        raise ValueError('Корінь проєкту не існує')
    git_root=Path(_git(root,'rev-parse','--show-toplevel')).resolve()
    if git_root!=root:
        raise ValueError('Для worktree корінь проєкту має бути коренем Git-репозиторію')
    status=_git(root,'status','--porcelain','--untracked-files=all')
    if status:
        raise ValueError('Для Git worktree спочатку зафіксуйте або приберіть незакомічені зміни проєкту')
    if worktree.exists():
        raise ValueError('Каталог Git worktree вже існує')
    if subprocess.run(['git','-C',str(root),'show-ref','--verify','--quiet','refs/heads/'+branch],capture_output=True).returncode==0:
        raise ValueError('Git-гілка вже існує: '+branch)
    worktree.parent.mkdir(parents=True,exist_ok=True)
    _git(root,'worktree','add','-b',branch,str(worktree),'HEAD',timeout=60)
    if not worktree.is_dir() or Path(_git(worktree,'rev-parse','--show-toplevel')).resolve()!=worktree:
        raise ValueError('Git не створив очікуваний ізольований worktree')
    return {'root':str(worktree),'branch':branch}


def remove_task_worktree(root, worktree, branch):
    """Remove a clean task worktree while preserving its user-visible branch."""
    root,worktree=Path(root),Path(worktree)
    if _contains_linked_path(root) or _contains_linked_path(worktree):
        raise ValueError('Git worktree містить symlink або junction')
    root=root.resolve();worktree=worktree.resolve()
    if not re.fullmatch(r'lowforge/[a-f0-9]{12}',str(branch)):
        raise ValueError('Некоректна назва ізольованої Git-гілки')
    if not root.is_dir() or not worktree.is_dir():
        raise ValueError('Корінь репозиторію або Git worktree відсутній')
    root_common=Path(_git(root,'rev-parse','--git-common-dir'))
    worktree_common=Path(_git(worktree,'rev-parse','--git-common-dir'))
    if not root_common.is_absolute():root_common=root/root_common
    if not worktree_common.is_absolute():worktree_common=worktree/worktree_common
    if root_common.resolve()!=worktree_common.resolve():
        raise ValueError('Git worktree не належить вказаному кореню репозиторію')
    if Path(_git(worktree,'rev-parse','--show-toplevel')).resolve()!=worktree:
        raise ValueError('Шлях не є коренем очікуваного Git worktree')
    if _git(worktree,'symbolic-ref','--short','HEAD')!=branch:
        raise ValueError('Git worktree перемкнено на іншу гілку; очищення зупинено')
    _git(root,'worktree','remove',str(worktree),timeout=60)
    return {'branch':branch,'removed':True}


def create_user_commit(root, work, backup, paths, message):
    """Commit only reviewed run paths, preserving unrelated staged index entries."""
    if any(linked(Path(path)) for path in (root,work,backup)):
        raise ValueError('Посилання та junction у корені, робочій або резервній копії заборонені')
    root=Path(root).resolve();work=Path(work).resolve();backup=Path(backup).resolve()
    if not shutil.which('git'):
        raise ValueError('Git не встановлено')
    if not root.is_dir() or not work.is_dir() or not backup.is_dir():
        raise ValueError('Робоча копія або резервна копія запуску відсутня')
    if not isinstance(message,str) or not message.strip() or len(message)>200:
        raise ValueError('Вкажіть повідомлення коміту до 200 символів')
    if not isinstance(paths,list) or not paths or len(paths)>200:
        raise ValueError('Для коміту потрібен список змінених файлів')
    selected=sorted(set(paths))
    if len(selected)!=len(paths):
        raise ValueError('Список файлів містить дублікати')
    for name in selected:
        source=safe(root,name);candidate=safe(work,name);original=safe(backup,name)
        if source.exists()!=candidate.exists() or (source.exists() and source.read_bytes()!=candidate.read_bytes()):
            raise ValueError('Файл у проєкті змінився після запуску або відрізняється від перевіреної копії: '+name)
        if original.exists() and source.exists() and original.read_bytes()==source.read_bytes():
            raise ValueError('Файл не має змін для коміту: '+name)

    git_root=Path(_git(root,'rev-parse','--show-toplevel')).resolve()
    if git_root!=root:
        raise ValueError('Для безпечного коміту корінь проєкту має бути коренем Git-репозиторію')
    # Reject paths that were already different from HEAD at run start. This prevents
    # bundling pre-existing user edits into the model's reviewed change.
    for name in selected:
        original=safe(backup,name)
        tracked=subprocess.run(['git','-C',str(root),'cat-file','-e',f'HEAD:{name}'],capture_output=True)
        if original.exists():
            blob=subprocess.run(['git','-C',str(root),'hash-object','--path',name,'--stdin'],input=original.read_bytes(),capture_output=True)
            head_blob=subprocess.run(['git','-C',str(root),'rev-parse',f'HEAD:{name}'],capture_output=True,text=True)
            if tracked.returncode or head_blob.returncode or blob.stdout.strip().decode()!=head_blob.stdout.strip():
                raise ValueError('Файл уже мав зміни до запуску; коміт зупинено, щоб не захопити сторонні правки: '+name)
        elif tracked.returncode==0:
            raise ValueError('Файл було видалено до запуску; коміт зупинено: '+name)

    untracked=[]
    for name in selected:
        result=subprocess.run(['git','-C',str(root),'ls-files','--error-unmatch','--',name],capture_output=True)
        if result.returncode and safe(root,name).exists():untracked.append(name)
    added_intent=[]
    try:
        for name in untracked:
            _git(root,'add','-N','--',name);added_intent.append(name)
        _git(root,'commit','--only','-m',message.strip(),'--',*selected,timeout=60)
    except Exception:
        # Remove only intent-to-add entries created above; existing staged work is untouched.
        for name in added_intent:
            subprocess.run(['git','-C',str(root),'reset','-q','--',name],capture_output=True)
        raise
    return {'commit':_git(root,'rev-parse','HEAD'),'paths':selected,'message':message.strip()}
