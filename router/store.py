"""Durable records; no mutable global application bindings."""
import json
import os
import sqlite3
import threading
import time
import uuid
from pathlib import Path

from .redaction import redact


class Store:
    SCHEMA_VERSION = 2

    def __init__(self, folder):
        self.folder = Path(folder).resolve()
        self.folder.mkdir(parents=True, exist_ok=True)
        self.lock = threading.RLock()
        self.db = sqlite3.connect(self.folder / 'router.sqlite3', check_same_thread=False, timeout=15)
        self.db.execute('PRAGMA journal_mode=WAL')
        self.db.execute('PRAGMA synchronous=FULL')
        version = self.db.execute('PRAGMA user_version').fetchone()[0]
        if version > self.SCHEMA_VERSION:
            self.db.close()
            raise ValueError(f'База LowForge має новішу схему ({version}); ця версія підтримує {self.SCHEMA_VERSION}.')
        self.db.executescript('''
            CREATE TABLE IF NOT EXISTS records(kind TEXT, id TEXT, data TEXT, PRIMARY KEY(kind,id));
            CREATE TABLE IF NOT EXISTS events(seq INTEGER PRIMARY KEY, run TEXT, at REAL, text TEXT);
        ''')
        if version < 1:
            self.db.execute('PRAGMA user_version=1')
            version=1
        if version < 2:
            self.db.execute('''CREATE TABLE IF NOT EXISTS quarantine(
                kind TEXT, id TEXT, data TEXT, error TEXT, quarantined_at REAL,
                PRIMARY KEY(kind,id))''')
            self.db.execute('PRAGMA user_version=2')
        self.db.commit()
        try:
            health=self.db.execute('PRAGMA quick_check').fetchone()
        except sqlite3.DatabaseError as error:
            self.db.close()
            raise ValueError('База LowForge не пройшла швидку перевірку цілісності SQLite') from error
        if not health or health[0]!='ok':
            self.db.close()
            raise ValueError('База LowForge не пройшла швидку перевірку цілісності SQLite')
        self.integrity='ok'

    def put(self, kind, record):
        data = json.dumps(record, ensure_ascii=False, allow_nan=False)
        if len(data.encode('utf-8'))>16*1024*1024:
            raise ValueError('Запис LowForge перевищує ліміт 16 MiB')
        with self.lock, self.db:
            self.db.execute('INSERT OR REPLACE INTO records VALUES(?,?,?)', (kind, record['id'], data))
        return record

    def get(self, kind, ident):
        with self.lock:
            row = self.db.execute('SELECT data FROM records WHERE kind=? AND id=?', (kind, ident)).fetchone()
            if row is None:
                raise ValueError('Запис не знайдено: ' + kind)
            try:return json.loads(row[0])
            except (json.JSONDecodeError,TypeError) as error:
                self._quarantine(kind,ident,row[0],error)
                self.db.commit()
                raise ValueError(f'Пошкоджений запис {kind}; сирі дані перенесено до карантину') from error

    def _quarantine(self,kind,ident,data,error):
        self.db.execute('INSERT OR REPLACE INTO quarantine VALUES(?,?,?,?,?)',
            (kind,ident,str(data),str(error)[:400],time.time()))
        self.db.execute('DELETE FROM records WHERE kind=? AND id=?',(kind,ident))

    def all(self, kind):
        with self.lock:
            rows = self.db.execute('SELECT id,data FROM records WHERE kind=? ORDER BY rowid DESC', (kind,)).fetchall()
            result=[]
            for ident,data in rows:
                try:result.append(json.loads(data))
                except (json.JSONDecodeError,TypeError) as error:
                    with self.db:self._quarantine(kind,ident,data,error)
        return result

    def delete(self, kind, ident):
        with self.lock, self.db:
            self.db.execute('DELETE FROM records WHERE kind=? AND id=?', (kind, ident))

    def delete_run(self, run_id):
        with self.lock, self.db:
            self.db.execute('DELETE FROM records WHERE kind=? AND id=?', ('run', run_id))
            self.db.execute('DELETE FROM events WHERE run=?', (run_id,))

    def log(self, run, text):
        with self.lock, self.db:
            self.db.execute('INSERT INTO events(run,at,text) VALUES(?,?,?)', (run, time.time(), redact(text)[:16000]))

    def events(self, run):
        with self.lock:
            rows = self.db.execute('SELECT seq,at,text FROM events WHERE run=? ORDER BY seq DESC LIMIT 200', (run,)).fetchall()
        return [dict(zip(('seq', 'at', 'text'), row)) for row in reversed(rows)]

    def recover(self):
        for run in self.all('run'):
            if run['status'] in ('queued', 'running', 'stopping', 'awaiting_approval', 'publishing'):
                run.update(status='interrupted', error='Програму перезапущено. Робочу копію збережено; запустіть задачу знову.')
                self.put('run', run)

    def backup(self):
        """Create an integrity-checked SQLite snapshot without copying an open WAL file."""
        folder=self.folder/'backups'
        folder.mkdir(parents=True,exist_ok=True)
        suffix=uuid.uuid4().hex[:8]
        target=folder/f'lowforge-{time.strftime("%Y%m%d-%H%M%S")}-{suffix}.sqlite3'
        temporary=folder/('.'+target.name+'.tmp')
        try:
            with self.lock:
                snapshot=sqlite3.connect(temporary,timeout=15)
                try:
                    self.db.backup(snapshot)
                    check=snapshot.execute('PRAGMA integrity_check').fetchone()
                    if not check or check[0]!='ok':
                        raise ValueError('Резервна копія SQLite не пройшла integrity_check')
                finally:
                    snapshot.close()
            os.replace(temporary,target)
            return {'path':str(target),'bytes':target.stat().st_size,'integrity':'ok'}
        finally:
            if temporary.exists():
                temporary.unlink()

    def close(self):
        with self.lock:
            self.db.close()


def ident():
    return uuid.uuid4().hex
