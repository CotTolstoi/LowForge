"""Persist a provider's known availability pause across independent batch cells.

No credentials or error bodies are stored. A successful later request is proof
that an earlier quota response no longer needs to pause the next cell.
"""
import hashlib
import json
import math
from pathlib import Path
import time

from .providers import Cancelled


class ProviderPause:
    def __init__(self, path, endpoint, model):
        self.path=Path(path)
        self.scope=hashlib.sha256((endpoint+'\n'+model).encode()).hexdigest()

    def deadline(self):
        if not self.path.exists():return 0.0
        value=json.loads(self.path.read_text(encoding='utf8'))
        if value.get('scope')!=self.scope:
            raise ValueError('Provider pause scope mismatch; refusing dispatch')
        deadline=value.get('not_before_epoch')
        if (isinstance(deadline,bool) or not isinstance(deadline,(int,float)) or
                not math.isfinite(deadline) or deadline<0):
            raise ValueError('Invalid provider pause deadline; refusing dispatch')
        return deadline

    def observe(self, requests):
        deadline=self.deadline()
        pending=0.0
        for row in requests:
            if row.get('status') in ('ok','recovered'):
                pending=0.0
            elif row.get('error_kind')=='rate_limit':
                seconds=row.get('retry_after_seconds',0)
                if (isinstance(seconds,(int,float)) and not isinstance(seconds,bool) and
                        math.isfinite(seconds) and seconds>0):
                    pending=max(pending,min(86400,seconds))
        # Measured from cell completion, intentionally conservative: metric rows
        # do not carry a trustworthy wall-clock timestamp for the quota response.
        deadline=max(deadline,time.time()+pending) if pending else deadline
        self.path.parent.mkdir(parents=True,exist_ok=True)
        temporary=self.path.with_suffix(self.path.suffix+'.tmp')
        temporary.write_text(json.dumps({'scope':self.scope,'not_before_epoch':deadline})+'\n',encoding='utf8')
        temporary.replace(self.path)
        return deadline

    def wait(self, stop, log):
        while True:
            if stop.is_set():raise Cancelled()
            remaining=self.deadline()-time.time()
            if remaining<=0:return
            log({'event':'provider_pause','remaining_seconds':round(remaining,3)})
            if stop.wait(min(60,remaining)):raise Cancelled()
