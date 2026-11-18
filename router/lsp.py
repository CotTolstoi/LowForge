"""Small bounded stdio LSP client for explicitly configured local language servers."""
import json
import os
import queue
import subprocess
import threading
import time
from pathlib import Path

from .checks import kill

MAX_MESSAGE=4*1024*1024


class Client:
    def __init__(self, command, root, timeout=15):
        if not isinstance(command,list) or not command or len(command)>80 or any(not isinstance(v,str) or not v for v in command):
            raise ValueError('Некоректна команда LSP-сервера')
        self.command=list(command);self.root=Path(root).resolve();self.timeout=max(2,min(float(timeout),60))
        self.process=None;self.incoming=queue.Queue();self.next_id=0;self.diagnostics={}

    def __enter__(self):
        try:
            self.process=subprocess.Popen(self.command,cwd=self.root,stdin=subprocess.PIPE,stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,env={**os.environ,'PYTHONUTF8':'1','CI':'1'},
                creationflags=subprocess.CREATE_NO_WINDOW if os.name=='nt' else 0,
                start_new_session=os.name!='nt')
        except OSError as error:
            raise ValueError('Не вдалося запустити LSP-сервер: '+str(error)[:400]) from error
        threading.Thread(target=self._reader,daemon=True).start()
        try:
            root_uri=self.root.as_uri()
            self._request('initialize',{'processId':os.getpid(),'rootUri':root_uri,'rootPath':str(self.root),
                'capabilities':{'textDocument':{'documentSymbol':{'hierarchicalDocumentSymbolSupport':True},
                    'definition':{'dynamicRegistration':False},'references':{'dynamicRegistration':False},
                    'publishDiagnostics':{'relatedInformation':False}},'workspace':{'symbol':{'dynamicRegistration':False}}},
                'clientInfo':{'name':'LowForge','version':'1.2'}})
            self._notify('initialized',{})
        except Exception:
            self.__exit__(None,None,None)
            raise
        return self

    def __exit__(self,exc_type,exc,tb):
        if self.process is None:return
        try:
            if self.process.poll() is None:
                try:
                    self._request('shutdown',{},timeout=min(2,self.timeout))
                    self._notify('exit',{})
                    self.process.wait(timeout=1)
                except (ValueError,TimeoutError,OSError,subprocess.SubprocessError):
                    kill(self.process)
        finally:
            for stream in (self.process.stdin,self.process.stdout):
                try: stream.close()
                except OSError: pass

    def _reader(self):
        try:
            while True:
                headers={}
                while True:
                    line=self.process.stdout.readline(8192)
                    if not line:raise EOFError('LSP-сервер закрив stdout')
                    if line in (b'\r\n',b'\n'):break
                    key,sep,value=line.partition(b':')
                    if not sep:raise ValueError('Некоректний заголовок LSP')
                    headers[key.strip().lower()]=value.strip()
                length=int(headers.get(b'content-length',b'-1'))
                if not 0<=length<=MAX_MESSAGE:raise ValueError('Некоректний або завеликий пакет LSP')
                raw=self.process.stdout.read(length)
                if len(raw)!=length:raise EOFError('Обрізаний пакет LSP')
                self.incoming.put(json.loads(raw.decode('utf-8')))
        except Exception as error:
            self.incoming.put({'_reader_error':str(error)[:500]})

    def _send(self,message):
        raw=json.dumps(message,ensure_ascii=False,separators=(',',':')).encode('utf-8')
        if len(raw)>MAX_MESSAGE:raise ValueError('Запит LSP перевищує ліміт розміру')
        self.process.stdin.write(f'Content-Length: {len(raw)}\r\n\r\n'.encode('ascii')+raw)
        self.process.stdin.flush()

    def _notify(self,method,params):
        self._send({'jsonrpc':'2.0','method':method,'params':params})

    def _server_request(self,message):
        """Answer server-initiated requests without granting editing capabilities."""
        method=message.get('method');params=message.get('params') or {}
        response={'jsonrpc':'2.0','id':message['id']}
        if method=='workspace/configuration':
            items=params.get('items',[]) if isinstance(params,dict) else []
            if not isinstance(items,list) or len(items)>100:
                response['error']={'code':-32602,'message':'Invalid configuration items'}
            else:response['result']=[None for _ in items]
        elif method=='workspace/workspaceFolders':
            response['result']=[{'uri':self.root.as_uri(),'name':self.root.name}]
        elif method=='workspace/applyEdit':
            response['result']={'applied':False,'failureReason':'LowForge LSP is read-only'}
        elif method in ('client/registerCapability','client/unregisterCapability','window/workDoneProgress/create'):
            response['result']=None
        else:
            response['error']={'code':-32601,'message':'Unsupported client method'}
        self._send(response)

    def _request(self,method,params,timeout=None):
        self.next_id+=1;request_id=self.next_id
        self._send({'jsonrpc':'2.0','id':request_id,'method':method,'params':params})
        deadline=time.monotonic()+(self.timeout if timeout is None else timeout)
        while True:
            remaining=deadline-time.monotonic()
            if remaining<=0:raise TimeoutError(f'LSP timeout: {method}')
            try:message=self.incoming.get(timeout=min(.2,remaining))
            except queue.Empty:
                if self.process.poll() is not None:raise ValueError('LSP-сервер завершився під час '+method)
                continue
            if '_reader_error' in message:raise ValueError(message['_reader_error'])
            if isinstance(message.get('method'),str) and 'id' in message:
                self._server_request(message)
                continue
            if message.get('method')=='textDocument/publishDiagnostics':
                params=message.get('params',{})
                if isinstance(params,dict):self.diagnostics[params.get('uri','')]=params.get('diagnostics',[])
            if message.get('id')!=request_id:continue
            if 'error' in message:raise ValueError('LSP '+method+': '+str(message['error'])[:500])
            return message.get('result')

    @staticmethod
    def uri(path):
        return Path(path).resolve().as_uri()

    def open_document(self,path,language,text):
        uri=self.uri(path)
        self._notify('textDocument/didOpen',{'textDocument':{'uri':uri,'languageId':language,
            'version':1,'text':text}})
        return uri

    def document_symbols(self,path,language,text):
        uri=self.open_document(path,language,text)
        result=self._request('textDocument/documentSymbol',{'textDocument':{'uri':uri}})
        return {'symbols':result,'diagnostics':self.diagnostics.get(uri,[])}

    def workspace_symbols(self,path,language,text,query):
        uri=self.open_document(path,language,text)
        result=self._request('workspace/symbol',{'query':query})
        return {'symbols':result,'diagnostics':self.diagnostics.get(uri,[])}

    def position_request(self,method,path,language,text,line,character):
        uri=self.open_document(path,language,text)
        params={'textDocument':{'uri':uri},'position':{'line':line-1,'character':character}}
        if method=='textDocument/references':params['context']={'includeDeclaration':True}
        result=self._request(method,params)
        return {'locations':result,'diagnostics':self.diagnostics.get(uri,[])}


def query(command,root,path,operation,language,**options):
    root=Path(root).resolve();path=Path(path)
    if not path.is_absolute():path=root/path
    path=path.resolve()
    if not path.is_relative_to(root) or not path.is_file():
        raise ValueError('LSP-файл має бути наявним у робочій копії')
    if path.stat().st_size>512*1024:raise ValueError('LSP не запускається для файлів понад 512 KiB')
    text=path.read_text(encoding='utf-8-sig')
    suffix=path.suffix.lower()
    if language=='typescript':
        language_id={'.js':'javascript','.jsx':'javascriptreact','.tsx':'typescriptreact'}.get(suffix,'typescript')
    else:
        language_id='python'
    with Client(command,root) as client:
        if operation=='document_symbols':
            result=client.document_symbols(path,language_id,text)
        elif operation=='workspace_symbols':
            result=client.workspace_symbols(path,language_id,text,str(options.get('query',''))[:200])
        elif operation in ('definition','references'):
            line=options.get('line');character=options.get('character',0)
            if type(line) is not int or type(character) is not int or line<1 or character<0:
                raise ValueError('Для LSP definition/references вкажіть line >= 1 і character >= 0')
            method='textDocument/definition' if operation=='definition' else 'textDocument/references'
            result=client.position_request(method,path,language_id,text,line,character)
        else:
            raise ValueError('Невідома LSP-операція')
    output=json.dumps(result,ensure_ascii=False)
    return output[:12000]+('\n[результат LSP обрізано]' if len(output)>12000 else '')
