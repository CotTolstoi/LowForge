"""Bounded stdio MCP client for explicitly configured, allow-listed tools."""
import json
import os
import queue
import subprocess
import threading
import time

from .checks import kill

MAX_MESSAGE=2*1024*1024
MODERN_VERSION='2026-07-28'
LEGACY_VERSION='2025-11-25'


class Client:
    def __init__(self,config,root,timeout=12):
        self.config=config;self.root=str(root);self.timeout=max(2,min(float(timeout),45))
        self.process=None;self.incoming=queue.Queue();self.next_id=0;self.mode=''
        self.client_info={'name':'LowForge','version':'1.2.0'}

    def __enter__(self):
        env={key:value for key,value in os.environ.items() if key in self.config.get('env_vars',[])}
        for key in ('PATH','SYSTEMROOT','WINDIR','TEMP','TMP','USERPROFILE','APPDATA','LOCALAPPDATA'):
            if key in os.environ:env[key]=os.environ[key]
        env['PYTHONUTF8']='1';env['CI']='1'
        flags=subprocess.CREATE_NO_WINDOW if os.name=='nt' else 0
        try:
            self.process=subprocess.Popen([self.config['command'],*self.config['args']],cwd=self.root,
                stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,env=env,
                creationflags=flags,start_new_session=os.name!='nt')
        except OSError as error:
            raise ValueError('Не вдалося запустити MCP-сервер: '+str(error)[:400]) from error
        threading.Thread(target=self._reader,daemon=True).start()
        try:
            params={'_meta':{'io.modelcontextprotocol/protocolVersion':MODERN_VERSION,
                'io.modelcontextprotocol/clientInfo':self.client_info,
                'io.modelcontextprotocol/clientCapabilities':{}}}
            try:
                discovered=self._request('server/discover',params,timeout=min(3,self.timeout),modern=True)
                supported=discovered.get('supportedVersions',[]) if isinstance(discovered,dict) else []
                if MODERN_VERSION not in supported:
                    raise ValueError('MCP-сервер не підтримує '+MODERN_VERSION)
                self.mode='modern'
            except TimeoutError:
                self._fallback_legacy()
            except ValueError as error:
                if 'error code -32022' in str(error):
                    self._fallback_legacy()
                elif 'error code -32601' in str(error) or 'error code -32602' in str(error):
                    self._fallback_legacy()
                else:raise
            if self.mode=='legacy':
                self._notify('notifications/initialized',{})
            return self
        except Exception:
            self.__exit__(None,None,None)
            raise

    def _fallback_legacy(self):
        self.mode='legacy'
        result=self._request('initialize',{'protocolVersion':LEGACY_VERSION,'capabilities':{},
            'clientInfo':self.client_info},timeout=self.timeout,modern=False)
        if not isinstance(result,dict):raise ValueError('MCP initialize повернув некоректний результат')

    def __exit__(self,*_):
        if self.process is None:return
        try:
            if self.process.poll() is None:
                try:
                    self.process.stdin.close()
                    self.process.wait(timeout=1.5)
                except (OSError,subprocess.SubprocessError):
                    kill(self.process)
        finally:
            for stream in (self.process.stdin,self.process.stdout):
                try:
                    if not stream.closed:stream.close()
                except OSError:pass

    def _reader(self):
        try:
            while True:
                line=self.process.stdout.readline(MAX_MESSAGE+1)
                if not line:raise EOFError('MCP-сервер закрив stdout')
                if len(line)>MAX_MESSAGE or not line.endswith(b'\n'):
                    raise ValueError('MCP-повідомлення завелике або не має нового рядка')
                self.incoming.put(json.loads(line.decode('utf-8')))
        except Exception as error:
            self.incoming.put({'_reader_error':str(error)[:400]})

    def _send(self,message):
        raw=json.dumps(message,ensure_ascii=False,separators=(',',':')).encode('utf-8')
        if len(raw)>MAX_MESSAGE:raise ValueError('MCP-запит перевищує ліміт розміру')
        self.process.stdin.write(raw+b'\n');self.process.stdin.flush()

    def _notify(self,method,params):
        self._send({'jsonrpc':'2.0','method':method,'params':params})

    def _request(self,method,params,timeout=None,modern=None):
        self.next_id+=1;request_id=self.next_id
        modern=(self.mode=='modern') if modern is None else modern
        if modern and method!='server/discover':
            params=dict(params)
            params['_meta']={'io.modelcontextprotocol/protocolVersion':MODERN_VERSION,
                'io.modelcontextprotocol/clientInfo':self.client_info,
                'io.modelcontextprotocol/clientCapabilities':{}}
        self._send({'jsonrpc':'2.0','id':request_id,'method':method,'params':params})
        deadline=time.monotonic()+(self.timeout if timeout is None else timeout)
        while True:
            remaining=deadline-time.monotonic()
            if remaining<=0:raise TimeoutError(f'MCP timeout: {method}')
            try:message=self.incoming.get(timeout=min(.2,remaining))
            except queue.Empty:
                if self.process.poll() is not None:raise ValueError(f'MCP-сервер завершився під час {method}')
                continue
            if '_reader_error' in message:raise ValueError(message['_reader_error'])
            if message.get('id')!=request_id:continue
            if message.get('jsonrpc')!='2.0':raise ValueError('MCP-повідомлення має невірну версію JSON-RPC')
            if 'error' in message:
                error=message['error']
                raise ValueError(f'MCP {method} error code {error.get("code")}: {str(error.get("message",""))[:300]}')
            return message.get('result')

    def list_tools(self):
        all_tools=[];cursor=None
        for _ in range(20):
            params={}
            if cursor:params['cursor']=cursor
            result=self._request('tools/list',params)
            if not isinstance(result,dict) or not isinstance(result.get('tools'),list):
                raise ValueError('MCP tools/list повернув некоректний список')
            all_tools.extend(tool for tool in result['tools'] if isinstance(tool,dict))
            if len(all_tools)>500:raise ValueError('MCP-сервер повернув понад 500 інструментів')
            cursor=result.get('nextCursor')
            if not cursor:break
        return all_tools

    def call_tool(self,name,arguments):
        result=self._request('tools/call',{'name':name,'arguments':arguments})
        if not isinstance(result,dict):raise ValueError('MCP tools/call повернув некоректний результат')
        return result


def visible_tools(tools,allowlist,max_chars=12000):
    allowed=set(allowlist)
    visible=[];seen=set()
    for tool in tools:
        name=tool.get('name')
        if not isinstance(name,str) or name not in allowed or name in seen:continue
        schema=tool.get('inputSchema',{'type':'object','properties':{}})
        if not isinstance(schema,dict) or len(json.dumps(schema,ensure_ascii=False))>2000:
            continue
        visible.append({'name':name,'description':str(tool.get('description',''))[:500],
                        'inputSchema':schema})
        seen.add(name)
        if len(visible)>=50 or len(json.dumps(visible,ensure_ascii=False))>=max_chars:break
    return visible


def catalog(servers,root,max_chars=12000):
    result=[]
    max_chars=max(500,min(int(max_chars),50000))
    used=0
    for index,server in enumerate(servers):
        row={'server':server['name'],'tools':[]}
        if used>=max_chars:
            result.extend({'server':item['name'],'status':'omitted','tools':[]} for item in servers[index:])
            break
        if not server.get('enabled',True):
            row['status']='disabled';result.append(row);continue
        try:
            with Client(server,root) as client:
                tools=visible_tools(client.list_tools(),server['allowed_tools'],max(500,max_chars-used))
            row.update(status='ready',tools=tools)
        except (OSError,ValueError,TimeoutError,subprocess.SubprocessError) as error:
            row.update(status='error',error=str(error)[:400])
        row_text=json.dumps(row,ensure_ascii=False)
        if used+len(row_text)>max_chars:
            row={'server':server['name'],'status':'omitted','tools':[]}
            row_text=json.dumps(row,ensure_ascii=False)
        result.append(row);used+=len(row_text)
    return result


def validate_arguments(schema,value,depth=0):
    if depth>16:raise ValueError('MCP JSON Schema занадто глибока')
    if not isinstance(schema,dict):raise ValueError('MCP inputSchema має бути об’єктом')
    expected=schema.get('type')
    valid={'object':lambda v:isinstance(v,dict),'array':lambda v:isinstance(v,list),
           'string':lambda v:isinstance(v,str),'integer':lambda v:type(v) is int,
           'number':lambda v:type(v) in (int,float),'boolean':lambda v:type(v) is bool,
           'null':lambda v:v is None}
    if expected in valid and not valid[expected](value):
        raise ValueError(f'MCP arguments очікують тип {expected}')
    if 'enum' in schema and value not in schema['enum']:raise ValueError('MCP arguments не відповідають enum')
    if isinstance(value,dict):
        required=schema.get('required',[])
        if not isinstance(required,list) or any(key not in value for key in required):
            raise ValueError('MCP arguments не містять обов’язкові поля')
        properties=schema.get('properties',{})
        if isinstance(properties,dict):
            for key,item in value.items():
                if key in properties:validate_arguments(properties[key],item,depth+1)
                elif schema.get('additionalProperties') is False:
                    raise ValueError(f'MCP arguments містять невідоме поле: {key}')
    if isinstance(value,list):
        if len(value)<schema.get('minItems',0) or len(value)>schema.get('maxItems',1000):
            raise ValueError('MCP array виходить за допустимі межі')
        if isinstance(schema.get('items'),dict):
            for item in value:validate_arguments(schema['items'],item,depth+1)
    if isinstance(value,str) and (len(value)<schema.get('minLength',0) or len(value)>schema.get('maxLength',50000)):
        raise ValueError('MCP string виходить за допустимі межі')
    if type(value) in (int,float):
        if value<schema.get('minimum',float('-inf')) or value>schema.get('maximum',float('inf')):
            raise ValueError('MCP number виходить за допустимі межі')


def call(servers,root,server_name,tool_name,arguments):
    server=next((item for item in servers if item.get('name')==server_name and item.get('enabled',True)),None)
    if not server:raise ValueError('MCP-сервер не дозволено в налаштуваннях проєкту')
    if tool_name not in server.get('allowed_tools',[]):
        raise ValueError('MCP-інструмент не дозволено в allow-list цього сервера')
    try:argument_size=len(json.dumps(arguments,ensure_ascii=False,allow_nan=False))
    except (TypeError,ValueError):argument_size=50001
    if not isinstance(arguments,dict) or argument_size>50000:
        raise ValueError('MCP arguments має бути об’єктом до 50 KiB')
    with Client(server,root) as client:
        actual=[tool for tool in client.list_tools() if tool.get('name')==tool_name]
        tools=visible_tools(actual,server['allowed_tools'])
        if not tools:
            raise ValueError('MCP-сервер не надав дозволений інструмент')
        validate_arguments(tools[0]['inputSchema'],arguments)
        result=client.call_tool(tool_name,arguments)
    rendered=json.dumps(result,ensure_ascii=False)
    return rendered[:16000]+('\n[результат MCP скорочено]' if len(rendered)>16000 else '')
