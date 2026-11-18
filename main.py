"""LowForge entry point. Python 3.10+, standard library only."""
import argparse
import os
from pathlib import Path
import sys
import threading
import webbrowser

from router.engine import Engine
from router import VERSION
from router.server import Server
from router.store import Store


class InstanceLock:
    def __init__(self, folder):
        Path(folder).mkdir(parents=True, exist_ok=True)
        self.file = None
        try:
            self.file = open(Path(folder) / 'instance.lock', 'a+b')
            self.file.seek(0)
            if not self.file.read(1):
                self.file.write(b'0')
                self.file.flush()
            self.file.seek(0)
            if os.name == 'nt':
                import msvcrt
                msvcrt.locking(self.file.fileno(), msvcrt.LK_NBLCK, 1)
            else:
                import fcntl
                fcntl.flock(self.file.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError:
            if self.file:
                self.file.close()
            raise RuntimeError('Ця папка даних уже використовується іншим LowForge') from None

    def close(self):
        self.file.close()


def main():
    parser = argparse.ArgumentParser(description='LowForge '+VERSION+' — локальний AI router')
    parser.add_argument('--data-dir', type=Path, default=Path(__file__).resolve().parent / '.router-data')
    parser.add_argument('--port', type=int, default=8876)
    parser.add_argument('--no-browser', action='store_true')
    args = parser.parse_args()
    lock = store = engine = server = None
    try:
        if sys.version_info < (3, 10):
            raise RuntimeError('Потрібен Python 3.10 або новіший')
        lock = InstanceLock(args.data_dir)
        store = Store(args.data_dir)
        engine = Engine(store)
        server = Server(('127.0.0.1', args.port), engine)
        print(f'LowForge {VERSION}\nПанель: {server.url}\nТокен: {server.token}\nДані: {store.folder}\nCtrl+C — завершити.', flush=True)
        if not args.no_browser:
            # Fragment is removed by the frontend and never reaches the HTTP server.
            webbrowser.open(server.url + '/#token=' + server.token)
        server.serve_forever(poll_interval=.2)
        return 0
    except KeyboardInterrupt:
        return 0
    except (OSError, RuntimeError, ValueError) as error:
        print('LowForge: ' + str(error), file=sys.stderr)
        return 1
    finally:
        if engine:
            engine.close()
        if server:
            server.server_close()
        if store:
            store.close()
        if lock:
            lock.close()


if __name__ == '__main__':
    raise SystemExit(main())
