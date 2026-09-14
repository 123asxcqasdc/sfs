#!/usr/bin/env python3
"""Запуск веб-GUI SFS на локальном HTTP-сервере (кроссплатформенный: Windows/Linux/macOS).

Использование:
    python serve.py            # сервер на http://127.0.0.1:8123 + открыть ui.html
    python serve.py 8080       # другой порт
    python serve.py --host 0.0.0.0   # доступно и по сети (осторожно: отдаёт всю папку)
    python serve.py stop       # остановить запущенный этим скриптом сервер

Всё нужное (ed25519.js, parser.js, vendor/*, zip-dec.js) отдаётся рядом с ui.html.
Требуется только Python 3 (http.server из стандартной библиотеки).
"""
import argparse
import os
import pathlib
import sys
import tempfile
import webbrowser
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer

ROOT = pathlib.Path(__file__).resolve().parent


def pid_file(port: int) -> pathlib.Path:
    return pathlib.Path(tempfile.gettempdir()) / f"sfs-server-{port}.pid"


def read_pid(port: int):
    try:
        return int(pid_file(port).read_text().strip())
    except (OSError, ValueError):
        return None


def is_alive(pid) -> bool:
    if pid is None:
        return False
    try:
        os.kill(pid, 0)
        return True
    except OSError:
        return False


def stop(port: int):
    pid = read_pid(port)
    if pid is None or not is_alive(pid):
        print(f"сервер на :{port} не запущен (нет pid-файла или процесс умер)")
        pid_file(port).unlink(missing_ok=True)
        return
    if sys.platform == "win32":
        os.kill(pid, 9)
    else:
        os.kill(pid, 0x0F)  # SIGTERM
    print(f"сервер остановлен (pid {pid})")
    pid_file(port).unlink(missing_ok=True)


def urls_ok(port: int) -> bool:
    import urllib.request
    try:
        with urllib.request.urlopen(f"http://127.0.0.1:{port}/ui.html", timeout=1) as r:
            return r.status == 200
    except Exception:
        return False


def main():
    ap = argparse.ArgumentParser(description="SFS Studio local server")
    ap.add_argument("port", nargs="?", default=8123, type=int)
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--no-open", action="store_true", help="не открывать браузер")
    ap.add_argument("--stop", action="store_true", help="остановить запущенный сервер")
    args = ap.parse_args()

    if args.stop:
        stop(args.port)
        sys.exit(0)

    url = f"http://127.0.0.1:{args.port}/ui.html"

    if urls_ok(args.port):
        print(f"http://127.0.0.1:{args.port} уже обслуживается — открываю {url}")
        if not args.no_open:
            webbrowser.open(url)
        sys.exit(0)

    class Handler(SimpleHTTPRequestHandler):
        def __init__(self, *a, **kw):
            super().__init__(*a, directory=str(ROOT), **kw)

        def log_message(self, fmt, *m):
            pass

    server = ThreadingHTTPServer((args.host, args.port), Handler)
    pid_file(args.port).write_text(str(os.getpid()))
    print(f"сервер запущен: http://127.0.0.1:{args.port}  (pid {os.getpid()})")
    print("остановить: python serve.py stop")
    if not args.no_open:
        webbrowser.open(url)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nостанавливаю…")
        server.shutdown()
        pid_file(args.port).unlink(missing_ok=True)


if __name__ == "__main__":
    main()