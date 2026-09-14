#!/usr/bin/env bash
# Конвертер SFS (ZIP -> SFS) на локальном HTTP-сервере, со всеми библиотеками
# (ed25519.js, parser.js, vendor/*, zip-dec.js) рядом с ui.html.
#
# Использование:
#   ./serve.sh            # сервер на http://127.0.0.1:8123 и открыть ui.html
#   ./serve.sh 8080       # другой порт
#   SFS_HOST=0.0.0.0 ./serve.sh   # доступно и по сети (аккуратно: это отдаёт всю папку)
#   ./serve.sh stop       # остановить запущенный скриптом сервер
#
# Требуется только Python 3 (http.server из стандартной библиотеки).
set -euo pipefail

cd "$(dirname "$(readlink -f "$0")")"

HOST="${SFS_HOST:-127.0.0.1}"

do_stop() {
  local pid_file="${TMPDIR:-/tmp}/sfs-server.pid"
  if [ -f "$pid_file" ]; then
    local pid
    pid="$(cat "$pid_file" 2>/dev/null || true)"
    if [ -n "$pid" ] && kill -0 "$pid" 2>/dev/null; then
      kill "$pid" 2>/dev/null && echo "сервер остановлен (pid $pid)"
    fi
    rm -f "$pid_file"
  fi
}

if [ "${1:-}" = "stop" ]; then
  do_stop
  exit 0
fi

PORT="${1:-8123}"
case "$PORT" in
  stop|-h|--help|help) echo "см. комментарии в начале скрипта"; exit 0 ;;
  *[!0-9]*|'') echo "порт должен быть числом: $PORT"; exit 1 ;;
esac

URL="http://127.0.0.1:$PORT/ui.html"

if curl -fsS "http://127.0.0.1:$PORT/zip-dec.js" >/dev/null 2>&1; then
  echo "http://127.0.0.1:$PORT уже обслуживается — открываю $URL"
else
  python3 -m http.server "$PORT" --bind "$HOST" --directory . >/dev/null 2>&1 &
  PID=$!
  echo "$PID" > "${TMPDIR:-/tmp}/sfs-server.pid"
  for i in 1 2 3 4 5 6 7 8 9 10; do
    if curl -fsS "http://127.0.0.1:$PORT/ui.html" >/dev/null 2>&1; then break; fi
    if ! kill -0 "$PID" 2>/dev/null; then
      echo "ОШИБКА: python не смог поднять сервер (или порт занят). Попробуйте: $0 ${PORT}off" >&2
      exit 1
    fi
    sleep 0.3
  done
  echo "сервер запущен: http://127.0.0.1:$PORT  (pid $PID)"
fi

echo "открываю в браузере: $URL"
if command -v xdg-open >/dev/null 2>&1; then
  xdg-open "$URL" >/dev/null 2>&1 || true
elif command -v open >/dev/null 2>&1; then
  open "$URL" >/dev/null 2>&1 || true
fi

if [ -n "${SSH_CONNECTION:-}" ] || [ -n "${SSH_TTY:-}" ]; then
  echo "внимание: похоже, вы по SSH — браузер нужно открыть локально: $URL"
 fi
echo "хинт: файл .sfs открывается парсером/конвертером прямо из этой папки"
echo "хинт: остановить сервер — $0 stop"
exit 0