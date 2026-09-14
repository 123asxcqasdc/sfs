# SFS — Simple File System

Деревовидная файловая система, хранящая имена **и содержимое** файлов.
Использует **все 256 значений байта** (0x00–0xFF) в именах и содержимом.
Целостность — SHA-256 в заголовке, аутентичность — **Ed25519-подпись издателя**.

Парсеры: **JavaScript** (Node / браузер) и **Kotlin** (Android), плюс **веб-GUI**.

## Формат (v2, заголовок 144 Б)
```
[0-3]    magic "SFSY"
[4-7]    version = 2 · root_count  (uint16 LE)
[8-39]   SHA-256 всех байт от offset 144  — целостность
[40-71]  публичный ключ издателя (Ed25519, 32 Б; нули = unsigned)
[72-79]  signer_id = SHA-256(pubkey)[0..7]
[80-143] подпись Ed25519 (64 Б) над header[0..79] + всё дерево
[144..]  дерево
```
Узел дерева:
```
type(1) · name_len(2,LE) · name(raw, все байты)
  dir  → child_count(2,LE) + дочерние узлы
  file → content_len(uint32,LE) + content
```
Совместим с v1 (заголовок 40 Б, только хеш) — читается как legacy unsigned.

## Файлы

| файл | назначение |
|---|---|
| `parser.js` | JS-парсер: `parse`, `serialize`, `verifyHash`, `verifySignature` |
| `parser.kt` | Kotlin/Android-парсер (тот же формат) |
| `ed25519.js` | чистый JS Ed25519 + SHA-512, без зависимостей (для Node и браузера) |
| `writer.js` | CLI-демо: упаковка подписанная / unsigned, тесты |
| `ui.html` | графический интерфейс (браузер) |
| `zip-dec.js` | распаковка ZIP-методов (bzip2/LZMA/zstd/deflate/store) |
| `vendor/` | MIT-библиотеки: seek-bzip, js-lzma, fzstd |
| `serve.sh` | запуск веб-GUI на локальном сервере со всеми библиотеками |

## Веб-GUI (`ui.html`)
Самый надёжный способ — локальный сервер (все библиотеки отдаются рядом с `ui.html`):
```bash
./serve.sh            # открывает http://127.0.0.1:8123/ui.html
./serve.sh 8080       # другой порт
./serve.sh stop       # остановить сервер
```
Требуется только `python3`. Можно и просто открыть `ui.html` файлом (`ed25519.js`,
`parser.js`, `vendor/`, `zip-dec.js` должны лежать рядом), но при `file://`
некоторые браузеры ограничивают загрузку локальных ресурсов — тогда распаковка
ZIP вернёт ошибку вида «не загружены распаковщики (zip-dec.js / vendor/)».
Возможности:
- редактор дерева (файлы/каталоги, имена и содержимое — любые байты);
- **упаковка без подписи** (только SHA-256);
- **упаковка с подписью** (генерация ключа / ввод seed);
- создание, **экспорт** и **импорт** ключей издателя (.json, .pub);
- открытие `.sfs`, проверка хеша, подписи и доверенных издателей (allowlist);
- **конвертация `.zip` → подписанный `.sfs`** — встроенный мини-распаковщик
  (методы: stored, deflate, bzip2, LZMA, zstd; имена и содержимое сохраняются
  по байтам). Если ключа нет — генерируется автоматически при конвертации.

Распаковка сжатых методов через готовые веб-декомпрессоры в `vendor/`
(работают офлайн, без WASM/воркеров):

| метод | что читает | библиотека (license) |
|---|---|---|
| 12 bzip2 | `vendor/bzip2.js` | seek-bzip (MIT) |
| 14 LZMA  | `vendor/lzma.js`  | js-lzma (MIT) |
| 95 zstd  | `vendor/fzstd.js` | fzstd (MIT) |

`zip-dec.js` — обёртка: `window.ZipDec.decode(method, payload, {size})`.
Не поддерживаются: deflate64 (9), PPMd (98), AES (99), zip64 — выдаётся
понятная ошибка.

## CLI (`writer.js`)
```bash
node writer.js                 # signed-пакет tree.sfs (ключ ген/чтение publisher.seed)
node writer.js --unsigned      # unsigned-пакет (только хеш)
node writer.js out.sfs         # имя файла результата
```

## API (JS)
```js
const { FsParser, FsNode, TYPE_FILE, TYPE_DIR } = require('./parser.js');

const roots = [ /* FsNode[] */ ];
const unsigned = FsParser.serialize(roots);            // unsigned
const signed   = FsParser.serialize(roots, {seed});    // signed

const r = FsParser.parse(bytes);                       // { version, roots, hashValid, signatureValid, signerId, pubkey }
const v = FsParser.verifySignature(bytes, [pubkey]);   // { signatureValid, trusted }
```

## API (Kotlin/Android)
```kotlin
val r = FsParser.parse(data)                       // Root(version, roots, hashValid, signatureValid, signerId, pubkey)
FsParser.verifyHash(data)
FsParser.verifySignature(data, listOf(pubkey))
FsParser.serialize(roots, seed, pubKey)            // signed
FsParser.serialize(roots)                          // unsigned
```
> Ed25519 в `java.security` требует Android API 33+; для старых устройств — BouncyCastle
> (`org.bouncycastle:bcprov-android`). `publicKeyFromSeed` требует BouncyCastle.

## Репозиторий
https://github.com/123asxcqasdc/sfs