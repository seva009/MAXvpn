# call_tunnel — VPN-туннель через звонок в мессенджере

SOCKS5-прокси, трафик которого шифруется (AES-256-GCM) и передаётся через
WebRTC DataChannel внутри обычного звонка в мессенджере OneMe/Max.
Одна сторона (**caller**, ПК) поднимает локальный SOCKS5 и звонит;
вторая сторона (**relay / callee**, Raspberry Pi) принимает звонок и
открывает реальные TCP-соединения в интернет.

```
 браузер / curl / tun2socks
          │ SOCKS5 (127.0.0.1:1080)
          ▼
 ┌────────────────────┐   звонок OneMe (WebRTC DataChannel,   ┌─────────────────────┐
 │ CALLER  (ПК)       │   пакеты AES-256-GCM)                 │ RELAY (Raspberry Pi)│
 │ Python:            │◄────────────────────────────────────►│ Go-бинарник         │──► интернет
 │ oneme_caller.py    │      api.oneme.ru + videowebrtc.      │ calltunnel-relay    │
 │ socks5_server.py   │      okcdn.ru (сигналинг, STUN/TURN)  │                     │
 └────────────────────┘                                        └─────────────────────┘
```

## Что изменилось в этой версии

Раньше обе стороны были на Python (`aiortc`), и на Pi Zero 2 W он не
запускался/не тянул. Сторона **relay** переписана на **Go** и собирается
в один статический бинарник (~8 МБ, без зависимостей, без Python).
Сторона **caller** остаётся на Python и запускается на ПК — без изменений.

Протокол и логика не менялись: те же опкоды, тот же формат пакетов, тот же
вывод ключа, те же команды сигналинга. Go-реляй совместим на проводе с
Python-caller (проверено тестовыми векторами, см. «Тесты»).

## Структура проекта

```
cmd/relay/main.go            точка входа (аналог oneme_client.py как программы)
internal/tunnelcrypto/       порт tunnel_crypto.py   (AES-GCM, опкоды, connect-payload)
internal/relay/              порт tunnel_relay.py    (мультиплексор TCP-соединений)
internal/proto/              порт oneme_proto.py     (бинарный протокол OneMe, msgpack+LZ4, vcp)
internal/callclient/         порт oneme_client.py    (логин, приём входящего звонка 137)
internal/signal/             порт webrtc_call.py     (сигналинг ws2 + pion/webrtc, callee-сторона)
python/                      исходные Python-файлы (нужны для caller на ПК)
deploy/                      systemd-юнит, пример конфига
vendor/                      зависимости (сборка работает офлайн)
dist/                        готовые бинарники
```

Соответствие модулей:

| Python | Go | Примечание |
|---|---|---|
| `tunnel_crypto.py` | `internal/tunnelcrypto` | 1:1 |
| `tunnel_relay.py` | `internal/relay` | 1:1 (asyncio-задачи → горутины) |
| `oneme_proto.py` | `internal/proto` | 1:1 |
| `oneme_client.py` | `internal/callclient` + `cmd/relay` | 1:1 |
| `webrtc_call.py` (callee) | `internal/signal` | см. «Отличия» |
| `socks5_server.py`, `oneme_caller.py` | остаются на Python | работают на ПК |

## Протокол

### 1. Шифрование туннеля и аутентификация (`tunnelcrypto`)

Поддерживаются два режима:
1. **Асимметричный Zero-Trust режим (Curve25519 / X25519)**:
   * **Call Knocking (защита от DoS на этапе звонка)**: при звонке `conversationId` кодируется как аутентифицированный через HMAC билет-токен. Relay проверяет билет до ответа на звонок; звонки от чужих пользователей немедленно сбрасываются, линия не занимается.
   * **In-Band Handshake (внутри DataChannel)**: после открытия канала происходит 1-RTT рукопожатие с взаимной аутентификацией открытых ключей и Perfect Forward Secrecy (PFS) на базе эфемерных ключей X25519.
   * **Раздельные сессионные ключи**: независимые ключи для направлений `Caller -> Relay` и `Relay -> Caller` защищают от атак отражения (reflection attacks) и повторов (replay attacks).
   * Защитный таймаут 3 с: неавторизованные клиенты молча отключаются.
2. **Симметричный режим (Legacy / Fallback)**:
   * Ключ: `SHA-256(secret)` → 32 байта AES-256.

* Пакет в DataChannel: `[12 байт случайный nonce] [AES-GCM(ciphertext + 16 байт tag)]`
* Открытый текст: `[1 байт тип][4 байта conn_id, big-endian][payload]`
* Нет открытых заголовков/magic-байт — пакет выглядит как случайный шум.

Опкоды: `1 CONNECT` (`[port:2][host:utf8]`), `2 CONNECT_OK`, `3 CONNECT_FAIL`
(текст ошибки), `4 DATA`, `5 CLOSE`, `6 PING`, `7 PONG`, `10 HANDSHAKE_INIT`, `11 HANDSHAKE_RESP`.

### 2. Ретранслятор (`relay`)

* `CONNECT` → TCP-подключение к `host:port` (таймаут 12 с) → ответ `CONNECT_OK` / `CONNECT_FAIL`.
* `DATA` → запись в сокет цели; чтение из сокета кусками по 16 КБ → `DATA` назад.
* `CLOSE` ← закрывает сокет; закрытие со стороны цели → `CLOSE` вызывающей стороне.
* Текстовые сообщения DataChannel `ping`/`pong` — keepalive (каждые 15 с).

### 3. OneMe-шлюз (`proto`, `callclient`)

`wss://api.oneme.ru/websocket`, заголовки `Origin: https://web.max.ru` и Firefox User-Agent.
Бинарный кадр: 10 байт заголовка (`ver=10`, `cmd`, `seq` int16, `opcode` int16,
коэффициент сжатия, длина 24 бита) + msgpack-payload (LZ4-блок, если ratio > 0).
Расширение msgpack тип 1 — 64-битные ID.

Последовательность: `opcode 6` (init) → `opcode 19` (login по токену) →
ожидание `opcode 137` (входящий звонок). Из `vcp` (`<длина>:<base64(LZ4(JSON))>`)
берутся `tkn` (токен звонка), `stne` (STUN), `trne/trnu/trnp` (TURN),
`wse` (сигналинг). **userId для OkCDN** — вторая часть `trnu` (`<время>:<id>`),
а не ID профиля чата.

### 4. WebRTC-сигналинг (`signal`)

`wss://videowebrtc.okcdn.ru/ws2?...&tgt=accept` →
ждём приветствие `connection` (до 3 с) → `accept-call` →
получаем `transmitted-data` с SDP offer → отвечаем SDP answer.

* Из answer вырезаются строки `a=candidate:` / `a=end-of-candidates`.
* Отдельными сообщениями трикл-ятся только `srflx`/`relay`-кандидаты (host пропускаются).
* Входящие кандидаты добавляются всегда с `sdpMid="0"`, `sdpMLineIndex=0`.
* DataChannel принимается от caller; бинарные сообщения идут в relay, текстовые — keepalive.
* При закрытии DataChannel / `hungup` — остановка relay и `hangup`.

## Быстрый старт

### 1. Получить токен

В браузере на аккаунте, который будет **принимать** звонок (аккаунт Pi):
открыть web.max.ru → консоль → `localStorage.getItem('__oneme_auth')`.
Токен даёт полный доступ к аккаунту — храните как пароль.
Аналогично получить токен аккаунта-звонящего для ПК, и узнать числовой ID аккаунта Pi.

### 2. Собрать (на любой машине с Go ≥ 1.22)

```bash
make test          # тесты
make all           # dist/calltunnel-relay-linux-{arm64,armv7,armv6}
```

Какой бинарник нужен:

| Устройство / ОС | Файл |
|---|---|
| Pi Zero 2 W, 64-bit Raspberry Pi OS | `calltunnel-relay-linux-arm64` |
| Pi Zero 2 W, 32-bit Raspberry Pi OS | `calltunnel-relay-linux-armv7` |
| Pi Zero / Zero W (первое поколение) | `calltunnel-relay-linux-armv6` |

Проверить на Pi: `uname -m` (`aarch64` → arm64, `armv7l` → armv7, `armv6l` → armv6).
Зависимости лежат в `vendor/`, интернет при сборке не нужен.

### 3. Установить на Pi

```bash
scp dist/calltunnel-relay-linux-arm64 deploy/* pi@raspberrypi:/tmp/
# на Pi:
sudo useradd -r -s /usr/sbin/nologin calltunnel
sudo mkdir -p /opt/calltunnel
sudo install -m755 /tmp/calltunnel-relay-linux-arm64 /opt/calltunnel/calltunnel-relay
sudo install -m600 -o calltunnel /tmp/config.example.json /opt/calltunnel/config.json
sudo nano /opt/calltunnel/config.json        # token + tunnel_secret
sudo cp /tmp/calltunnel-relay.service /etc/systemd/system/
sudo systemctl daemon-reload && sudo systemctl enable --now calltunnel-relay
journalctl -u calltunnel-relay -f
```

В логе должно появиться `Logged in successfully ... Listening for incoming calls...`.

`config.json`:

| Поле | Описание |
|---|---|
| `token` | токен аккаунта Pi (`__oneme_auth`) |
| `tunnel_secret` | общий секрет туннеля (fallback) |
| `private_key` | приватный ключ релея X25519 (hex) |
| `allowed_peers` | список публичных ключей разрешённых клиентов X25519 (hex) |
| `device_id` | UUID устройства; генерируется автоматически |
| `viewer_id` | необязательно, определяется при логине |

Генерация ключей:
```bash
./dist/calltunnel-relay -gen-key
# или в Python:
python3 python/oneme_caller.py --gen-key
```

### 4. Запустить caller на ПК

```bash
cd python
pip install aiortc websockets msgpack lz4 cryptography

# Вариант А (рекомендуется): через config_caller.json (без аргументов при запуске)
cp config_caller.example.json config_caller.json
# Заполните callee_id, token, private_key, peer_public_key в config_caller.json
python3 oneme_caller.py

# Вариант Б: передать параметры вручную через флаги:
python3 oneme_caller.py <ID_аккаунта_Pi> --token <ТОКЕН_ЗВОНЯЩЕГО> \
    --privkey <ПРИВАТНЫЙ_КЛЮЧ_CALLER> \
    --peer-pubkey <ПУБЛИЧНЫЙ_КЛЮЧ_PI>

# Или в legacy-режиме с общим паролем:
python3 oneme_caller.py <ID_аккаунта_Pi> --token <ТОКЕН_ЗВОНЯЩЕГО> --secret <секрет>

curl -x socks5h://127.0.0.1:1080 https://api.ipify.org   # должен показать IP Pi
```

`--audio-only` — звонок без видео; `--proxy-port/--proxy-host` — адрес SOCKS5.
Для всей системы поверх SOCKS5 можно использовать tun2socks.

## Тесты

`make test` проверяет:
* расшифровку Go пакета, зашифрованного оригинальным `tunnel_crypto.py` (векторы), и совпадение connect-payload;
* декодирование кадра OneMe, созданного `oneme_proto.py`, формат заголовка и `vcp` (LZ4+base64+JSON), сжатый Python;
* сквозную работу relay на реальном TCP (CONNECT → OK → DATA-эхо → CLOSE, CONNECT_FAIL при недоступном порте).

## Отличия от Python-версии и ограничения

Нужно знать честно — это важно перед использованием:

1. **Живая часть не проверена.** В среде разработки нет доступа к `api.oneme.ru` и `okcdn.ru`, поэтому
   логин, приём звонка, ICE/DTLS и DataChannel с реальными серверами **не тестировались**.
   Криптография, фреймы и relay проверены; сигналинг портирован по исходнику построчно, но
   первый реальный запуск может потребовать правок. Запускайте сначала на ПК с видимым логом.
2. **Патчи aiortc/aioice не портированы.** В `webrtc_call.py` монки-патчи (список шифров DTLS,
   принудительная роль SCTP, повтор STUN-проверок при 400/401/431, запрет пар relay↔private IP,
   подмена `remote_username`) обходят баги и особенности aiortc. В pion роли DTLS/SCTP, ICE-роли и
   пары кандидатов обрабатываются по стандарту. **Самый вероятный источник проблем** — подмена
   `ufrag` кандидатов от SFU OkCDN: в pion нет API для переопределения remote ufrag, поэтому
   расширение `ufrag …` просто вырезается из кандидата. Если ICE не соединяется, смотрите сюда первым.
3. **Только callee.** Go-версия — только принимающая сторона (прокси-режим). Режим `speedtest`
   и сторона caller/SOCKS5 остаются в Python.
4. **Безопасность.** Ключ — SHA-256 от строки без соли и KDF: используйте длинную случайную фразу и
   **смените `tunnel_secret`** (значение по умолчанию публично). Нет защиты от повторов (replay).
   Любой, кто знает секрет и может позвонить на аккаунт Pi, получает relay, который
   подключается куда угодно, включая вашу локальную сеть. Ограничивайте по необходимости
   (firewall/`nftables` для пользователя `calltunnel`). Токен OneMe в `config.json` — права `600`.
5. Токен/версии клиента (`appVersion 26.10.3`, `sdkVersion`) зашиты как в оригинале; при
   обновлении мессенджера протокол может измениться.
6. Использование «неофициального клиента» может противоречить правилам сервиса и привести к
   блокировке аккаунта — используйте отдельные аккаунты.

## Зависимости Go

`pion/webrtc/v3`, `gorilla/websocket`, `vmihailenco/msgpack/v5`, `pierrec/lz4/v4`.
В `go.mod` есть `replace`-директивы на GitHub-зеркала `golang.org/x/*` и `gopkg.in/*` — они нужны только
для сборки в среде без доступа к этим доменам; при обычном доступе их можно удалить
(`go mod tidy`). Сборка из `vendor/` работает в любом случае.
