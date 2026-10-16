# call_tunnel — VPN-туннель через звонок в мессенджере (Go-версия)

SOCKS5-прокси, трафик которого шифруется (AES-256-GCM + X25519) и передаётся через WebRTC DataChannel внутри обычного аудио/видеозвонка в мессенджере OneMe / Max.

Обе стороны туннеля — и **caller** (клиент со встроенным SOCKS5 на Android Termux / ПК / macOS / Windows), и **relay** (сервер на Raspberry Pi / Linux / VPS) — написаны на **Go** и собираются в **единые статические бинарники** (`CGO_ENABLED=0`, без зависимостей, без Python и без pip).

```
 браузер / curl / tun2socks
          │ SOCKS5 (127.0.0.1:1080)
          ▼
 ┌────────────────────┐   звонок OneMe (WebRTC DataChannel,   ┌─────────────────────┐
 │ CALLER             │   пакеты AES-256-GCM + X25519)        │ RELAY (Raspberry Pi)│
 │ Go-бинарник        │◄────────────────────────────────────►│ Go-бинарник         │──► Интернет
 │ calltunnel-caller  │      api.oneme.ru + videowebrtc.      │ calltunnel-relay    │
 │ (Android / ПК)     │      okcdn.ru (сигналинг, STUN/TURN)  │ (ARM / x86 / VPS)   │
 └────────────────────┘                                        └─────────────────────┘
```

---

## 🚀 Преимущества Go-версии

1. **Один автономный бинарник**: запуск на телефоне (Android Termux), роутере, Raspberry Pi, ПК без установки Python, `pip`, `aiortc`, `cryptography` и компиляторов.
2. **Работа на Android без Root**: обходит ограничения SELinux Android 11+ для сетевых интерфейсов.
3. **Встроенные сертификаты Минцифры и Mozilla**: нет ошибок `x509: certificate signed by unknown authority` на мобильных устройствах.
4. **Умный DNS-резолвер**: автоматическая работа через нативный сокет Android `/dev/socket/dnsproxyd` и публичные апстримы при отсутствии `/etc/resolv.conf`.
5. **Auto-Reconnect и Keepalive Pings**: автоматическое переподключение шлюза при смене сетей (Wi-Fi ↔ LTE) и периодические пинги для предотвращения сброса NAT.

---

## 🛠️ Архитектура и структура кода

```text
cmd/caller/main.go            точка входа клиента SOCKS5 (calltunnel-caller)
cmd/relay/main.go             точка входа релея (calltunnel-relay)
internal/caller/              клиент OneMe Caller: логин, звонок, Auto-Redial
internal/callclient/          клиент OneMe Callee: приём звонков (Relay)
internal/socks5/              локальный RFC 1928 SOCKS5-прокси сервер
internal/relay/               высокопроизводительный TCP-мультиплексор (горутины)
internal/signal/              Pion WebRTC + сигналинг ws2 (DataChannel, SDP, ICE)
internal/tunnelcrypto/        криптография AES-GCM + X25519 (Call Knocking, PFS)
internal/proto/               бинарный протокол OneMe, MsgPack + LZ4, VCP
internal/netx/                сетевой стек: DNS dnsproxyd, Root CA Минцифры, ResilientNet
vendor/                       все зависимости внутри репозитория (офлайн-сборка)
dist/                         готовые скомпилированные бинарники для всех платформ
```

---

## 🔒 Безопасность и Zero-Trust протокол

1. **Call Knocking (Защита от сканирования и DoS)**:
   - При звонке `conversationId` кодируется как аутентифицированный HMAC-тикет на базе времени и публичного ключа релея.
   - Релей валидирует тикет **до ответа на звонок**. Звонки от посторонних аккаунтов немедленно отклоняются без занятия линии.
2. **In-Band Handshake (1-RTT PFS)**:
   - После открытия DataChannel стороны производят обмен эфемерными ключами X25519 с взаимной проверкой публичных ключей.
   - Выводятся раздельные симметричные ключи (AES-256-GCM) для направлений `Caller -> Relay` и `Relay -> Caller` с монотонными счётчиками для защиты от replay-атак.
3. **Симметричный режим (Fallback)**:
   - При отсутствии X25519 ключей используется общий пароль `tunnel_secret` (AES-256-GCM от SHA-256 секрета).

---

## 🔧 Критические исправления для мобильных устройств (Android / Termux)

В ходе разработки и боевого тестирования на Android / Termux были решены все ключевые проблемы мобильной среды:

### 1. Сертификаты TLS (Минцифры России + Mozilla Web PKI)
* **Проблема**: На Android в Termux или минимальных Linux-системах подключение к `wss://api.oneme.ru/websocket` или `videowebrtc.okcdn.ru` завершалось ошибкой:
  ```text
  dial gateway: tls: failed to verify certificate: x509: certificate signed by unknown authority
  ```
  Это вызвано тем, что сервисы OneMe/OkCDN используют TLS-сертификаты, выпущенные Национальным удостоверяющим центром (Минцифры России), которых нет в стандартных бандлах Android и Mozilla, а в Termux часто отсутствует путь `/etc/ssl/certs/ca-certificates.crt`.
* **Решение**:
  - В бинарник напрямую вшит полный CA-бандл (185 КБ), включающий актуальные сертификаты **Mozilla Web PKI** + корневой и выпускающий сертификаты **Минцифры России (Russian Trusted Root CA / Sub CA)**.
  - Реализован автоматический сканер системных путей Android (`/apex/com.android.conscrypt/cacerts`, `/system/etc/security/cacerts`, `$PREFIX/etc/tls/cert.pem`).
  - Добавлен флаг `-k` / `--insecure` и опция `"insecure_skip_verify": true` для пропуска проверки сертификатов при необходимости.

### 2. DNS-резолвинг на Android (`dnsproxyd` + Multi-Upstream)
* **Проблема**:
  1. В Android Termux отсутствует `/etc/resolv.conf`, из-за чего Go пытался стучаться в `[::1]:53` (`connection refused`).
  2. При обращении к публичным DNS по TCP без соблюдения RFC 1035 возникал таймаут: `lookup api.oneme.ru: i/o timeout`.
* **Решение**:
  - Модуль `internal/netx/dns.go` автоматически обнаруживает системный Unix-сокет Android `/dev/socket/dnsproxyd` и выполняет нативный системный резолвинг с учётом активного Wi-Fi/LTE DNS.
  - При недоступности сокета используется конкурентный опрос публичных DNS (Яндекс `77.88.8.8`, Cloudflare `1.1.1.1`, Google `8.8.8.8`) по UDP и TCP с корректной длиной кадров (`streamConn`).
  - Добавлен флаг `-dns <ip>` (например, `-dns 77.88.8.8`) для ручного переопределения DNS.

### 3. Обход блокировки SELinux Netlink на Android 11+ (`netlinkrib: permission denied`)
* **Проблема**: На нерутованном Android 11+ непривилегированным процессам (включая Termux) запрещён доступ к сетевому сокету Netlink (`AF_NETLINK`):
  ```text
  CreateOffer failed: failed to create network: route ip+net: netlinkrib: permission denied
  ```
  Из-за этого стандартный стек Pion WebRTC не мог перечислить интерфейсы и падал при создании SDP offer.
* **Решение**:
  - Создан кастомный `ResilientNet` (`internal/netx/pion_net.go`), реализующий интерфейс Pion transport.
  - Определение IP-адресов выполняется через UDP route probe сокеты (без вызова Netlink) и чтение `/proc/net/dev`.
  - Отключен mDNS (`MulticastDNSModeDisabled`), который также требовал Netlink.
  - Пропатчен модуль интерфейсов `anet`. В результате приложение работает на Android **без root-прав**!

### 4. Auto-Reconnect и WebSocket Keepalive
* **Проблема**: При смене сетей (Wi-Fi ↔ LTE) или агрессивном энергосбережении Android сокеты обрывались с `software caused connection abort`, а программа завершалась с `gateway connection lost`.
* **Решение**:
  - Каждые 20 секунд в шлюз OneMe отправляются WebSocket RFC 6455 Ping-фреймы, что предотвращает сброс NAT-маршрутизаторов.
  - Встроен двойной цикл автоматического переподключения (как внутри логики шлюза, так и в `main`): при любом разрыве процесс ждёт 3 секунды, переподключается, авторизуется и возобновляет работу прокси.

### 5. Обработка дублирующихся SDP-ответов
* **Проблема**: При быстром хэндшейке SFU OkCDN присылал повторный ответ:
  ```text
  SetRemoteDescription failed: InvalidModificationError: invalid proposed signaling state transition: stable->SetRemote(answer)->stable
  ```
* **Решение**: `internal/signal/signal.go` безопасно игнорирует повторные ответы в состоянии `stable`.

---

## 📦 Быстрый старт

### 1. Сборка бинарников

```bash
cd gotunnel
make all        # соберёт все бинарники в dist/
```

Готовые файлы в `dist/`:
- `calltunnel-caller-linux-arm64` — **Android (Termux arm64)**, Raspberry Pi 64-bit, ARM64 VPS.
- `calltunnel-caller-linux-amd64` — ПК Linux x86_64.
- `calltunnel-caller-windows-amd64.exe` — ПК Windows x64.
- `calltunnel-caller-darwin-arm64` — macOS Apple Silicon (M1/M2/M3/M4).
- `calltunnel-caller-darwin-amd64` — macOS Intel.
- `calltunnel-relay-*` — аналогичный набор бинарников для стороны релея.

---

### 2. Запуск релея (Raspberry Pi / VPS)

1. Сгенерируйте ключи X25519:
   ```bash
   ./dist/calltunnel-relay -gen-key
   ```
2. Создайте `config.json`:
   ```json
   {
     "token": "<ТОКЕН_АККАУНТА_PI>",
     "private_key": "<ПРИВАТНЫЙ_КЛЮЧ_PI_HEX>",
     "allowed_peers": [
       "<ПУБЛИЧНЫЙ_КЛЮЧ_CALLER_HEX>"
     ]
   }
   ```
3. Запустите:
   ```bash
   ./calltunnel-relay -config config.json
   ```

---

### 3. Запуск caller (Телефон Android в Termux / ПК)

1. Перенесите бинарник `calltunnel-caller-linux-arm64` на телефон в Termux:
   ```bash
   chmod +x calltunnel-caller-linux-arm64
   ```
2. Создайте `config_caller.json`:
   ```json
   {
     "callee_id": 12345678,
     "token": "<ТОКЕН_АККАУНТА_CALLER>",
     "proxy_host": "127.0.0.1",
     "proxy_port": 1080,
     "private_key": "<ПРИВАТНЫЙ_КЛЮЧ_CALLER_HEX>",
     "peer_public_key": "<ПУБЛИЧНЫЙ_КЛЮЧ_PI_HEX>"
   }
   ```
3. Запустите одной командой:
   ```bash
   ./calltunnel-caller-linux-arm64 -c config_caller.json
   ```
4. В соседней вкладке Termux или в браузере проверьте прокси:
   ```bash
   curl -x socks5h://127.0.0.1:1080 https://api.ipify.org
   ```
   Команда покажет внешний IP-адрес релея (Raspberry Pi)!

---

## ⚙️ Флаги командной строки `calltunnel-caller`

| Флаг | Описание |
|---|---|
| `-c`, `-config` | Путь к файлу конфигурации (по умолчанию `config_caller.json`) |
| `<callee_id>` | Числовой ID аккаунта OneMe для звонка (позиционный аргумент) |
| `-t`, `-token` | Токен авторизации звонящего (`__oneme_auth`) |
| `-p`, `-proxy-port` | Порт локального SOCKS5-прокси (по умолчанию `1080`) |
| `-proxy-host` | Хост локального SOCKS5-прокси (по умолчанию `127.0.0.1`) |
| `-privkey` | Асимметричный приватный ключ X25519 (hex) |
| `-peer-pubkey` | Публичный ключ X25519 релея (hex) |
| `-s`, `-secret` | Симметричный пароль (legacy-режим) |
| `-dns` | Переопределить DNS-сервер (например: `-dns 77.88.8.8`) |
| `-k`, `-insecure` | Пропустить валидацию TLS-сертификатов |
| `-audio-only` | Инициировать только аудио-звонок без видеотрека |
| `-gen-key` | Сгенерировать пару ключей X25519 и выйти |

---

## 🧪 Тестирование

```bash
cd gotunnel
go test -v ./...
```
Тесты проверяют бинарную совместимость криптографии, LZ4-декодер VCP параметров, RFC 1928 SOCKS5 и проксирование данных.
