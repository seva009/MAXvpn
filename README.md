# OneMe WebRTC Tunnel (call_tunnel)

> **VPN-туннель (SOCKS5) через обычный аудио/видеозвонок в мессенджере OneMe / Max.**  
> Трафик полностью маскируется под легитимный медиа-звонок между двумя пользователями (WebRTC UDP/DTLS через CDN-серверы `videowebrtc.okcdn.ru`). Внутри WebRTC DataChannel передаётся зашифрованный туннель (AES-256-GCM) с нулевым доверием (Zero-Trust аутентификация X25519) и защитой от чужих звонков (Call Knocking).

---

## 🚀 Архитектура и схема работы

```text
  Браузер / Программы / tun2socks
                 │ SOCKS5 (127.0.0.1:1080)
                 ▼
     ┌───────────────────────┐                               ┌───────────────────────┐
     │  CALLER (ПК/Телефон)  │   Звонок OneMe через OkCDN    │   RELAY (Сервер / Pi) │
     │      Go / Python      │ ◄═══════════════════════════► │      Go / Python      │ ──► Интернет
     │  (calltunnel-caller)  │      WebRTC DataChannel       │  (calltunnel-relay)   │
     │   (Android Termux)    │     (AES-256-GCM + X25519)    │  (internal/relay)     │
     └───────────────────────┘                               └───────────────────────┘
```

1. **Caller (клиент на Android / Termux / ПК / macOS / Windows)**:
   - Скомпилирован в **один автономный статический Go-бинарник** (`gotunnel/dist/calltunnel-caller-*`), не требующий Python, pip, GCC или внешних библиотек.
   - Поднимает локальный SOCKS5-прокси (`127.0.0.1:1080`).
   - Инициирует звонок через OneMe шлюз (`api.oneme.ru` / `videowebrtc.okcdn.ru`).
   - Автоматически переподключается при смене сетей (Wi-Fi ↔ LTE) и отправляет keepalive-пинги.
   - Доступна также альтернативная Python-реализация (`oneme_caller.py`).

2. **Relay (принимающая сторона на Raspberry Pi / Linux / VPS)**:
   - Доступен на **Go** (`gotunnel/dist/calltunnel-relay-*` — статический бинарник ~8 МБ, потребляет ~15 МБ RAM, идеален для Pi Zero 2 W) и на **Python** (`oneme_client.py`).
   - Ожидает входящие вызовы, проверяет Call Knocking билет, открывает TCP-соединения в интернет.
   - Автоматически восстанавливает соединение со шлюзом OneMe при обрывах связи.

---

## 🔒 Безопасность и Zero-Trust протокол

В проект встроена многоуровневая криптографическая защита, не зависящая от серверов мессенджера:

1. **Защита от DoS и сканирования (Call Knocking)**:
   - При звонке `conversationId` формируется как криптографический HMAC-тикет на основе времени и публичного ключа релея.
   - Релей валидирует тикет **до ответа на звонок**. Если звонит спамер или посторонний пользователь, звонок отклоняется немедленно без занятия линии.
2. **In-Band Handshake с Perfect Forward Secrecy (PFS)**:
   - Сразу после открытия WebRTC DataChannel стороны выполняют 1-RTT рукопожатие на эфемерных ключах Curve25519 (X25519).
   - Даже если долговременный секрет будет скомпрометирован в будущем, прошлый трафик расшифровать невозможно.
3. **Раздельные сессионные ключи**:
   - Генерируются независимые ключи для направлений `Caller -> Relay` и `Relay -> Caller` с монотонными счётчиками, что исключает replay-атаки и атаки отражения (reflection).
4. **Симметричный режим (Legacy / Fallback)**:
   - Поддерживается упрощённый режим с единым паролем `tunnel_secret` (AES-256-GCM от SHA-256 секрета).

---

## 📱 Полная адаптация под Android и Termux (Все фиксы)

При запуске на мобильных устройствах под управлением Android (в среде Termux) стандартные сетевые приложения сталкиваются с системными ограничениями ОС. В GoTunnel все эти проблемы решены "из коробки":

### 1. Сертификаты TLS и Минцифры России
* **Симптом**: Ошибка `tls: failed to verify certificate: x509: certificate signed by unknown authority`.
* **Причина**: Шлюз `api.oneme.ru` и CDN-серверы используют сертификаты Национального удостоверяющего центра (Минцифры России), которых нет в доверенных хранилищах Android и Mozilla. Кроме того, в Termux отсутствует стандартный системный путь `/etc/ssl/certs/ca-certificates.crt`.
* **Решение**:
  - В бинарник напрямую вшит полный CA-бандл (185 КБ), включающий актуальные сертификаты **Mozilla Web PKI** + корневые и выпускающие сертификаты **Минцифры России (Russian Trusted Root CA / Sub CA)**.
  - Реализован автоматический сканер системных путей Android (`/apex/com.android.conscrypt/cacerts`, `/system/etc/security/cacerts`, `$PREFIX/etc/tls/cert.pem`).
  - Добавлены флаг `-k` / `--insecure` и опция `"insecure_skip_verify": true` для аварийного отключения проверки при необходимости.

### 2. DNS-резолвинг на Android (`dnsproxyd` + публичные апстримы)
* **Симптом**:
  1. `dial tcp: lookup api.oneme.ru on [::1]:53: read: connection refused` (в Termux нет `/etc/resolv.conf`).
  2. `lookup api.oneme.ru: i/o timeout` (Go пытался слать DNS-запросы без учёта длины пакетов).
* **Решение**:
  - Модуль `internal/netx/dns.go` на лету обнаруживает Unix-сокет Android `/dev/socket/dnsproxyd` и использует встроенный системный резолвер ОС Android (учитывает текущий Wi-Fi, мобильный интернет и системные настройки DNS).
  - Если сокет недоступен, автоматически включается параллельный опрос публичных апстримов (Яндекс `77.88.8.8`, Cloudflare `1.1.1.1`, Google `8.8.8.8`) по UDP и TCP с корректной длиной кадров (`streamConn`).
  - Добавлен флаг `-dns <ip>` (например, `-dns 77.88.8.8`).

### 3. Обход блокировки SELinux Netlink на Android 11+ (`netlinkrib: permission denied`)
* **Симптом**: `failed to create network: route ip+net: netlinkrib: permission denied` при вызове `CreateOffer`.
* **Причина**: На Android 11+ в непривилегированном окружении SELinux запрещает создание Netlink-сокетов (`AF_NETLINK`) для перечисления сетевых интерфейсов.
* **Решение**:
  - Разработан `ResilientNet` (`internal/netx/pion_net.go`), полностью заменяющий сетевой интерфейс для Pion WebRTC.
  - Определение IP-адресов устройства выполняется через UDP route probe сокеты (без вызова Netlink) и чтение `/proc/net/dev`.
  - Отключен mDNS (`MulticastDNSModeDisabled`), также вызывавший сбой Netlink.
  - Пропатчен модуль интерфейсов `anet`. В результате приложение запускается в Termux **без root-прав**!

### 4. Защита от разрывов: Keepalive Pings и Auto-Reconnect
* **Симптом**: Ошибка `software caused connection abort` -> `gateway connection lost` при засыпании экрана или смене сетей (Wi-Fi ↔ LTE).
* **Причина**: Мобильные NAT-роутеры и операторские CGNAT сбрасывают неактивные TCP-сессии; кратковременный обрыв сети приводит к завершению процесса.
* **Решение**:
  - Каждые 20 секунд в шлюз OneMe отправляются WebSocket RFC 6455 Ping-фреймы, что держит NAT-таблицы активными.
  - Встроен двойной цикл автоматического переподключения (как внутри логики шлюза, так и в `main`): при любом разрыве процесс ждёт 3 секунды, переподключается, авторизуется и возобновляет работу прокси без участия пользователя.

### 5. Обработка повторных ответов сигналинга
* **Симптом**: `SetRemoteDescription failed: InvalidModificationError: invalid proposed signaling state transition: stable->SetRemote(answer)->stable`.
* **Решение**: `internal/signal/signal.go` безопасно подавляет дубликаты SDP-ответов от SFU, приходящие после перехода в состояние `stable`.

---

## 📁 Структура проекта

```text
/
├── gotunnel/                    # Высокопроизводительный Go-клиент и релей (единые бинарники)
│   ├── cmd/caller/main.go       # Точка входа клиента со встроенным SOCKS5-прокси
│   ├── cmd/relay/main.go        # Точка входа релея
│   ├── internal/caller/         # OneMe Caller: авторизация, звонок, Auto-Redial
│   ├── internal/callclient/     # OneMe Callee: приём входящих звонков
│   ├── internal/socks5/         # Локальный RFC 1928 SOCKS5-сервер
│   ├── internal/relay/          # TCP-мультиплексор (горутины)
│   ├── internal/signal/         # Pion WebRTC + сигналинг ws2
│   ├── internal/tunnelcrypto/   # Порт X25519 + AES-GCM
│   ├── internal/proto/          # Парсер пакетов OneMe, MsgPack + LZ4
│   ├── internal/netx/           # DNS dnsproxyd, Root CA Минцифры, ResilientNet (Android fix)
│   ├── dist/                    # Скомпилированные бинарники под все платформы
│   ├── vendor/                  # Автономные зависимости для офлайн-сборки
│   └── Makefile                 # Скрипт сборки под все платформы
│
├── oneme_caller.py              # Клиентская часть (Python, fallback)
├── oneme_client.py              # Серверная часть (Python, fallback)
├── socks5_server.py             # Локальный асинхронный SOCKS5-сервер (Python)
├── tunnel_crypto.py             # Криптография туннеля (Python)
├── tunnel_relay.py              # Модуль мультиплексирования TCP-соединений (Python)
├── webrtc_call.py               # Сигналинг OneMe/OkCDN и логика WebRTC (Python)
├── oneme_proto.py               # Кодирование протокола OneMe (Python)
├── config.example.json          # Пример конфигурации релея
└── config_caller.example.json   # Пример конфигурации клиента
```

---

## 🛠️ Быстрый старт

### 1. Получение токенов OneMe

Вам понадобятся **два отдельных аккаунта OneMe/Max** (один для релея на Pi, второй для клиента на телефоне/ПК):
1. Откройте [web.max.ru](https://web.max.ru) в браузере под нужным аккаунтом.
2. Откройте DevTools (F12) → вкладка Console.
3. Выполните:
   ```javascript
   localStorage.getItem('__oneme_auth')
   ```
4. Сохраните токен и числовой ID профиля (caller / callee).

---

### 2. Генерация криптографических ключей X25519

Сгенерируйте ключевые пары для клиента и релея:
```bash
./gotunnel/dist/calltunnel-caller -gen-key
```
Вывод покажет:
```text
Generated X25519 Keypair:
  Private Key: <64-hex символа приватного ключа>
  Public Key:  <64-hex символа публичного ключа>
```
*Сгенерируйте две пары: одну для релея (Pi), другую для звонящего (телефон/ПК).*

---

### 3. Настройка и запуск релея (Raspberry Pi / Linux / VPS)

1. Соберите бинарники или возьмите готовый из `gotunnel/dist/`:
   ```bash
   cd gotunnel && make all
   ```
   *Файлы в `gotunnel/dist/`:*
   - `calltunnel-relay-linux-arm64` — 64-bit Linux ARM64 (Raspberry Pi 3, 4, 5, Pi Zero 2 W, ARM64 VPS).
   - `calltunnel-relay-linux-amd64` — 64-bit Linux x86_64 (VPS, домашний сервер, ПК).
   - `calltunnel-relay-linux-armv7` — 32-bit Raspberry Pi OS (Pi 2, 3, 4 в 32-битном режиме).
   - `calltunnel-relay-linux-armv6` — Raspberry Pi 1, Pi Zero (ARMv6).
   - `calltunnel-relay-windows-amd64.exe` — Windows x64.
   - `calltunnel-relay-darwin-arm64` — macOS (Apple Silicon).

2. Создайте файл конфигурации `config.json`:
   ```json
   {
     "token": "<ТОКЕН_АККАУНТА_PI>",
     "private_key": "<ПРИВАТНЫЙ_КЛЮЧ_PI_HEX>",
     "allowed_peers": [
       "<ПУБЛИЧНЫЙ_КЛЮЧ_ТЕЛЕФОНА_HEX>"
     ]
   }
   ```

3. Запустите релей:
   ```bash
   ./calltunnel-relay-linux-arm64 -config config.json
   ```

---

### 4. Настройка и запуск клиента (Телефон Android в Termux / ПК)

1. Скопируйте файл `calltunnel-caller-linux-arm64` на телефон (в каталог Termux):
   ```bash
   chmod +x calltunnel-caller-linux-arm64
   ```

2. Создайте `config_caller.json`:
   ```json
   {
     "callee_id": 12345678,
     "token": "<ТОКЕН_АККАУНТА_ТЕЛЕФОНА>",
     "proxy_host": "127.0.0.1",
     "proxy_port": 1080,
     "audio_only": false,
     "private_key": "<ПРИВАТНЫЙ_КЛЮЧ_ТЕЛЕФОНА_HEX>",
     "peer_public_key": "<ПУБЛИЧНЫЙ_КЛЮЧ_PI_HEX>"
   }
   ```

3. Запустите клиент:
   ```bash
   ./calltunnel-caller-linux-arm64 -c config_caller.json
   ```
   Логи покажут:
   ```text
   [DNS] Android system dnsproxyd detected (/dev/socket/dnsproxyd). Using native Android resolver.
   Connected to wss://api.oneme.ru/websocket!
   Logged in successfully as caller '123456789'!
   Call initiated successfully!
   [Signaling] WebRTC session established and running indefinitely.
   [WebRTC DataChannel] OPENED successfully!
   [Auth] Handshake SUCCESSFUL! PFS session established.
   [SOCKS5 PROXY ACTIVE] Listening on 127.0.0.1:1080!
   ```

4. Проверьте работоспособность туннеля через SOCKS5:
   ```bash
   curl -x socks5h://127.0.0.1:1080 https://api.ipify.org
   ```
   Команда вернёт публичный IP-адрес интернет-подключения релея (Raspberry Pi / VPS)!

---

## ⚙️ Параметры командной строки `calltunnel-caller`

| Параметр | Описание |
|---|---|
| `-c`, `-config` | Путь к файлу конфигурации (по умолчанию `config_caller.json`) |
| `<callee_id>` | Числовой ID аккаунта OneMe, принимающего звонок (позиционный аргумент) |
| `-t`, `-token` | Токен авторизации звонящего (`__oneme_auth`) |
| `-privkey` | Асимметричный приватный ключ X25519 (hex) |
| `-peer-pubkey` | Публичный ключ X25519 релея (hex) |
| `-s`, `-secret` | Общий пароль шифрования (симметричный legacy-режим) |
| `-p`, `-proxy-port` | Порт локального SOCKS5-прокси (по умолчанию `1080`) |
| `-proxy-host` | Хост локального SOCKS5-прокси (по умолчанию `127.0.0.1`) |
| `-dns` | Ручное переопределение DNS (например: `-dns 77.88.8.8`) |
| `-k`, `-insecure` | Пропуск валидации TLS-сертификатов |
| `-audio-only` | Инициировать только аудио-звонок (без видеотрека) |
| `-gen-key` | Сгенерировать пару ключей X25519 и выйти |

---

## 🧪 Тестирование

```bash
cd gotunnel
make test
```
Тесты проверяют:
- Взаимную совместимость шифрования и расшифровки между Python и Go (AES-GCM векторы);
- Корректность кодирования/декодирования бинарных фреймов OneMe и VCP параметров (LZ4 + Base64 + JSON);
- Полный сквозной цикл TCP-проксирования релея на реальном сокете.

---

## 📄 Лицензия и отказ от ответственности

Проект создан исключительно в исследовательских целях для тестирования возможностей WebRTC DataChannel и устойчивости сетевых протоколов. Использование неофициальных клиентов мессенджеров может противоречить пользовательскому соглашению сервиса.
