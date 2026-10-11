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
     │      CALLER (ПК)      │   Звонок OneMe через OkCDN    │   RELAY (Сервер / Pi) │
     │        Python         │ ◄═══════════════════════════► │      Go / Python      │ ──► Интернет
     │   (oneme_caller.py)   │      WebRTC DataChannel       │  (calltunnel-relay)   │
     │   (socks5_server.py)  │     (AES-256-GCM + X25519)    │  (internal/relay)     │
     └───────────────────────┘                               └───────────────────────┘
```

1. **Caller (клиент на ПК)**:
   - Запускает локальный SOCKS5-прокси (`127.0.0.1:1080`).
   - Авторизуется в сигналинге OneMe (`api.oneme.ru` / `videowebrtc.okcdn.ru`).
   - Инициирует защищённый звонок на указанный ID аккаунта релея.
   - Мультиплексирует клиентские TCP-сессии в защищённый канал WebRTC DataChannel.

2. **Relay (принимающая сторона на Raspberry Pi или VPS)**:
   - Доступен как на **Go** (`gotunnel/dist/calltunnel-relay-linux-*` — статический бинарник ~8 МБ, потребляет ~15 МБ RAM, идеален для Pi Zero 2 W), так и на **Python** (`oneme_client.py`).
   - Ожидает входящие звонки на аккаунте.
   - Открывает реальные TCP-соединения к целевым хостам в интернет и транслирует данные обратно.

---

## 🔒 Безопасность и Zero-Trust аутентификация

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

## ⚡ Оптимизация и стабильность WebRTC под нагрузкой

При активном сёрфинге (видео на Twitch, YouTube, открытие 50+ параллельных TCP-сокетов) стандартный стек WebRTC сталкивается с ограничениями. В проект внесены критические доработки:

- **Resilient STUN Consent Freshness (RFC 7675)**: в `aioice` стандартный опрос согласия выполняется с 500-мс таймаутом без повторов, из-за чего при заполнении сетевых очередей звонок падал с `Consent to send expired`. В [webrtc_call.py](file:///home/nkmr/proj_19/webrtc_call.py) внедрены повторные попытки (`retransmissions=2`), повышен лимит сбоев до 15 и активирован учёт активности потока данных (если пир шлёт данные, согласие считается подтверждённым).
- **Фильтрация пар TURN-кандидатов**: предотвращены ошибки 403 Forbidden на публичных релеях при попытке спаривания с частными локальными IP.
- **Поддержка комбинированных DTLS-сертификатов**: поддержка ECDSA и RSA шифров для совместимости с различными клиентами.
- **Увеличенные таймауты подключения в SOCKS5**: таймаут подтверждения поднят до 15 секунд для согласованности с сетевым диалером релея.

---

## 📁 Структура проекта

```text
/home/nkmr/proj_19/
├── oneme_caller.py              # Клиентская часть (Python): запуск звонка и SOCKS5-прокси
├── oneme_client.py              # Серверная часть (Python): приём звонка и ретрансляция
├── socks5_server.py             # Локальный асинхронный SOCKS5-сервер
├── tunnel_crypto.py             # Криптография туннеля (AES-GCM, X25519, Call Knocking)
├── tunnel_relay.py              # Модуль мультиплексирования TCP-соединений (Python)
├── webrtc_call.py               # Сигналинг OneMe/OkCDN и логика WebRTC (aiortc/aioice)
├── oneme_proto.py               # Кодирование протокола OneMe (MsgPack, LZ4, VCP-параметры)
├── config.example.json          # Пример конфигурации релея
├── config_caller.example.json   # Пример конфигурации клиента
├── .gitignore                   # Настройки игнорирования Git
│
├── gotunnel/                    # Высокопроизводительный Go-релей для Raspberry Pi / серверов
│   ├── cmd/relay/main.go        # Точка входа Go-релея
│   ├── internal/callclient/     # OneMe WebSocket клиент на Go
│   ├── internal/relay/          # Быстрый TCP-прокси мультиплексор (горутины)
│   ├── internal/signal/         # WebRTC сигналинг и Pion WebRTC на Go
│   ├── internal/tunnelcrypto/   # Порт X25519 + AES-GCM на Go
│   ├── internal/proto/          # Парсер пакетов OneMe на Go
│   ├── deploy/                  # systemd сервис и примеры
│   └── Makefile                 # Сборка под x86_64, arm64, armv7, armv6
│
└── scratch/                     # Вспомогательные скрипты исследования протокола и тесты
```

---

## 🛠️ Быстрый старт

### 1. Получение токенов OneMe

Вам понадобятся **два отдельных аккаунта OneMe/Max** (один для релея на Pi, второй для клиента на ПК):
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
python3 oneme_caller.py --gen-key
```
Вывод покажет:
```text
Generated X25519 Keypair:
  Private Key: <64-hex символа приватного ключа>
  Public Key:  <64-hex символа публичного ключа>
```
*Сгенерируйте две пары: одну для релея (Pi), другую для звонящего (ПК).*

---

### 3. Настройка и запуск релея (Raspberry Pi)

#### Вариант А: Использование Go-бинарника (Рекомендуется)
1. Соберите бинарник под архитектуру вашей платы (например, на хост-машине):
   ```bash
   cd gotunnel
   make all
   ```
   *Готовые бинарники появятся в `gotunnel/dist/`:*
   - `calltunnel-relay-linux-arm64` — 64-bit Raspberry Pi OS (Pi Zero 2 W, Pi 3, 4, 5).
   - `calltunnel-relay-linux-armv7` — 32-bit Raspberry Pi OS.

2. Скопируйте на Raspberry Pi:
   ```bash
   scp dist/calltunnel-relay-linux-arm64 deploy/config.example.json deploy/calltunnel-relay.service pi@192.168.0.8:/tmp/
   ```

3. Установите сервис на Raspberry Pi:
   ```bash
   sudo useradd -r -s /usr/sbin/nologin calltunnel
   sudo mkdir -p /opt/calltunnel
   sudo install -m755 /tmp/calltunnel-relay-linux-arm64 /opt/calltunnel/calltunnel-relay
   sudo install -m600 -o calltunnel /tmp/config.example.json /opt/calltunnel/config.json
   ```

4. Заполните `/opt/calltunnel/config.json`:
   ```json
   {
     "token": "<ТОКЕН_АККАУНТА_PI>",
     "private_key": "<ПРИВАТНЫЙ_КЛЮЧ_PI_HEX>",
     "allowed_peers": [
       "<ПУБЛИЧНЫЙ_КЛЮЧ_ПК_HEX>"
     ]
   }
   ```

5. Активируйте systemd-сервис:
   ```bash
   sudo cp /tmp/calltunnel-relay.service /etc/systemd/system/
   sudo systemctl daemon-reload
   sudo systemctl enable --now calltunnel-relay
   journalctl -u calltunnel-relay -f
   ```

#### Вариант Б: Запуск на Python
```bash
python3 oneme_client.py -c config.json
```

---

### 4. Настройка и запуск клиента (ПК)

1. Установите зависимости Python:
   ```bash
   pip install aiortc websockets msgpack lz4 cryptography
   ```

2. Создайте файл `config_caller.json` (скопируйте из `config_caller.example.json`):
   ```json
   {
     "callee_id": 12345678,
     "token": "<ТОКЕН_АККАУНТА_ПК>",
     "proxy_host": "127.0.0.1",
     "proxy_port": 1080,
     "audio_only": false,
     "private_key": "<ПРИВАТНЫЙ_КЛЮЧ_ПК_HEX>",
     "peer_public_key": "<ПУБЛИЧНЫЙ_КЛЮЧ_PI_HEX>"
   }
   ```

3. Запустите звонок (без необходимости указывать параметры в командной строке):
   ```bash
   python3 oneme_caller.py -c config_caller.json
   # или просто:
   python3 oneme_caller.py
   ```

4. Проверьте работоспособность туннеля через SOCKS5:
   ```bash
   curl -x socks5h://127.0.0.1:1080 https://api.ipify.org
   ```
   Команда вернёт публичный IP-адрес интернет-подключения релея (Raspberry Pi)!

---

## ⚙️ Параметры командной строки `oneme_caller.py`

| Параметр | Описание |
|---|---|
| `-c`, `--config` | Путь к файлу конфигурации (по умолчанию `config_caller.json`) |
| `callee_id` | ID аккаунта OneMe, принимающего звонок (если не задан в конфиге) |
| `-t`, `--token` | Токен авторизации звонящего (`__oneme_auth`) |
| `--privkey` | Асимметричный приватный ключ Curve25519 (hex) |
| `--peer-pubkey` | Публичный ключ Curve25519 релея (hex) |
| `-s`, `--secret` | Общий пароль шифрования (симметричный legacy-режим) |
| `--proxy-port` | Порт локального SOCKS5-прокси (по умолчанию `1080`) |
| `--proxy-host` | Хост локального SOCKS5-прокси (по умолчанию `127.0.0.1`) |
| `--audio-only` | Инициировать только аудио-звонок (без видеотрека) |
| `--gen-key` | Сгенерировать пару ключей X25519 и выйти |

---

## 🧪 Тестирование

Для запуска сквозных тестов криптографии и совместимости:
```bash
cd gotunnel
make test
```
Тесты проверяют:
- Совместимость шифрования и расшифровки между Python и Go (AES-GCM векторы);
- Корректность кодирования/декодирования бинарных фреймов OneMe и VCP параметров (LZ4 + Base64 + JSON);
- Полный сквозной цикл TCP-проксирования релея на реальном сокете.

---

## 📄 Лицензия и отказ от ответственности

Проект создан исключительно в исследовательских целях для тестирования возможностей WebRTC DataChannel и устойчивости сетевых протоколов. Использование неофициальных клиентов мессенджеров может противоречить пользовательскому соглашению сервиса.
