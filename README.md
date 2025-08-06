# Сетевой сканер с веб-скриншотами

Сканер сети, который проверяет открытые порты и делает скриншоты веб-страниц.

## 📁 Структура проекта

```
network-scanner/
├── web.py              # Основной сканер
├── config.yaml         # Конфигурация
├── requirements.txt    # Зависимости
├── README.md           # Документация
├── .gitignore          # Исключения Git
├── run_tests.py        # Запуск тестов
└── tests/              # Тесты
    ├── __init__.py
    └── test_main.py    # Объединенные тесты
```

## 🚀 Установка

```bash
# Клонирование репозитория
git clone https://github.com/andrei-s96s/network_scan.git
cd network-scanner

# Установка зависимостей
pip install -r requirements.txt
playwright install chromium
```

## Использование

```bash
python web.py <сеть> [потоки] [--no-json]
```

### Примеры

```bash
# Сканирование сети с 10 потоками (JSON и HTML отчеты по умолчанию)
python web.py 172.30.1.0/24 10

# Сканирование с 5 потоками (JSON и HTML отчеты по умолчанию)
python web.py 192.168.1.0/24 5

# Сканирование без JSON и HTML отчетов
python web.py 172.30.1.0/24 10 --no-json
```

## Конфигурация

Создайте файл `config.yaml` для настройки параметров:

```yaml
# Таймауты
probe_timeout: 5
web_timeout: 10

# Размер окна браузера
viewport_width: 1280
viewport_height: 720

# Логирование
log_level: "INFO"
log_file: "scanner.log"
```

## Результаты

- **TCP сканирование**: `scan-<сеть>.txt`
- **JSON отчет**: `scan-<сеть>.json` (по умолчанию)
- **HTML отчет**: `scan-<сеть>.html` (по умолчанию)
- **Веб-скриншоты**: `./web/<ip>/<порт>.png`
- **Логи**: `scanner.log`

## Особенности

1. **Логирование**: Структурированное логирование с файлом и консолью
2. **Конфигурация**: YAML файл для настройки параметров
3. **Валидация**: Проверка входных данных и сетевых адресов
4. **Оптимизация**: Браузер создается только при необходимости
5. **Обработка ошибок**: Улучшенная обработка исключений
6. **Типизация**: Добавлены типы для лучшей читаемости
7. **Безопасность**: Предупреждения о публичных сетях
8. **Определение ОС**: Автоматическое определение операционной системы по баннерам сервисов

## Проверяемые порты

- 22 (SSH)
- 80 (HTTP)
- 443 (HTTPS)
- 135 (RPC)
- 139 (NetBIOS)
- 445 (SMB)
- 3389 (RDP)
- 5985 (WinRM HTTP)
- 5986 (WinRM HTTPS)
- 1433 (MSSQL)
- 3306 (MySQL)
- 5432 (PostgreSQL)
- 161 (SNMP)
- 5060 (SIP)
- 5061 (SIP-TLS)
- 10000 (IP Phone Web)
- 8080 (Alternative Web)
- 554 (RTSP)
- 8000 (IP Camera Web)
- 37777 (Dahua Camera)
- 37778 (Dahua Camera)

## Поддерживаемые ОС

Сканер автоматически определяет операционные системы по баннерам сервисов:

### Windows
- IIS (Microsoft-IIS)
- Exchange Server
- SMB/CIFS сервисы
- RDP (Remote Desktop)
- WinRM (Windows Remote Management)

### Linux
- Ubuntu, Debian, CentOS, RedHat, Fedora
- OpenSSH (чаще на Linux)
- Apache, Nginx веб-серверы

### Unix
- FreeBSD, OpenBSD, NetBSD
- Solaris
- Другие Unix-подобные системы

### Сетевые устройства
- SNMP устройства (роутеры, свитчи, принтеры)
- Устройства с community string "public"

### IP Телефоны
- SIP серверы (порты 5060, 5061) с улучшенной валидацией ответов
- Веб-интерфейсы IP телефонов (порт 10000)
- Cisco, Yealink, Grandstream телефоны
- Asterisk, FreePBX серверы

### IP Камеры
- RTSP сервисы (порт 554) с улучшенной валидацией ответов
- Веб-интерфейсы IP камер (порт 8000)
- Dahua, Hikvision, Axis, Foscam камеры
- Специальные порты Dahua (37777, 37778)

### Улучшенное определение сервисов
- **RDP (3389)**: Специальный RDP connection request для точного определения
- **PostgreSQL (5432)**: Валидация ответов на startup message
- **SIP (5060, 5061)**: Проверка SIP/2.0 ответов на OPTIONS запросы
- **RTSP (554)**: Проверка RTSP/1.0 ответов на OPTIONS запросы

**Важно**: Для портов 3389, 5432, 5060, 5061, 554 используется строгая валидация. Если сервис не отвечает ожидаемым образом, порт не будет отмечен как открытый.

## 📊 Пример результатов

После выполнения сканирования вы получите:

- **Файл результатов**: `scan-<сеть>.txt` - список открытых портов
- **Скриншоты**: `./web/<ip>/<порт>.png` - изображения веб-страниц  
- **Логи**: `scanner.log` - детальная информация о процессе

### Пример вывода:
```
172.30.1.1  80:HTTP/1.1 200 OK  443:open
172.30.1.11  22:SSH-2.0-OpenSSH_8.2p1  80:HTTP/1.1 200 OK
```

### Пример JSON структуры:
```json
{
  "scan_info": {
    "network": "172.30.1.0/24",
    "scan_time": "2024-01-15T10:30:00",
    "total_hosts": 254,
    "hosts_with_ports": 5,
    "hosts_with_screenshots": 3
  },
  "hosts": [
    {
      "ip": "172.30.1.1",
      "ports": {
        "80": {
          "service": "HTTP",
          "response": "HTTP/1.1 200 OK",
          "status": "open"
        },
        "443": {
          "service": "HTTPS",
          "response": "open",
          "status": "open"
        }
      },
      "screenshots": 2,
      "summary": {
        "total_ports": 2,
        "web_ports": 2,
        "services": ["HTTP", "HTTPS"]
      }
    }
  ],
  "summary": {
    "total_ports_found": 8,
    "services_found": ["HTTP", "HTTPS", "SSH"],
    "web_services": 3
  }
}
```

### HTML отчет
При использовании флага `--json` также создается красивый HTML отчет с:
- 📊 Статистикой сканирования
- 🌐 Детальной информацией по каждому хосту
- 🔧 Списком обнаруженных сервисов
- 📸 Информацией о скриншотах
- 🎨 Современным дизайном

## ⚠️ Важно

- Используйте только для сканирования собственных сетей
- Соблюдайте законодательство вашей страны
- Не используйте для атак на чужие системы

## 🧪 Тестирование

### Запуск тестов
```bash
# Запуск всех тестов
python run_tests.py

# Запуск с покрытием кода
pytest tests/ --cov=web --cov-report=html

# Запуск конкретного теста
python -m pytest tests/test_scanner.py::TestConfig::test_config_defaults
```

### Покрытие тестами
- ✅ Конфигурация (Config, load_config)
- ✅ Валидация (validate_network, validate_threads)
- ✅ TCP сканирование (probe_port, tcp_scan)
- ✅ Менеджер браузера (BrowserManager)
- ✅ Загрузка конфигурации из файла

## 🚀 CI/CD

Проект использует GitHub Actions для автоматической проверки качества:

- **Тестирование** - автоматический запуск тестов на Python 3.8-3.11
- **Линтинг** - проверка стиля кода с flake8
- **Безопасность** - проверка уязвимостей с Bandit и Safety
- **Сборка** - создание артефактов для релиза

[![CI/CD Status](https://img.shields.io/badge/CI%2FCD-Passing-brightgreen)](https://github.com/andrei-s96s/network_scan/actions)

### 📊 Отчеты CI/CD
- **Actions** - полные логи выполнения
- **Artifacts** - результаты тестов
- **Security** - отчеты о безопасности

