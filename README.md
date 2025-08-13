# Network Scanner v2.0.0 🚀

[![Docker Hub](https://img.shields.io/badge/Docker%20Hub-andreis1s%2Fnet__scan-blue?logo=docker)](https://hub.docker.com/r/andreis1s/net_scan)
[![Python](https://img.shields.io/badge/Python-3.11+-green?logo=python)](https://python.org)
[![License](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

**Современный сетевой сканер с веб-интерфейсом, автоматическими скриншотами и Docker поддержкой**

## ✨ Особенности

- 🔍 **Двухэтапное сканирование**: Быстрое обнаружение + детальное сканирование портов
- 🌐 **Веб-интерфейс**: Современный UI с реальным временем
- 📸 **Автоматические скриншоты**: Веб-сервисы с поддержкой HTTP/HTTPS
- 🐳 **Docker готов**: Полная контейнеризация
- 📊 **Детальные отчеты**: HTML с сортировкой и модальными окнами
- 🔧 **Гибкая настройка**: Конфигурация через YAML
- 📱 **Telegram бот**: Уведомления о задачах
- 🚀 **Высокая производительность**: Асинхронное сканирование

## 🐳 Docker (рекомендуется)

### Быстрый старт
```bash
# Скачать и запустить
docker run -p 5000:5000 andreis1s/net_scan

# Или с docker-compose
git clone https://github.com/andreis1s/network-scanner.git
cd network-scanner
./docker-build.sh
```

### Доступ
- **Веб-интерфейс**: http://localhost:5000
- **API Health**: http://localhost:5000/api/health

## 📦 Установка

### Требования
- Python 3.11+
- Docker (опционально)

### Локальная установка
```bash
git clone https://github.com/andreis1s/network-scanner.git
cd network-scanner

# Создать виртуальное окружение
python -m venv venv
source venv/bin/activate  # Linux/Mac
# или
venv\Scripts\activate     # Windows

# Установить зависимости
pip install -r requirements.txt

# Установить Playwright браузеры
playwright install chromium

# Запустить
python -m src.task_web
```

## 🚀 Использование

### Веб-интерфейс
1. Откройте http://localhost:5000
2. Создайте новую задачу сканирования
3. Укажите сеть (например: 192.168.1.0/24)
4. Дождитесь завершения и скачайте отчет

### CLI команды
```bash
# Создать задачу
python scripts/task_cli.py create --network 172.30.1.0/24

# Мониторинг задач
python scripts/task_monitor.py
```

## 📋 Конфигурация

Основные настройки в `config.py`:

```python
# Сканирование
MAX_WORKERS = 16              # Количество воркеров
DISCOVERY_TIMEOUT = 0.5       # Таймаут обнаружения
USE_ICMP_PING = True          # Использовать ICMP ping

# Скриншоты
SCREENSHOT_WORKERS = 4        # Воркеры для скриншотов
VIEWPORT_WIDTH = 1920         # Ширина viewport
VIEWPORT_HEIGHT = 1080        # Высота viewport

# Веб-интерфейс
WEB_HOST = "0.0.0.0"         # Хост для веб-сервера
WEB_PORT = 5000              # Порт веб-сервера
```

## 📁 Структура проекта

```
network-scanner/
├── src/                    # Основной код
│   ├── task_manager.py     # Управление задачами
│   ├── network_scanner.py  # Сканер сети
│   ├── screenshot_manager.py # Скриншоты
│   ├── task_web.py         # Веб-интерфейс
│   └── scanner_logger.py   # Логирование
├── templates/              # HTML шаблоны
├── static/                 # Статические файлы
├── scripts/                # CLI утилиты
├── tests/                  # Тесты
├── docs/                   # Документация
├── Dockerfile              # Docker образ
├── docker-compose.yml      # Docker Compose
└── config.py               # Конфигурация
```

## 🔧 Разработка

### Установка для разработки
```bash
pip install -e ".[dev]"
```

### Запуск тестов
```bash
pytest tests/
```

### Линтинг
```bash
black src/ tests/
flake8 src/ tests/
mypy src/
```

## 📊 Возможности

### Сканирование
- **Обнаружение хостов**: TCP ping + ICMP ping
- **Сканирование портов**: 1-65535 с банерами
- **Веб-сервисы**: Автоматические скриншоты
- **SSL/TLS**: Игнорирование сертификатов
- **Протоколы**: Автоопределение HTTP/HTTPS

### Отчеты
- **HTML формат**: Современный дизайн
- **Сортировка**: По IP адресам
- **Скриншоты**: Модальные окна
- **Статистика**: Детальная информация
- **ZIP архивы**: Сжатые отчеты

### Мониторинг
- **Ресурсы**: CPU, RAM, сеть
- **Логи**: Ротация и структурирование
- **Health check**: Docker совместимость
- **Telegram**: Уведомления

## 🤝 Вклад в проект

1. Fork репозитория
2. Создайте ветку для фичи (`git checkout -b feature/amazing-feature`)
3. Commit изменения (`git commit -m 'Add amazing feature'`)
4. Push в ветку (`git push origin feature/amazing-feature`)
5. Откройте Pull Request

## 📄 Лицензия

Этот проект лицензирован под MIT License - см. файл [LICENSE](LICENSE) для деталей.

## 🔗 Ссылки

- **GitHub**: https://github.com/andreis1s/network-scanner
- **Docker Hub**: https://hub.docker.com/r/andreis1s/net_scan
- **Issues**: https://github.com/andreis1s/network-scanner/issues
- **Documentation**: [docs/](docs/)

## 📈 Статистика

- **Версия**: 2.0.0
- **Python**: 3.11+
- **Docker**: Поддерживается
- **Лицензия**: MIT
- **Статус**: Production Ready

---

**Network Scanner Team** - Создано с ❤️ для сообщества
