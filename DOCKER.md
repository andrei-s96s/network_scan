# 🐳 Docker для Network Scanner

## Быстрый старт

### Автоматический запуск
```bash
# Сборка и запуск в один клик
./docker-build.sh
```

### Ручной запуск
```bash
# Сборка образа
docker-compose build

# Запуск
docker-compose up -d

# Проверка статуса
docker-compose ps
```

## Доступ к сервису

- **Веб-интерфейс**: http://localhost:5000
- **Health check**: http://localhost:5000/api/health
- **API**: http://localhost:5000/api/tasks

## Управление контейнером

```bash
# Просмотр логов
docker-compose logs -f

# Остановка
docker-compose down

# Перезапуск
docker-compose restart

# Обновление (пересборка)
docker-compose up -d --build
```

## Структура данных

### Монтируемые директории
- `./results/` - результаты сканирования
- `./logs/` - логи приложения
- `./reports/` - сгенерированные отчеты

### Конфигурация
- `./config.py` - монтируется как read-only для кастомизации

## Безопасность

### Привилегии
Контейнер запускается с привилегиями для сетевого сканирования:
- `privileged: true` - для доступа к сетевому стеку
- `network_mode: host` - для прямого доступа к сети

### Пользователь
- Контейнер запускается от пользователя `scanner` (UID 1000)
- Не root для безопасности

## Ограничения ресурсов

```yaml
deploy:
  resources:
    limits:
      cpus: '4.0'      # Максимум 4 CPU
      memory: 4G       # Максимум 4GB RAM
    reservations:
      cpus: '1.0'      # Минимум 1 CPU
      memory: 1G       # Минимум 1GB RAM
```

## Health Check

Автоматическая проверка здоровья сервиса:
- **Интервал**: 30 секунд
- **Таймаут**: 10 секунд
- **Повторы**: 3 раза
- **Endpoint**: `/api/health`

## Переменные окружения

```bash
PYTHONPATH=/app
FLASK_ENV=production
FLASK_APP=src.task_web
```

## Проблемы и решения

### Проблема: Контейнер не запускается
```bash
# Проверка логов
docker-compose logs

# Проверка статуса
docker-compose ps
```

### Проблема: Нет доступа к сети
```bash
# Проверка привилегий
docker run --privileged --network host network-scanner
```

### Проблема: Не хватает памяти
```bash
# Увеличить лимиты в docker-compose.yml
memory: 8G
```

## Разработка

### Сборка для разработки
```bash
# Сборка без кэша
docker-compose build --no-cache

# Запуск с логами
docker-compose up
```

### Отладка
```bash
# Запуск в интерактивном режиме
docker-compose run --rm network-scanner bash

# Просмотр файлов
docker exec -it network-scanner ls -la /app
```

## Мониторинг

### Метрики контейнера
```bash
# Использование ресурсов
docker stats network-scanner

# Информация о контейнере
docker inspect network-scanner
```

### Логи приложения
```bash
# Логи в реальном времени
docker-compose logs -f network-scanner

# Логи с временными метками
docker-compose logs -f --timestamps network-scanner
```

## Резервное копирование

### Экспорт результатов
```bash
# Копирование результатов
docker cp network-scanner:/app/results ./backup/

# Создание архива
tar -czf backup-$(date +%Y%m%d).tar.gz results/
```

## Обновление

### Обновление образа
```bash
# Остановка
docker-compose down

# Обновление кода
git pull

# Пересборка и запуск
./docker-build.sh
```

## Производительность

### Оптимизация для продакшена
```yaml
# В docker-compose.yml
services:
  network-scanner:
    # Увеличить лимиты для больших сетей
    deploy:
      resources:
        limits:
          cpus: '8.0'
          memory: 8G
    # Добавить ulimits для большего количества соединений
    ulimits:
      nofile:
        soft: 65536
        hard: 65536
```

## Безопасность сети

### Firewall правила
```bash
# Разрешить только необходимые порты
iptables -A INPUT -p tcp --dport 5000 -j ACCEPT
iptables -A INPUT -p icmp -j ACCEPT
```

### Изоляция сети
```bash
# Создание отдельной сети
docker network create scanner-network

# Использование в docker-compose.yml
networks:
  - scanner-network
```
