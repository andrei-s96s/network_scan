# Система ограничения ресурсов

## Обзор

Система ограничения ресурсов предназначена для защиты сервера от перегрузки во время сетевого сканирования. Она автоматически контролирует использование CPU, памяти и сетевых соединений, динамически адаптируя активность сканера.

## Компоненты системы

### 1. ResourceMonitor

Основной класс для мониторинга ресурсов системы:

```python
from src.resource_monitor import get_resource_monitor

monitor = get_resource_monitor()
usage = monitor.get_current_usage()
```

**Возможности:**
- Мониторинг CPU в реальном времени
- Отслеживание использования памяти
- Контроль сетевого трафика в МБ/с
- Callback-уведомления при превышении лимитов

### 2. ResourceLimiter

Контекстный менеджер для ограничения ресурсов:

```python
from src.resource_monitor import get_resource_limiter

async with get_resource_limiter():
    # Код, который должен быть ограничен ресурсами
    await scan_network()
```

## Конфигурация

Настройки ограничений находятся в `config.py`:

```python
# Ограничения ресурсов
max_concurrent_connections: int = 100  # Максимум одновременных соединений
max_cpu_percent: int = 90             # Максимальная загрузка CPU в процентах
max_memory_mb: int = 2048             # Максимальное использование памяти в МБ (2GB)
max_network_mbps: float = 100.0       # Максимальный сетевой трафик в МБ/с (практически без ограничений)
```

**Примечание**: Система теперь только мониторит ресурсы без блокировки работы. Лимиты используются только для логирования.

## Интеграция в компоненты

### NetworkScanner

Сетевой сканер автоматически использует ограничения ресурсов:

```python
async def probe_port_async(self, host: str, port: int):
    async with self.resource_limiter:
        # Проверка порта с ограничением ресурсов
        pass
```

### TaskManager

Менеджер задач проверяет ресурсы перед выполнением:

```python
def start_worker(self):
    while True:
        # Проверяем ресурсы перед выполнением
        usage = self.resource_monitor.get_current_usage()
        if usage['cpu_percent'] > self.config.max_cpu_percent:
            # Откладываем задачу
            time.sleep(2)
            continue
```

### Web Interface

Веб-интерфейс отображает текущее состояние ресурсов:

```javascript
socket.on('resource_usage', function(data) {
    // Обновляем отображение CPU, памяти и соединений
    cpuPercent.textContent = `${data.cpu_percent.toFixed(1)}%`;
    memoryMb.textContent = `${data.memory_mb.toFixed(0)} MB`;
    connections.textContent = data.connections;
});
```

## Алгоритм работы

### 1. Мониторинг ресурсов

Система постоянно отслеживает:
- **CPU**: Процент использования процессора
- **Память**: Использование RAM в МБ и процентах
- **Сетевой трафик**: Передаваемые данные в МБ/с

### 2. Проверка лимитов

Система мониторит ресурсы, но не блокирует работу:

```python
def is_over_limit(self) -> bool:
    # Проверяем только для логирования, не блокируем работу
    over_cpu = usage['cpu_percent'] > self.limits.max_cpu_percent
    over_memory = usage['memory_mb'] > self.limits.max_memory_mb
    over_network = usage['network_mbps'] > self.limits.max_network_mbps
    
    # Возвращаем True только если все лимиты превышены (для логирования)
    return over_cpu and over_memory and over_network
```

### 3. Адаптивное поведение

При превышении лимитов система:
- Снижает количество одновременных соединений
- Приостанавливает новые задачи
- Восстанавливает работу при нормализации ресурсов

## API мониторинга

### Получение информации о ресурсах

```python
# Текущее использование
usage = monitor.get_current_usage()
print(f"CPU: {usage['cpu_percent']}%")
print(f"Memory: {usage['memory_mb']} MB")
print(f"Network: {usage['network_mbps']} MB/s")

# Проверка лимитов
is_over = monitor.is_over_limit()
```

### Управление соединениями

```python
# Получение соединения
if monitor.acquire_connection():
    # Выполнение работы
    pass
    # Освобождение соединения
    monitor.release_connection()
```

### Callback-уведомления

```python
def on_resource_limit_exceeded(is_over_limit: bool):
    if is_over_limit:
        print("Превышение лимитов - снижаем активность")
    else:
        print("Ресурсы восстановлены")

monitor.add_callback(on_resource_limit_exceeded)
```

## Веб-интерфейс

### Отображение ресурсов

Веб-интерфейс показывает:
- **CPU**: Процент использования с визуальной полосой
- **Память**: Использование в МБ с полосой прогресса
- **Сетевой трафик**: Передаваемые данные в МБ/с с полосой прогресса

### Обновление в реальном времени

Данные обновляются каждые 2 секунды через WebSocket:
```javascript
socket.on('resource_usage', function(data) {
    // Обновление UI
});
```

## Тестирование

### Запуск тестов

```bash
make test-resources
```

### Ручное тестирование

```python
from src.resource_monitor import get_resource_monitor

monitor = get_resource_monitor()
print(f"Текущие ресурсы: {monitor.get_current_usage()}")
```

## Рекомендации

### 1. Настройка лимитов

Для разных систем рекомендуются следующие настройки:

**Мощный сервер:**
```python
max_cpu_percent = 90
max_memory_mb = 4096  # 4GB
max_network_mbps = 100.0
```

**Слабый сервер:**
```python
max_cpu_percent = 80
max_memory_mb = 1024  # 1GB
max_network_mbps = 50.0
```

### 2. Мониторинг

Регулярно проверяйте:
- Логи в `logs/task_manager.log`
- Веб-интерфейс для отображения ресурсов
- Системные мониторы (htop, top)

### 3. Оптимизация

Для улучшения производительности:
- Увеличьте лимиты для мощных серверов
- Настройте размеры батчей в сканере
- Оптимизируйте таймауты соединений

## Устранение неполадок

### Высокая нагрузка на CPU

1. Проверьте текущие лимиты:
```python
from config import ScannerConfig
print(f"CPU limit: {ScannerConfig.max_cpu_percent}%")
```

2. Снизьте лимиты временно:
```python
# В config.py
max_cpu_percent = 50  # Вместо 70
```

### Нехватка памяти

1. Уменьшите лимит памяти:
```python
max_memory_mb = 256  # Вместо 512
```

2. Проверьте утечки памяти в логах

### Медленное сканирование

1. Проверьте настройки сети и DNS
2. Увеличьте таймауты в конфигурации:
```python
probe_timeout = 5.0  # Вместо 2.0
web_timeout = 60.0   # Вместо 30.0
```

## Логирование

Система ведет подробные логи:

```
2024-01-15 10:30:15 - resource_monitor - INFO - Запуск мониторинга ресурсов
2024-01-15 10:30:16 - resource_monitor - WARNING - Высокая нагрузка на ресурсы - продолжаем работу
2024-01-15 10:30:18 - resource_monitor - INFO - Ресурсы восстановлены
```

## Безопасность

- Система не позволяет превысить установленные лимиты
- Автоматическое восстановление при нормализации ресурсов
- Защита от DoS-атак через ограничение соединений
