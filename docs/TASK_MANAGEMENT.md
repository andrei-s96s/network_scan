# 🚀 Система управления задачами сканирования

## 📋 Обзор

Система управления задачами предоставляет удобные интерфейсы для создания, мониторинга и управления задачами сетевого сканирования. Поддерживает как CLI, так и веб-интерфейс.

## 🏗️ Архитектура

### Основные компоненты

1. **TaskManager** (`task_manager.py`) - Ядро системы управления задачами
2. **TaskCLI** (`task_cli.py`) - Командная строка для управления
3. **TaskWebInterface** (`task_web.py`) - Веб-интерфейс
4. **Task** - Модель задачи с полной типизацией

### Типы задач

- **NETWORK_SCAN** - Сканирование сети
- **SCREENSHOT_CREATION** - Создание скриншотов
- **REPORT_GENERATION** - Генерация отчетов
- **CLEANUP** - Очистка временных файлов
- **COMPRESSION** - Сжатие результатов

### Статусы задач

- **PENDING** - Ожидает выполнения
- **RUNNING** - Выполняется
- **COMPLETED** - Завершена успешно
- **FAILED** - Завершена с ошибкой
- **CANCELLED** - Отменена
- **PAUSED** - Приостановлена

### Приоритеты

- **LOW** - Низкий приоритет
- **NORMAL** - Обычный приоритет
- **HIGH** - Высокий приоритет
- **URGENT** - Срочный приоритет

## 🖥️ CLI Интерфейс

### Установка и запуск

```bash
# Установка зависимостей
pip install -r requirements.txt

# Запуск CLI
python task_cli.py --help
```

### Основные команды

#### Создание задач

```bash
# Сканирование сети
python task_cli.py scan 192.168.1.0/24 --threads 20 --priority high --name "Сканирование офиса"

# Создание скриншотов
python task_cli.py screenshot 192.168.1.0/24 --priority normal --name "Скриншоты веб-сервисов"

# Генерация отчетов
python task_cli.py report 192.168.1.0/24 --priority normal --name "Отчеты по сети"

# Очистка временных файлов
python task_cli.py cleanup --priority low --name "Еженедельная очистка"

# Сжатие результатов
python task_cli.py compress 192.168.1.0/24 --priority normal --name "Архивирование результатов"
```

#### Управление задачами

```bash
# Список всех задач
python task_cli.py list

# Список задач по статусу
python task_cli.py list --status running

# Список задач по типу
python task_cli.py list --type network_scan

# Информация о задаче
python task_cli.py info <task_id>

# Управление задачами
python task_cli.py control cancel <task_id>
python task_cli.py control pause <task_id>
python task_cli.py control resume <task_id>
```

#### Мониторинг и статистика

```bash
# Статистика менеджера задач
python task_cli.py stats

# Мониторинг в реальном времени
python task_cli.py monitor

# Интерактивный режим
python task_cli.py interactive
```

### Интерактивный режим

Интерактивный режим предоставляет удобный интерфейс для управления задачами:

```bash
python task_cli.py interactive
```

Доступные команды в интерактивном режиме:
- `scan <сеть> [--threads N] [--priority P]` - добавить сканирование
- `screenshot <сеть> [--priority P]` - добавить скриншоты
- `report <сеть> [--priority P]` - добавить отчеты
- `cleanup [--priority P]` - добавить очистку
- `compress <сеть> [--priority P]` - добавить сжатие
- `list [--status S] [--type T]` - список задач
- `info <task_id>` - информация о задаче
- `cancel <task_id>` - отменить задачу
- `pause <task_id>` - приостановить задачу
- `resume <task_id>` - возобновить задачу
- `stats` - статистика
- `monitor` - мониторинг
- `quit` - выход

## 🌐 Веб-интерфейс

### Запуск веб-интерфейса

```bash
# Запуск веб-сервера
python task_web.py

# Веб-интерфейс будет доступен по адресу:
# http://localhost:5000
```

### Возможности веб-интерфейса

#### 📊 Дашборд
- Статистика в реальном времени
- Графики производительности
- Мониторинг ресурсов

#### ➕ Создание задач
- Интуитивные формы
- Валидация параметров
- Предварительный просмотр

#### 📋 Управление задачами
- Список всех задач
- Фильтрация по статусу и типу
- Детальная информация о задачах
- Управление (отмена, пауза, возобновление)

#### 🔔 Уведомления
- WebSocket уведомления в реальном времени
- Статус выполнения задач
- Ошибки и предупреждения

### API Endpoints

#### Получение данных
- `GET /api/tasks` - список всех задач
- `GET /api/tasks/<task_id>` - информация о задаче
- `GET /api/stats` - статистика менеджера задач

#### Управление задачами
- `POST /api/tasks` - создание новой задачи
- `DELETE /api/tasks/<task_id>` - отмена задачи
- `POST /api/tasks/<task_id>/pause` - приостановка задачи
- `POST /api/tasks/<task_id>/resume` - возобновление задачи

#### WebSocket события
- `task_completed` - задача завершена
- `task_error` - ошибка в задаче
- `stats_update` - обновление статистики
- `tasks_update` - обновление списка задач

## 🔧 Программный API

### Создание менеджера задач

```python
from config import load_config
from task_manager import TaskManager, TaskPriority, TaskType

# Загрузка конфигурации
config = load_config()

# Создание менеджера задач
task_manager = TaskManager(config, max_workers=5)
task_manager.start()

# Создание задачи сканирования
task = task_manager.create_network_scan_task(
    network="192.168.1.0/24",
    threads=20,
    priority=TaskPriority.HIGH,
    name="Сканирование сети"
)

# Добавление задачи в очередь
task_id = task_manager.add_task(task)
```

### Callback функции

```python
def on_task_completion(task):
    print(f"Задача {task.name} завершена")

def on_task_error(task, error):
    print(f"Ошибка в задаче {task.name}: {error}")

# Регистрация callback функций
task_manager.add_completion_callback(on_task_completion)
task_manager.add_error_callback(on_task_error)
```

### Мониторинг задач

```python
# Получение всех задач
all_tasks = task_manager.get_all_tasks()

# Фильтрация по статусу
running_tasks = task_manager.get_tasks_by_status(TaskStatus.RUNNING)

# Фильтрация по типу
scan_tasks = task_manager.get_tasks_by_type(TaskType.NETWORK_SCAN)

# Получение статистики
stats = task_manager.get_stats()
```

## 📊 Мониторинг и логирование

### Логирование

Система ведет подробные логи всех операций:

```python
import logging

# Настройка логирования
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('task_manager.log'),
        logging.StreamHandler()
    ]
)
```

### Метрики

Система собирает следующие метрики:
- Количество задач по статусам
- Время выполнения задач
- Использование ресурсов
- Ошибки и исключения
- Производительность

## 🔒 Безопасность

### Рекомендации

1. **Ограничение доступа**
   - Используйте файрвол для ограничения доступа к веб-интерфейсу
   - Настройте аутентификацию для веб-интерфейса

2. **Валидация входных данных**
   - Все параметры задач валидируются
   - Проверка сетевых диапазонов
   - Ограничение количества потоков

3. **Логирование безопасности**
   - Все действия пользователей логируются
   - Отслеживание подозрительной активности

## 🚀 Производительность

### Оптимизации

1. **Пул исполнителей**
   - Переиспользование потоков
   - Ограничение максимального количества задач

2. **Приоритизация**
   - Очередь с приоритетами
   - Динамическое управление ресурсами

3. **Асинхронность**
   - Неблокирующие операции
   - WebSocket для реального времени

### Рекомендации по настройке

```python
# Для высоконагруженных систем
task_manager = TaskManager(config, max_workers=10)

# Для систем с ограниченными ресурсами
task_manager = TaskManager(config, max_workers=3)

# Настройка таймаутов
config.probe_timeout = 10
config.web_timeout = 15
```

## 🧪 Тестирование

### Запуск тестов

```bash
# Тесты менеджера задач
python -m pytest tests/test_task_manager.py -v

# Тесты CLI
python -m pytest tests/test_task_cli.py -v

# Тесты веб-интерфейса
python -m pytest tests/test_task_web.py -v
```

### Примеры тестов

```python
def test_task_creation():
    task_manager = TaskManager(config)
    task = task_manager.create_network_scan_task("192.168.1.0/24")
    assert task.network == "192.168.1.0/24"
    assert task.task_type == TaskType.NETWORK_SCAN

def test_task_execution():
    task_manager = TaskManager(config)
    task_manager.start()
    
    task = task_manager.create_network_scan_task("127.0.0.1/32")
    task_id = task_manager.add_task(task)
    
    # Ждем завершения
    time.sleep(5)
    
    completed_task = task_manager.get_task(task_id)
    assert completed_task.status == TaskStatus.COMPLETED
```

## 📝 Примеры использования

### Полный цикл сканирования

```python
from task_manager import TaskManager, TaskPriority
from config import load_config

config = load_config()
task_manager = TaskManager(config)
task_manager.start()

# 1. Сканирование сети
scan_task = task_manager.create_network_scan_task(
    network="192.168.1.0/24",
    threads=20,
    priority=TaskPriority.HIGH,
    name="Сканирование сети"
)
scan_id = task_manager.add_task(scan_task)

# 2. Создание скриншотов (после завершения сканирования)
screenshot_task = task_manager.create_screenshot_task(
    scan_results=[],  # Будет заполнено после сканирования
    network="192.168.1.0/24",
    priority=TaskPriority.NORMAL,
    name="Скриншоты веб-сервисов"
)
screenshot_id = task_manager.add_task(screenshot_task)

# 3. Генерация отчетов
report_task = task_manager.create_report_task(
    scan_results=[],  # Будет заполнено после сканирования
    network="192.168.1.0/24",
    screenshots_count={},  # Будет заполнено после скриншотов
    priority=TaskPriority.NORMAL,
    name="Генерация отчетов"
)
report_id = task_manager.add_task(report_task)

# Мониторинг выполнения
while True:
    stats = task_manager.get_stats()
    if stats['completed_tasks'] == 3:
        break
    time.sleep(1)

print("Все задачи завершены!")
```

### Интеграция с существующим кодом

```python
# Интеграция с main.py
from task_manager import TaskManager
from config import load_config

def main():
    config = load_config()
    task_manager = TaskManager(config)
    task_manager.start()
    
    # Создание задачи из аргументов командной строки
    network = "192.168.1.0/24"
    threads = 10
    
    task = task_manager.create_network_scan_task(
        network=network,
        threads=threads,
        priority=TaskPriority.NORMAL
    )
    
    task_id = task_manager.add_task(task)
    print(f"Задача создана: {task_id}")
    
    # Ожидание завершения
    while True:
        task = task_manager.get_task(task_id)
        if task.status in [TaskStatus.COMPLETED, TaskStatus.FAILED]:
            break
        time.sleep(1)
    
    if task.status == TaskStatus.COMPLETED:
        print("Сканирование завершено успешно")
        return task.results
    else:
        print(f"Ошибка сканирования: {task.error_message}")
        return None
```

## 🔄 Обновления и миграции

### Версионирование

Система поддерживает версионирование задач и совместимость:

```python
# Проверка версии задачи
if task.version < "2.0.0":
    # Миграция старой задачи
    task = migrate_task(task)
```

### Сохранение состояния

```python
# Сохранение состояния менеджера задач
task_manager.save_state(Path("task_manager_state.json"))

# Загрузка состояния
task_manager.load_state(Path("task_manager_state.json"))
```

## 📞 Поддержка

### Логи и отладка

```bash
# Включение отладочного режима
export TASK_MANAGER_DEBUG=1
python task_cli.py --verbose

# Просмотр логов
tail -f task_manager.log
```

### Часто задаваемые вопросы

**Q: Как увеличить количество одновременных задач?**
A: Измените параметр `max_workers` при создании TaskManager.

**Q: Как настроить уведомления о завершении задач?**
A: Используйте callback функции `add_completion_callback()`.

**Q: Можно ли отменить выполняющуюся задачу?**
A: Да, используйте метод `cancel_task(task_id)`.

**Q: Как получить статистику выполнения?**
A: Используйте метод `get_stats()` для получения статистики.

## 📚 Дополнительные ресурсы

- [Документация Flask](https://flask.palletsprojects.com/)
- [Документация Socket.IO](https://socket.io/docs/)
- [Руководство по асинхронному программированию](https://docs.python.org/3/library/asyncio.html)
- [Лучшие практики логирования](https://docs.python.org/3/howto/logging.html)
