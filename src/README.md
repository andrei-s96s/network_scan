# Основные модули системы

Этот каталог содержит основные модули системы сканирования сети.

## Основные файлы:

- **task_manager.py** - Менеджер задач, управляет выполнением сканирования
- **task_web.py** - Веб-интерфейс для управления задачами
- **network_scanner.py** - Сканер сети, выполняет поиск хостов и портов
- **report_generator.py** - Генератор отчетов (HTML, JSON, TXT)
- **screenshot_manager.py** - Менеджер скриншотов веб-интерфейсов
- **retry_manager.py** - Менеджер повторных попыток
- **stream_processor.py** - Обработчик потоков данных
- **cache_manager.py** - Менеджер кэширования
- **cleanup_manager.py** - Менеджер очистки временных файлов
- **compression_manager.py** - Менеджер сжатия результатов
- **resource_monitor.py** - Мониторинг ресурсов системы
- **scanner_logger.py** - Логирование сканера
- **system_analyzer.py** - Анализ системы для оптимизации

## Использование:

```bash
# Запуск веб-интерфейса
python src/task_web.py

# Запуск CLI
python src/task_cli.py

# Запуск мониторинга
python scripts/task_monitor.py
```
