# Makefile для сетевого сканера
.PHONY: install test run clean web cli monitor test-resources lint format type-check clean-all help

# Установка зависимостей
install:
	pip install -r requirements.txt
	playwright install

# Запуск тестов
test:
	python -m pytest tests/ -v

# Запуск веб-интерфейса
web:
	python -m src.task_web

# Запуск CLI
cli:
	python -m src.task_cli

# Мониторинг системы
monitor:
	python -m src.task_monitor

# Тестирование системы ограничения ресурсов
test-resources:
	python -m pytest tests/ -k "resource" -v

# Линтинг кода
lint:
	flake8 src/ scripts/ --max-line-length=120 --ignore=E501,W503

# Форматирование кода
format:
	black src/ scripts/ --line-length=120

# Проверка типов
type-check:
	mypy src/ --ignore-missing-imports

# Очистка
clean:
	# Удаление Python кэша
	find . -type f -name "*.pyc" -delete
	find . -type d -name "__pycache__" -exec rm -rf {} + 2>/dev/null || true
	find . -type d -name "*.pyo" -delete
	
	# Удаление логов
	find . -type f -name "*.log" -delete
	
	# Удаление архивов отчетов
	find . -type f -name "*.zip" -delete
	
	# Удаление временных файлов
	find . -type f -name "*.tmp" -delete
	find . -type f -name "*.temp" -delete
	
	# Удаление файлов результатов сканирования
	find results/ -type f -name "*.json" -delete
	find results/ -type f -name "*.html" -delete
	find results/ -type f -name "*.txt" -delete
	find results/ -type f -name "*.png" -delete
	find results/ -type f -name "*.jpg" -delete
	find results/ -type f -name "*.jpeg" -delete
	
	# Удаление временных директорий отчетов
	find reports/ -type d -name "temp_*" -exec rm -rf {} + 2>/dev/null || true
	
	# Удаление кэша pytest
	rm -rf .pytest_cache/ 2>/dev/null || true
	
	# Удаление кэша mypy
	rm -rf .mypy_cache/ 2>/dev/null || true

# Полная очистка
clean-all: clean
	# Полная очистка результатов
	rm -rf results/* 2>/dev/null || true
	rm -rf logs/* 2>/dev/null || true
	rm -rf reports/* 2>/dev/null || true
	
	# Очистка кэша Python
	rm -rf __pycache__/ 2>/dev/null || true
	rm -rf .pytest_cache/ 2>/dev/null || true
	rm -rf .mypy_cache/ 2>/dev/null || true
	
	# Очистка временных файлов в корне
	rm -f *.log 2>/dev/null || true
	rm -f *.zip 2>/dev/null || true
	rm -f *.tmp 2>/dev/null || true

# Помощь
help:
	@echo "Доступные команды:"
	@echo "  install        - Установка зависимостей"
	@echo "  test           - Запуск тестов"
	@echo "  web            - Запуск веб-интерфейса"
	@echo "  cli            - Запуск CLI"
	@echo "  monitor        - Мониторинг системы"
	@echo "  test-resources - Тестирование системы ограничения ресурсов"
	@echo "  lint           - Проверка кода"
	@echo "  format         - Форматирование кода"
	@echo "  type-check     - Проверка типов"
	@echo "  clean          - Очистка временных файлов"
	@echo "  clean-all      - Полная очистка"
	@echo "  help           - Показать эту справку"
