.PHONY: help install test lint format type-check security-check clean run demo

# Переменные
PYTHON = python
PIP = pip
PYTEST = pytest
FLAKE8 = flake8
BLACK = black
MYPY = mypy
BANDIT = bandit
SAFETY = safety

# Цвета для вывода
GREEN = \033[0;32m
YELLOW = \033[1;33m
RED = \033[0;31m
NC = \033[0m # No Color

help: ## Показать справку
	@echo "$(GREEN)Доступные команды:$(NC)"
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "  $(YELLOW)%-20s$(NC) %s\n", $$1, $$2}'

install: ## Установить зависимости
	@echo "$(GREEN)Установка зависимостей...$(NC)"
	$(PIP) install -r requirements.txt
	@echo "$(GREEN)Установка браузеров Playwright...$(NC)"
	playwright install chromium

test: ## Запустить тесты
	@echo "$(GREEN)Запуск тестов...$(NC)"
	$(PYTEST) tests/ -v --cov=. --cov-report=html --cov-report=term-missing

test-fast: ## Быстрые тесты без покрытия
	@echo "$(GREEN)Запуск быстрых тестов...$(NC)"
	$(PYTEST) tests/ -v

lint: ## Проверка стиля кода
	@echo "$(GREEN)Проверка стиля кода...$(NC)"
	$(FLAKE8) config.py network_scanner.py screenshot_manager.py report_generator.py main.py tests/

format: ## Форматирование кода
	@echo "$(GREEN)Форматирование кода...$(NC)"
	$(BLACK) config.py network_scanner.py screenshot_manager.py report_generator.py main.py tests/

type-check: ## Проверка типов
	@echo "$(GREEN)Проверка типов...$(NC)"
	$(MYPY) config.py network_scanner.py screenshot_manager.py report_generator.py main.py

security-check: ## Проверка безопасности
	@echo "$(GREEN)Проверка безопасности...$(NC)"
	$(BANDIT) -r .
	$(SAFETY) check

check-all: ## Полная проверка проекта
	@echo "$(GREEN)Полная проверка проекта...$(NC)"
	@$(MAKE) lint
	@$(MAKE) type-check
	@$(MAKE) security-check
	@$(MAKE) test

clean: ## Очистка временных файлов
	@echo "$(GREEN)Очистка временных файлов...$(NC)"
	find . -type f -name "*.pyc" -delete
	find . -type d -name "__pycache__" -delete
	find . -type d -name "*.egg-info" -exec rm -rf {} +
	find . -type d -name ".pytest_cache" -exec rm -rf {} +
	find . -type d -name "htmlcov" -exec rm -rf {} +
	find . -type f -name ".coverage" -delete
	find . -type f -name "*.log" -delete
	find . -type f -name "scan-*.txt" -delete
	find . -type f -name "scan-*.json" -delete
	find . -type f -name "scan-*.html" -delete
	find . -type d -name "web" -exec rm -rf {} +

run: ## Запуск сканера (пример)
	@echo "$(GREEN)Запуск сканера...$(NC)"
	@echo "$(YELLOW)Пример: make run NETWORK=192.168.1.0/24 THREADS=10$(NC)"
	$(PYTHON) main.py $(NETWORK) $(THREADS)

demo: ## Демонстрация работы
	@echo "$(GREEN)Демонстрация работы сканера...$(NC)"
	@echo "$(YELLOW)Сканирование локальной сети...$(NC)"
	$(PYTHON) main.py 127.0.0.1/32 1 --verbose

install-dev: ## Установка для разработки
	@echo "$(GREEN)Установка для разработки...$(NC)"
	$(PIP) install -r requirements.txt
	$(PIP) install -e .
	playwright install chromium

setup: ## Настройка проекта
	@echo "$(GREEN)Настройка проекта...$(NC)"
	@$(MAKE) install
	@$(MAKE) format
	@$(MAKE) check-all

# Команды для CI/CD
ci-test: ## Тесты для CI
	$(PYTEST) tests/ --cov=. --cov-report=xml --cov-report=term-missing

ci-lint: ## Линтинг для CI
	$(FLAKE8) config.py network_scanner.py screenshot_manager.py report_generator.py main.py tests/

ci-type: ## Проверка типов для CI
	$(MYPY) config.py network_scanner.py screenshot_manager.py report_generator.py main.py

ci-security: ## Безопасность для CI
	$(BANDIT) -r . -f json -o bandit-report.json
	$(SAFETY) check --json --output safety-report.json

# Дополнительные команды
docs: ## Генерация документации
	@echo "$(GREEN)Генерация документации...$(NC)"
	@echo "$(YELLOW)Документация доступна в README.md$(NC)"

benchmark: ## Бенчмарк производительности
	@echo "$(GREEN)Запуск бенчмарка...$(NC)"
	@echo "$(YELLOW)Сканирование сети /24 с 20 потоками...$(NC)"
	time $(PYTHON) main.py 192.168.1.0/24 20 --no-reports

profile: ## Профилирование кода
	@echo "$(GREEN)Профилирование кода...$(NC)"
	$(PYTHON) -m cProfile -o profile.stats main.py 127.0.0.1/32 1
	$(PYTHON) -c "import pstats; p = pstats.Stats('profile.stats'); p.sort_stats('cumulative').print_stats(20)"

# Команды для релиза
release: ## Подготовка к релизу
	@echo "$(GREEN)Подготовка к релизу...$(NC)"
	@$(MAKE) check-all
	@$(MAKE) clean
	@echo "$(GREEN)Все проверки пройдены!$(NC)"

.PHONY: help install test lint format type-check security-check clean run demo install-dev setup ci-test ci-lint ci-type ci-security docs benchmark profile release
