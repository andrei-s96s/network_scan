#!/bin/bash

# Скрипт для сборки и запуска Network Scanner в Docker

set -e

echo "🐳 Сборка и запуск Network Scanner в Docker"

# Цвета для вывода
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Функция для вывода с цветом
print_status() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Проверяем наличие Docker
if ! command -v docker &> /dev/null; then
    print_error "Docker не установлен. Установите Docker и попробуйте снова."
    exit 1
fi

# Проверяем наличие docker-compose
if ! command -v docker-compose &> /dev/null; then
    print_error "Docker Compose не установлен. Установите Docker Compose и попробуйте снова."
    exit 1
fi

# Создаем необходимые директории
print_status "Создание директорий для результатов..."
mkdir -p results logs reports

# Останавливаем существующие контейнеры
print_status "Остановка существующих контейнеров..."
docker-compose down 2>/dev/null || true

# Собираем образ
print_status "Сборка Docker образа..."
docker-compose build --no-cache

# Запускаем контейнеры
print_status "Запуск контейнеров..."
docker-compose up -d

# Ждем запуска
print_status "Ожидание запуска сервиса..."
sleep 10

# Проверяем статус
print_status "Проверка статуса контейнеров..."
docker-compose ps

# Проверяем health check
print_status "Проверка health check..."
for i in {1..30}; do
    if curl -f http://localhost:5000/api/health >/dev/null 2>&1; then
        print_success "Сервис запущен и работает!"
        break
    fi
    if [ $i -eq 30 ]; then
        print_error "Сервис не запустился в течение 30 секунд"
        docker-compose logs
        exit 1
    fi
    sleep 1
done

# Показываем информацию
print_success "Network Scanner успешно запущен!"
echo ""
echo "🌐 Веб-интерфейс: http://localhost:5000"
echo "📊 Health check: http://localhost:5000/api/health"
echo "📁 Результаты: ./results/"
echo "📝 Логи: ./logs/"
echo ""
echo "Команды для управления:"
echo "  docker-compose logs -f    # Просмотр логов"
echo "  docker-compose down       # Остановка"
echo "  docker-compose restart    # Перезапуск"
echo ""

# Показываем логи
print_status "Последние логи:"
docker-compose logs --tail=20
