# Используем Python 3.11 как базовый образ
FROM python:3.11-slim

# Устанавливаем метаданные
LABEL maintainer="Network Scanner Team"
LABEL description="Network Scanner with Web Interface"
LABEL version="1.0.0"

# Устанавливаем системные зависимости
RUN apt-get update && apt-get install -y --no-install-recommends \
    # Build tools for psutil
    gcc \
    python3-dev \
    # System utilities
    curl \
    wget \
    ca-certificates \
    iputils-ping \
    net-tools \
    procps \
    # Playwright/Chromium runtime deps
    libnss3 \
    libnspr4 \
    libatk1.0-0 \
    libatk-bridge2.0-0 \
    libcups2 \
    libdrm2 \
    libdbus-1-3 \
    libxkbcommon0 \
    libatspi2.0-0 \
    libxcomposite1 \
    libxdamage1 \
    libxfixes3 \
    libxrandr2 \
    libgbm1 \
    libasound2 \
    libpangocairo-1.0-0 \
    libpango-1.0-0 \
    libcairo2 \
    libx11-6 \
    libx11-xcb1 \
    libxcb1 \
    libxext6 \
    libxshmfence1 \
    libxrender1 \
    libfontconfig1 \
    # Fonts
    fonts-liberation \
    fonts-unifont \
    fonts-noto \
    fonts-noto-color-emoji \
    && rm -rf /var/lib/apt/lists/*

# Создаем рабочую директорию
WORKDIR /app

# Копируем файлы зависимостей
COPY requirements.txt .
COPY pyproject.toml .
COPY mypy.ini .

# Устанавливаем Python зависимости
RUN pip install --no-cache-dir -r requirements.txt

# Clean up build tools after pip install
RUN apt-get update && apt-get remove -y gcc python3-dev && apt-get autoremove -y && rm -rf /var/lib/apt/lists/*

# Устанавливаем Playwright браузеры
RUN playwright install chromium

# Копируем исходный код
COPY src/ ./src/
COPY static/ ./static/
COPY templates/ ./templates/
COPY scripts/ ./scripts/
COPY config.py .
COPY main.py .

# Создаем необходимые директории
RUN mkdir -p logs results reports

# Создаем пользователя для безопасности
RUN useradd -m -u 1000 scanner && \
    chown -R scanner:scanner /app

# Переключаемся на пользователя scanner
USER scanner

# Открываем порт для веб-интерфейса
EXPOSE 5000

# Устанавливаем переменные окружения
ENV PYTHONPATH=/app
ENV FLASK_APP=src.task_web
ENV FLASK_ENV=production

# Создаем healthcheck
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:5000/api/health || exit 1

# Команда по умолчанию - запуск веб-интерфейса
CMD ["python", "-m", "src.task_web"]
