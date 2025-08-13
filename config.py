#!/usr/bin/env python3
"""
Конфигурация сетевого сканера с автоматической оптимизацией
"""

import logging
from dataclasses import dataclass, field
from typing import Dict, Optional
from pathlib import Path


@dataclass
class ScannerConfig:
    """Конфигурация сетевого сканера с автоматической оптимизацией"""

    # TCP сканирование - оптимизировано с ограничениями CPU
    probe_timeout: int = 2  # Увеличиваем до 2 секунд для снижения нагрузки
    web_timeout: int = 30   # Увеличиваем для лучшей работы с сертификатами

    # Веб-скриншоты - оптимизированные настройки с ограничениями
    viewport_width: int = 1280
    viewport_height: int = 720
    
    # Ограничения ресурсов (будут переопределены автоматической оптимизацией)
    max_cpu_percent: int = 90  # Максимальная загрузка CPU в процентах
    max_memory_mb: int = 2048   # Максимальное использование памяти в МБ (2GB)
    max_network_mbps: float = 100.0  # Максимальный сетевой трафик в МБ/с
    
    # Настройки потоков (будут переопределены автоматической оптимизацией)
    max_workers: int = 10  # Количество воркеров для обработки задач
    max_browsers: int = 3   # Количество браузеров для скриншотов
    max_concurrent_connections: int = 500  # Максимальное количество одновременных соединений
    
    # Настройки обнаружения хостов
    use_icmp_ping: bool = True  # Использовать ICMP ping как дополнительный метод
    discovery_timeout: float = 0.5  # Таймаут для TCP обнаружения в секундах

    # Логирование
    log_level: str = "INFO"
    log_file: str = "scanner.log"
    task_log_file: str = "task_manager.log"  # Отдельный лог для системы управления задачами

    # Пути для сохранения
    output_dir: Path = field(default_factory=lambda: Path("."))

    # Порты для сканирования с улучшенными пробами
    ports_tcp_probe: Dict[int, bytes] = field(
        default_factory=lambda: {
            22: b"SSH-2.0-OpenSSH_8.0\r\n",  # SSH - отправляем SSH версию для получения баннера
            80: b"HEAD / HTTP/1.0\r\n\r\n",
            443: b"",  # HTTPS
            135: b"",  # RPC
            139: b"",  # NetBIOS
            445: b"",  # SMB
            3389: b"",  # RDP
            5985: b"",  # WinRM HTTP
            5986: b"",  # WinRM HTTPS
            1433: b"",  # MSSQL
            3306: b"\x0a",  # MySQL - простой ping
            5432: b"\x00\x00\x00\x08\x04\xd2\x16\x2f",  # PostgreSQL startup message
            161: b"",  # SNMP
            # IP Phones
            10000: b"HEAD / HTTP/1.0\r\n\r\n",  # IP Phone web interface
            8080: b"HEAD / HTTP/1.0\r\n\r\n",  # Alternative web interface
            # IP Cameras
            554: b"OPTIONS rtsp://test.com/test RTSP/1.0\r\nCSeq: 1\r\n\r\n",  # RTSP OPTIONS
            8000: b"HEAD / HTTP/1.0\r\n\r\n",  # IP Camera web interface
            37777: b"HEAD / HTTP/1.0\r\n\r\n",  # Dahua cameras web interface
            37778: b"HEAD / HTTP/1.0\r\n\r\n",  # Dahua cameras web interface
        }
    )

    def __post_init__(self):
        """Валидация конфигурации после инициализации"""
        if self.probe_timeout <= 0:
            raise ValueError("probe_timeout должен быть положительным")
        if self.web_timeout <= 0:
            raise ValueError("web_timeout должен быть положительным")
        if self.max_browsers <= 0:
            raise ValueError("max_browsers должен быть положительным")
        if self.viewport_width <= 0 or self.viewport_height <= 0:
            raise ValueError("Размеры viewport должны быть положительными")

        # Создаем выходную директорию если не существует
        self.output_dir.mkdir(exist_ok=True)

    def setup_logging(self) -> None:
        """Настраивает логирование"""
        logging.basicConfig(
            level=getattr(logging, self.log_level),
            format="%(asctime)s - %(levelname)s - %(message)s",
            handlers=[
                logging.FileHandler(self.log_file, encoding="utf-8"),
                logging.StreamHandler(),  # Добавляем вывод в консоль
            ],
        )


def load_config(config_path: Optional[Path] = None) -> ScannerConfig:
    """Загружает конфигурацию из файла или возвращает по умолчанию"""
    if config_path and config_path.exists():
        # TODO: Добавить загрузку из YAML/JSON файла
        pass

    return ScannerConfig()


def get_optimized_config() -> ScannerConfig:
    """Получить оптимизированную конфигурацию на основе анализа системы"""
    try:
        from src.system_analyzer import get_optimized_config as get_system_config
        
        # Получаем оптимизированную конфигурацию
        optimized = get_system_config()
        
        # Создаем конфигурацию с оптимизированными параметрами
        config = ScannerConfig()
        config.max_workers = optimized.max_workers
        config.max_browsers = optimized.max_browsers
        config.max_cpu_percent = optimized.max_cpu_percent
        config.max_memory_mb = optimized.max_memory_mb
        config.max_network_mbps = optimized.max_network_mbps
        config.probe_timeout = optimized.probe_timeout
        config.web_timeout = optimized.web_timeout
        
        return config
        
    except Exception as e:
        logging.warning(f"Не удалось выполнить автоматическую оптимизацию: {e}")
        logging.info("Используются настройки по умолчанию")
        return ScannerConfig()
