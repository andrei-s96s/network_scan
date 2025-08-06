#!/usr/bin/env python3
"""
Конфигурация сетевого сканера
"""

import logging
from dataclasses import dataclass, field
from typing import Dict, Optional
from pathlib import Path


@dataclass
class ScannerConfig:
    """Конфигурация сетевого сканера с улучшенной типизацией"""

    # TCP сканирование
    probe_timeout: int = 5
    web_timeout: int = 10

    # Веб-скриншоты
    viewport_width: int = 1280
    viewport_height: int = 720
    max_browsers: int = 3

    # Логирование
    log_level: str = "INFO"
    log_file: str = "scanner.log"

    # Пути для сохранения
    output_dir: Path = field(default_factory=lambda: Path("."))

    # Порты для сканирования с улучшенными пробами
    ports_tcp_probe: Dict[int, bytes] = field(
        default_factory=lambda: {
            22: b"",  # SSH
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
            5060: b"OPTIONS sip:test@test.com SIP/2.0\r\nVia: SIP/2.0/UDP test.com\r\nFrom: <sip:test@test.com>\r\nTo: <sip:test@test.com>\r\nCall-ID: test@test.com\r\nCSeq: 1 OPTIONS\r\n\r\n",
            5061: b"OPTIONS sip:test@test.com SIP/2.0\r\nVia: SIP/2.0/TLS test.com\r\nFrom: <sip:test@test.com>\r\nTo: <sip:test@test.com>\r\nCall-ID: test@test.com\r\nCSeq: 1 OPTIONS\r\n\r\n",
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
