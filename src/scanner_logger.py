#!/usr/bin/env python3
"""
Модуль для логирования сетевого сканера
"""
import logging
import logging.handlers
from pathlib import Path
from datetime import datetime
import os


class ScannerLogger:
    """Логгер для сетевого сканера с отдельным файлом"""
    
    def __init__(self, name: str = "network_scanner"):
        self.name = name
        self.logger = None
        self._setup_logger()
    
    def _setup_logger(self):
        """Настройка логгера для сканера"""
        # Создаем логгер
        self.logger = logging.getLogger(self.name)
        self.logger.setLevel(logging.DEBUG)
        
        # Очищаем существующие обработчики
        for handler in self.logger.handlers[:]:
            self.logger.removeHandler(handler)
        
        # Создаем папку для логов, если её нет
        logs_dir = Path("logs")
        logs_dir.mkdir(exist_ok=True)
        
        # Создаем файл для логов сканера
        scanner_log_file = logs_dir / "scanner.log"
        
        # Создаем обработчик файла с ротацией
        file_handler = logging.handlers.RotatingFileHandler(
            scanner_log_file,
            maxBytes=10*1024*1024,  # 10MB
            backupCount=5,
            encoding='utf-8'
        )
        file_handler.setLevel(logging.DEBUG)
        
        # Создаем форматтер
        formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S'
        )
        file_handler.setFormatter(formatter)
        
        # Добавляем обработчик к логгеру
        self.logger.addHandler(file_handler)
        
        # Также добавляем вывод в консоль для отладки
        console_handler = logging.StreamHandler()
        console_handler.setLevel(logging.INFO)
        console_handler.setFormatter(formatter)
        self.logger.addHandler(console_handler)
        
        # Логируем инициализацию
        self.logger.info(f"Логгер сканера инициализирован: {scanner_log_file}")
    
    def get_logger(self) -> logging.Logger:
        """Получить настроенный логгер"""
        return self.logger
    
    def log_scan_start(self, network: str, host_count: int):
        """Логировать начало сканирования"""
        self.logger.info(f"=== НАЧАЛО СКАНИРОВАНИЯ ===")
        self.logger.info(f"Сеть: {network}")
        self.logger.info(f"Количество хостов: {host_count}")
        self.logger.info(f"Время начала: {datetime.now()}")
    
    def log_scan_progress(self, current_host: int, total_hosts: int, host: str):
        """Логировать прогресс сканирования"""
        if total_hosts > 0:
            progress = (current_host / total_hosts) * 100
            self.logger.info(f"Прогресс: {progress:.1f}% ({current_host}/{total_hosts}) - Сканируем: {host}")
        else:
            self.logger.info(f"Прогресс: {current_host}/{total_hosts} - Сканируем: {host}")
    
    def log_host_result(self, host: str, open_ports: list, response_time: float = None):
        """Логировать результат сканирования хоста"""
        if open_ports:
            ports_str = ", ".join(map(str, open_ports))
            time_str = f" (время ответа: {response_time:.3f}s)" if response_time else ""
            self.logger.info(f"✓ {host}: найдены открытые порты [{ports_str}]{time_str}")
        else:
            self.logger.debug(f"✗ {host}: открытых портов не найдено")
    
    def log_port_scan(self, host: str, port: int, is_open: bool, banner: str = None):
        """Логировать сканирование отдельного порта"""
        if is_open:
            banner_info = f" - баннер: {banner}" if banner else ""
            self.logger.debug(f"  {host}:{port} - ОТКРЫТ{banner_info}")
        else:
            self.logger.debug(f"  {host}:{port} - закрыт")
    
    def log_scan_complete(self, total_hosts: int, active_hosts: int, scan_time: float):
        """Логировать завершение сканирования"""
        self.logger.info(f"=== ЗАВЕРШЕНИЕ СКАНИРОВАНИЯ ===")
        self.logger.info(f"Всего хостов: {total_hosts}")
        self.logger.info(f"Активных хостов: {active_hosts}")
        self.logger.info(f"Время сканирования: {scan_time:.2f} секунд")
        if scan_time > 0:
            speed = total_hosts / scan_time
            self.logger.info(f"Средняя скорость: {speed:.1f} хостов/сек")
        else:
            self.logger.info("Средняя скорость: не определена (время сканирования = 0)")
    
    def log_error(self, error: str, context: str = ""):
        """Логировать ошибку"""
        context_str = f" [{context}]" if context else ""
        self.logger.error(f"ОШИБКА{context_str}: {error}")
    
    def log_warning(self, warning: str, context: str = ""):
        """Логировать предупреждение"""
        context_str = f" [{context}]" if context else ""
        self.logger.warning(f"ПРЕДУПРЕЖДЕНИЕ{context_str}: {warning}")
    
    def log_resource_usage(self, cpu_percent: float, memory_percent: float):
        """Логировать использование ресурсов"""
        self.logger.debug(f"Ресурсы - CPU: {cpu_percent:.1f}%, RAM: {memory_percent:.1f}%")
    
    def log_batch_progress(self, batch_num: int, total_batches: int, batch_size: int):
        """Логировать прогресс обработки батчей"""
        self.logger.info(f"Батч {batch_num}/{total_batches} (размер: {batch_size})")
    
    def log_web_hosts_found(self, web_hosts: list):
        """Логировать найденные веб-хосты"""
        if web_hosts:
            self.logger.info(f"Найдено веб-хостов для скриншотов: {len(web_hosts)}")
            for host in web_hosts:
                self.logger.debug(f"  Веб-хост: {host}")
        else:
            self.logger.info("Веб-хостов для скриншотов не найдено")
    
    def log_discovery_start(self, total_hosts: int):
        """Логировать начало этапа обнаружения"""
        self.logger.info(f"=== ЭТАП 1: ОБНАРУЖЕНИЕ АКТИВНЫХ ХОСТОВ ===")
        self.logger.info(f"Начинаем обнаружение из {total_hosts} хостов...")
    
    def log_discovery_progress(self, current_host: int, total_hosts: int, host: str, is_active: bool):
        """Логировать прогресс обнаружения"""
        status = "✓" if is_active else "✗"
        self.logger.info(f"Обнаружение: {current_host}/{total_hosts} - {status} {host}")
    
    def log_discovery_complete(self, total_hosts: int, active_hosts: int):
        """Логировать завершение этапа обнаружения"""
        self.logger.info(f"=== ЗАВЕРШЕНИЕ ОБНАРУЖЕНИЯ ===")
        self.logger.info(f"Обнаружено {active_hosts} активных хостов из {total_hosts}")
        if total_hosts > 0:
            efficiency = (active_hosts / total_hosts) * 100
            self.logger.info(f"Эффективность обнаружения: {efficiency:.1f}%")
    
    def log_port_scan_start(self, active_hosts: int):
        """Логировать начало этапа сканирования портов"""
        self.logger.info(f"=== ЭТАП 2: СКАНИРОВАНИЕ ПОРТОВ ===")
        self.logger.info(f"Начинаем сканирование портов на {active_hosts} активных хостах...")


# Глобальный экземпляр логгера сканера
_scanner_logger_instance: ScannerLogger = None


def get_scanner_logger() -> ScannerLogger:
    """Получить глобальный экземпляр логгера сканера"""
    global _scanner_logger_instance
    if _scanner_logger_instance is None:
        _scanner_logger_instance = ScannerLogger()
    return _scanner_logger_instance


def get_scanner_logger_instance() -> logging.Logger:
    """Получить настроенный логгер для использования в других модулях"""
    return get_scanner_logger().get_logger()
