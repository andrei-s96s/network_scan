#!/usr/bin/env python3
"""
Автоматический анализатор системы для оптимальной настройки потоков
"""

import psutil
import logging
from typing import Dict, Any
from dataclasses import dataclass

logger = logging.getLogger(__name__)


@dataclass
class SystemInfo:
    """Информация о системе"""
    cpu_count: int
    cpu_freq_mhz: float
    memory_total_gb: float
    memory_available_gb: float
    disk_free_gb: float
    network_speed_mbps: float = 100.0  # По умолчанию 100 МБ/с


@dataclass
class OptimizedConfig:
    """Оптимизированная конфигурация на основе анализа системы"""
    max_workers: int
    max_browsers: int
    max_memory_mb: int
    max_cpu_percent: int = 90
    max_network_mbps: float = 100.0
    probe_timeout: int = 2
    web_timeout: int = 30


class SystemAnalyzer:
    """Анализатор системы для автоматической настройки"""
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)
    
    def analyze_system(self) -> SystemInfo:
        """Анализирует систему и возвращает информацию"""
        try:
            # CPU информация
            cpu_count = psutil.cpu_count(logical=True)
            cpu_freq = psutil.cpu_freq()
            cpu_freq_mhz = cpu_freq.current if cpu_freq else 2000.0
            
            # Память
            memory = psutil.virtual_memory()
            memory_total_gb = memory.total / (1024**3)
            memory_available_gb = memory.available / (1024**3)
            
            # Диск
            disk = psutil.disk_usage('/')
            disk_free_gb = disk.free / (1024**3)
            
            # Сетевая скорость (оценка)
            network_speed_mbps = self._estimate_network_speed()
            
            system_info = SystemInfo(
                cpu_count=cpu_count,
                cpu_freq_mhz=cpu_freq_mhz,
                memory_total_gb=memory_total_gb,
                memory_available_gb=memory_available_gb,
                disk_free_gb=disk_free_gb,
                network_speed_mbps=network_speed_mbps
            )
            
            self.logger.info(f"Анализ системы завершен:")
            self.logger.info(f"  CPU: {cpu_count} ядер, {cpu_freq_mhz:.0f} МГц")
            self.logger.info(f"  RAM: {memory_total_gb:.1f} GB (доступно: {memory_available_gb:.1f} GB)")
            self.logger.info(f"  Диск: {disk_free_gb:.1f} GB свободно")
            self.logger.info(f"  Сеть: {network_speed_mbps:.1f} МБ/с")
            
            return system_info
            
        except Exception as e:
            self.logger.error(f"Ошибка при анализе системы: {e}")
            # Возвращаем безопасные значения по умолчанию
            return SystemInfo(
                cpu_count=2,
                cpu_freq_mhz=2000.0,
                memory_total_gb=4.0,
                memory_available_gb=2.0,
                disk_free_gb=10.0,
                network_speed_mbps=100.0
            )
    
    def _estimate_network_speed(self) -> float:
        """Оценивает скорость сети"""
        try:
            # Простая оценка на основе интерфейсов
            net_io = psutil.net_io_counters()
            # Оцениваем как 100 МБ/с для большинства случаев
            return 100.0
        except:
            return 100.0
    
    def optimize_config(self, system_info: SystemInfo) -> OptimizedConfig:
        """Оптимизирует конфигурацию на основе анализа системы"""
        
        # Определяем тип сервера
        server_type = self._classify_server(system_info)
        
        # Настраиваем параметры в зависимости от типа сервера
        if server_type == "powerful":
            max_workers = min(system_info.cpu_count * 2, 20)
            max_browsers = min(system_info.cpu_count, 8)
            max_memory_mb = int(system_info.memory_available_gb * 1024 * 0.8)  # 80% доступной памяти
            self.logger.info("Тип сервера: МОЩНЫЙ")
            
        elif server_type == "medium":
            max_workers = min(system_info.cpu_count, 10)
            max_browsers = min(system_info.cpu_count // 2, 4)
            max_memory_mb = int(system_info.memory_available_gb * 1024 * 0.7)  # 70% доступной памяти
            self.logger.info("Тип сервера: СРЕДНИЙ")
            
        elif server_type == "weak":
            max_workers = max(system_info.cpu_count // 2, 3)
            max_browsers = max(system_info.cpu_count // 2, 2)
            max_memory_mb = int(system_info.memory_available_gb * 1024 * 0.6)  # 60% доступной памяти
            self.logger.info("Тип сервера: СЛАБЫЙ")
            
        else:  # very_weak
            max_workers = max(system_info.cpu_count // 2, 2)
            max_browsers = 1
            max_memory_mb = int(system_info.memory_available_gb * 1024 * 0.5)  # 50% доступной памяти
            self.logger.info("Тип сервера: ОЧЕНЬ СЛАБЫЙ")
        
        # Ограничиваем максимальные значения
        max_workers = min(max_workers, 20)
        max_browsers = min(max_browsers, 8)
        max_memory_mb = min(max_memory_mb, 8192)  # Максимум 8GB
        
        config = OptimizedConfig(
            max_workers=max_workers,
            max_browsers=max_browsers,
            max_memory_mb=max_memory_mb,
            max_network_mbps=system_info.network_speed_mbps
        )
        
        self.logger.info(f"Оптимизированная конфигурация:")
        self.logger.info(f"  Воркеры: {max_workers}")
        self.logger.info(f"  Браузеры: {max_browsers}")
        self.logger.info(f"  Максимум RAM: {max_memory_mb} MB")
        self.logger.info(f"  Максимум CPU: {config.max_cpu_percent}%")
        self.logger.info(f"  Сетевой трафик: {config.max_network_mbps} МБ/с")
        
        return config
    
    def _classify_server(self, system_info: SystemInfo) -> str:
        """Классифицирует сервер по мощности"""
        
        # Критерии классификации
        cpu_score = system_info.cpu_count * (system_info.cpu_freq_mhz / 2000.0)
        memory_score = system_info.memory_total_gb
        combined_score = cpu_score * memory_score
        
        if combined_score >= 64:  # 8 ядер * 3 ГГц * 8 GB = 192
            return "powerful"
        elif combined_score >= 32:  # 4 ядра * 2.5 ГГц * 8 GB = 80
            return "medium"
        elif combined_score >= 16:  # 2 ядра * 2 ГГц * 4 GB = 16
            return "weak"
        else:
            return "very_weak"


def get_optimized_config() -> OptimizedConfig:
    """Получить оптимизированную конфигурацию на основе анализа системы"""
    analyzer = SystemAnalyzer()
    system_info = analyzer.analyze_system()
    return analyzer.optimize_config(system_info)
