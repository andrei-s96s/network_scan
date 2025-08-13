"""
Модуль для мониторинга и ограничения ресурсов системы
"""
import psutil
import asyncio
import logging
from typing import Optional, Callable
from dataclasses import dataclass
from threading import Lock
import time
import threading

logger = logging.getLogger(__name__)


@dataclass
class ResourceLimits:
    """Настройки ограничений ресурсов"""
    max_cpu_percent: int = 70
    max_memory_mb: int = 512
    max_network_mbps: float = 10.0  # Максимум сетевого трафика в МБ/с
    check_interval: float = 1.0  # Интервал проверки в секундах


class ResourceMonitor:
    """Мониторинг и ограничение ресурсов системы"""
    
    def __init__(self, limits: ResourceLimits):
        self.limits = limits
        self._lock = Lock()
        self._is_monitoring = False
        self._current_connections = 0
        self._callbacks = []
        
        # Для мониторинга сетевого трафика
        self._last_network_stats = None
        self._network_traffic_mbps = 0.0
        
    def add_callback(self, callback: Callable[[bool], None]):
        """Добавить callback для уведомления о превышении лимитов"""
        with self._lock:
            self._callbacks.append(callback)
    
    def _get_network_traffic(self) -> float:
        """Получить текущий сетевой трафик в МБ/с"""
        try:
            current_stats = psutil.net_io_counters()
            
            if self._last_network_stats is None:
                self._last_network_stats = current_stats
                return 0.0
            
            # Вычисляем разницу в байтах
            bytes_sent_diff = current_stats.bytes_sent - self._last_network_stats.bytes_sent
            bytes_recv_diff = current_stats.bytes_recv - self._last_network_stats.bytes_recv
            
            # Общий трафик в байтах
            total_bytes = bytes_sent_diff + bytes_recv_diff
            
            # Конвертируем в МБ/с
            mbps = (total_bytes / 1024 / 1024) / self.limits.check_interval
            
            # Обновляем статистику
            self._last_network_stats = current_stats
            self._network_traffic_mbps = mbps
            
            return mbps
            
        except Exception as e:
            logger.error(f"Ошибка при получении сетевого трафика: {e}")
            return 0.0
    
    def get_current_usage(self) -> dict:
        """Получить текущее использование ресурсов"""
        cpu_percent = psutil.cpu_percent(interval=0.1)
        memory = psutil.virtual_memory()
        memory_mb = memory.used / (1024 * 1024)
        network_mbps = self._get_network_traffic()
        
        return {
            'cpu_percent': cpu_percent,
            'memory_mb': memory_mb,
            'memory_percent': memory.percent,
            'network_mbps': network_mbps,
            'connections': self._current_connections  # Оставляем для обратной совместимости
        }
    
    def is_over_limit(self) -> bool:
        """Проверить, превышены ли лимиты ресурсов (только для логирования)"""
        usage = self.get_current_usage()
        
        # Проверяем только для логирования, не блокируем работу
        over_cpu = usage['cpu_percent'] > self.limits.max_cpu_percent
        over_memory = usage['memory_mb'] > self.limits.max_memory_mb
        over_network = usage['network_mbps'] > self.limits.max_network_mbps
        
        # Возвращаем True только если все лимиты превышены (для логирования)
        return over_cpu and over_memory and over_network
    
    def acquire_connection(self) -> bool:
        """Попытаться получить разрешение на новое соединение"""
        with self._lock:
            # Используем фиксированный лимит соединений для обратной совместимости
            max_connections = 100
            if self._current_connections < max_connections:
                self._current_connections += 1
                return True
            return False
    
    def release_connection(self):
        """Освободить соединение"""
        with self._lock:
            if self._current_connections > 0:
                self._current_connections -= 1
    
    async def start_monitoring(self):
        """Запустить мониторинг ресурсов"""
        if self._is_monitoring:
            return
            
        self._is_monitoring = True
        logger.info("Запуск мониторинга ресурсов")
        
        while self._is_monitoring:
            try:
                usage = self.get_current_usage()
                over_limit = self.is_over_limit()
                
                if over_limit:
                    logger.warning(
                        f"Превышение лимитов ресурсов: "
                        f"CPU: {usage['cpu_percent']:.1f}%, "
                        f"Memory: {usage['memory_mb']:.1f}MB, "
                        f"Network: {usage['network_mbps']:.2f}MB/s"
                    )
                    
                    # Уведомить все callbacks
                    with self._lock:
                        for callback in self._callbacks:
                            try:
                                callback(True)  # True = превышение лимитов
                            except Exception as e:
                                logger.error(f"Ошибка в callback: {e}")
                
                await asyncio.sleep(self.limits.check_interval)
                
            except Exception as e:
                logger.error(f"Ошибка мониторинга ресурсов: {e}")
                await asyncio.sleep(self.limits.check_interval)
    
    def start_monitoring_with_socketio(self, socketio):
        """Запустить мониторинг ресурсов с отправкой данных через SocketIO"""
        if self._is_monitoring:
            return
            
        self._is_monitoring = True
        logger.info("Запуск мониторинга ресурсов с SocketIO")
        
        def monitor_loop():
            while self._is_monitoring:
                try:
                    usage = self.get_current_usage()
                    over_limit = self.is_over_limit()
                    
                    # Отправляем данные через SocketIO
                    socketio.emit('resource_usage', {
                        'cpu_percent': usage['cpu_percent'],
                        'memory_mb': usage['memory_mb'],
                        'memory_percent': usage['memory_percent'],
                        'network_mbps': usage['network_mbps'],
                        'connections': usage['connections'],  # Для обратной совместимости
                        'timestamp': time.time()
                    })
                    
                    if over_limit:
                        logger.warning(
                            f"Превышение лимитов ресурсов: "
                            f"CPU: {usage['cpu_percent']:.1f}%, "
                            f"Memory: {usage['memory_mb']:.1f}MB, "
                            f"Network: {usage['network_mbps']:.2f}MB/s"
                        )
                        
                        # Уведомить все callbacks
                        with self._lock:
                            for callback in self._callbacks:
                                try:
                                    callback(True)  # True = превышение лимитов
                                except Exception as e:
                                    logger.error(f"Ошибка в callback: {e}")
                    
                    time.sleep(self.limits.check_interval)
                    
                except Exception as e:
                    logger.error(f"Ошибка мониторинга ресурсов: {e}")
                    time.sleep(5)
        
        monitor_thread = threading.Thread(target=monitor_loop, daemon=True)
        monitor_thread.start()
        return monitor_thread
    
    def stop_monitoring(self):
        """Остановить мониторинг ресурсов"""
        self._is_monitoring = False
        logger.info("Остановка мониторинга ресурсов")


class ResourceLimiter:
    """Контекстный менеджер для ограничения ресурсов"""
    
    def __init__(self, monitor: ResourceMonitor):
        self.monitor = monitor
        self._acquired = False
    
    async def __aenter__(self):
        """Попытаться получить ресурсы"""
        while not self.monitor.acquire_connection():
            # Ждем освобождения ресурсов
            await asyncio.sleep(0.1)
        
        self._acquired = True
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Освободить ресурсы"""
        if self._acquired:
            self.monitor.release_connection()
            self._acquired = False


# Глобальный экземпляр мониторинга
_global_monitor: Optional[ResourceMonitor] = None


def get_resource_monitor() -> ResourceMonitor:
    """Получить глобальный экземпляр мониторинга ресурсов"""
    global _global_monitor
    if _global_monitor is None:
        from config import ScannerConfig
        limits = ResourceLimits(
            max_cpu_percent=ScannerConfig.max_cpu_percent,
            max_memory_mb=ScannerConfig.max_memory_mb,
            max_network_mbps=ScannerConfig.max_network_mbps
        )
        _global_monitor = ResourceMonitor(limits)
    return _global_monitor


def get_resource_limiter() -> ResourceLimiter:
    """Получить лимитер ресурсов"""
    return ResourceLimiter(get_resource_monitor())
