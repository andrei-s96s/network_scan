#!/usr/bin/env python3
"""
Сетевой сканер с поддержкой мониторинга ресурсов
"""
import asyncio
import socket
import ipaddress
import logging
from typing import List, Dict, Set, Optional
from dataclasses import dataclass
from collections import deque
import time
from pathlib import Path
import sys

# Добавляем путь к src для импорта
sys.path.append(str(Path(__file__).parent.parent))

from config import ScannerConfig
from .resource_monitor import get_resource_limiter, get_resource_monitor
from .scanner_logger import get_scanner_logger_instance, get_scanner_logger

# Используем специальный логгер для сканера
logger = get_scanner_logger_instance()


@dataclass
class ScanResult:
    """Результат сканирования хоста"""
    host: str
    open_ports: List[int]
    banners: Dict[int, str]
    os_info: Optional[str] = None
    response_time: Optional[float] = None


class NetworkScanner:
    """Асинхронный сетевой сканер с ограничением ресурсов"""
    
    def __init__(self):
        self.config = ScannerConfig()
        self.semaphore = asyncio.Semaphore(self.config.max_concurrent_connections)
        self.response_times = deque(maxlen=200)
        self.adaptive_limits = {
            'max_concurrent': 500,
            'min_concurrent': 100,
            'adjustment_factor': 2.0
        }
        
        # Кэши для оптимизации
        self.dns_cache = {}
        self.connection_cache = {}
        
        # Мониторинг ресурсов
        self.resource_monitor = get_resource_monitor()
        self.resource_limiter = get_resource_limiter()
        
        # Callback для превышения лимитов
        self.resource_monitor.add_callback(self._on_resource_limit_exceeded)
        
    def _on_resource_limit_exceeded(self, is_over_limit: bool):
        """Callback при превышении лимитов ресурсов"""
        scanner_logger = get_scanner_logger()
        if is_over_limit:
            scanner_logger.log_warning("Высокая нагрузка на ресурсы - продолжаем сканирование")
        else:
            logger.info("Ресурсы восстановлены")
    
    async def probe_port_async(self, host: str, port: int) -> Optional[ScanResult]:
        """Асинхронная проверка порта с ограничением ресурсов"""
        async with self.resource_limiter:
            async with self.semaphore:
                try:
                    start_time = time.time()
                    
                    # Используем asyncio.open_connection для лучшей производительности
                    reader, writer = await asyncio.wait_for(
                        asyncio.open_connection(host, port),
                        timeout=self.config.probe_timeout
                    )
                    
                    response_time = time.time() - start_time
                    self.response_times.append(response_time)
                    
                    # Получаем баннер
                    banner = ""
                    try:
                        writer.write(b"HEAD / HTTP/1.1\r\nHost: " + host.encode() + b"\r\n\r\n")
                        await writer.drain()
                        
                        # Читаем ответ
                        data = await asyncio.wait_for(reader.read(1024), timeout=2.0)
                        if data:
                            banner = data.decode('utf-8', errors='ignore').strip()
                    except:
                        pass
                    
                    writer.close()
                    await writer.wait_closed()
                    
                    return ScanResult(
                        host=host,
                        open_ports=[port],
                        banners={port: banner},
                        response_time=response_time
                    )
                    
                except asyncio.TimeoutError:
                    return None
                except Exception as e:
                    logger.debug(f"Ошибка при сканировании {host}:{port}: {e}")
                    return None
    
    def _get_web_ports(self) -> Set[int]:
        """Получить список веб-портов для скриншотов"""
        return {80, 443, 8080, 8443, 9443, 3000, 5000, 8000, 9000}
    
    async def ping_host_async(self, host: str) -> bool:
        """Быстрая проверка доступности хоста (улучшенная)"""
        async with self.semaphore:
            # Порты для обнаружения разных типов устройств
            discovery_ports = [
                80,    # HTTP - веб-серверы, камеры, роутеры
                22,    # SSH - Linux серверы, сетевые устройства
                23,    # Telnet - старые устройства, камеры
                443,   # HTTPS - защищенные веб-сервисы
                3389,  # RDP - Windows серверы
                8080,  # Альтернативный HTTP - камеры, принтеры
                554,   # RTSP - IP камеры
                37777, # Dahua камеры
                37778, # Dahua камеры
                8000,  # Альтернативный HTTP - камеры
                9000,  # Альтернативный HTTP - камеры
            ]
            
            for port in discovery_ports:
                try:
                    reader, writer = await asyncio.wait_for(
                        asyncio.open_connection(host, port),
                        timeout=self.config.discovery_timeout
                    )
                    writer.close()
                    await writer.wait_closed()
                    logger.debug(f"Хост {host} обнаружен через порт {port}")
                    return True
                except:
                    continue
            
            # Если TCP не сработал, пробуем ICMP ping (если доступен)
            if self.config.use_icmp_ping:
                try:
                    return await self.icmp_ping_async(host)
                except Exception as e:
                    logger.debug(f"ICMP ping недоступен для {host}: {e}")
            
            return False
    
    async def icmp_ping_async(self, host: str) -> bool:
        """ICMP ping для обнаружения хостов"""
        try:
            # Используем subprocess для ping
            process = await asyncio.create_subprocess_exec(
                'ping', '-c', '1', '-W', '1', host,
                stdout=asyncio.subprocess.DEVNULL,
                stderr=asyncio.subprocess.DEVNULL
            )
            await asyncio.wait_for(process.wait(), timeout=2.0)
            return process.returncode == 0
        except:
            return False
    
    async def discover_active_hosts(self, hosts: List[str]) -> List[str]:
        """Обнаружение активных хостов в сети (улучшенное)"""
        scanner_logger = get_scanner_logger()
        
        # Логируем начало этапа обнаружения
        scanner_logger.log_discovery_start(len(hosts))
        
        # Создаем задачи для параллельного ping всех хостов
        ping_tasks = [self.ping_host_async(host) for host in hosts]
        
        # Выполняем все ping параллельно
        ping_results = await asyncio.gather(*ping_tasks, return_exceptions=True)
        
        # Собираем активные хосты
        active_hosts = []
        tcp_discovered = 0
        
        for i, is_active in enumerate(ping_results):
            host = hosts[i]
            if isinstance(is_active, Exception):
                logger.debug(f"Ошибка при TCP ping {host}: {is_active}")
                scanner_logger.log_discovery_progress(i + 1, len(hosts), host, False)
                continue
                
            if is_active:
                active_hosts.append(host)
                tcp_discovered += 1
                scanner_logger.log_discovery_progress(i + 1, len(hosts), host, True)
            else:
                logger.debug(f"Хост не отвечает на TCP: {host}")
                scanner_logger.log_discovery_progress(i + 1, len(hosts), host, False)
        
        # Дополнительная статистика
        logger.info(f"TCP обнаружение: {tcp_discovered} хостов из {len(hosts)}")
        
        # Логируем завершение этапа обнаружения
        scanner_logger.log_discovery_complete(len(hosts), len(active_hosts))
        return active_hosts
    
    async def scan_network_async(self, network: str) -> List[ScanResult]:
        """Асинхронное сканирование сети с ограничением ресурсов"""
        start_time = time.time()
        
        # Получаем специальный логгер для сканера
        scanner_logger = get_scanner_logger()
        
        try:
            # Парсим сеть
            network_obj = ipaddress.ip_network(network, strict=False)
            all_hosts = [str(host) for host in network_obj.hosts()]
            
            # Логируем начало сканирования
            scanner_logger.log_scan_start(network, len(all_hosts))
            
            # Логируем настройки параллелизма
            logger.info(f"Настройки параллелизма: max_concurrent_connections={self.config.max_concurrent_connections}, batch_size={200}")
            logger.info(f"Используется двухэтапное сканирование: обнаружение + сканирование портов")
            
            # ЭТАП 1: Обнаружение активных хостов
            active_hosts = await self.discover_active_hosts(all_hosts)
            
            if not active_hosts:
                logger.info("Активных хостов не обнаружено")
                return []
            
            # ЭТАП 2: Сканирование портов только на активных хостах
            scanner_logger.log_port_scan_start(len(active_hosts))
            
            # Создаем очередь для результатов
            results_queue = asyncio.Queue()
            web_ports = self._get_web_ports()
            
            # Функция для сканирования одного хоста
            async def scan_host(host: str):
                host_results = []
                open_ports = []
                
                # Сканируем основные порты ПАРАЛЛЕЛЬНО
                common_ports = [21, 22, 23, 25, 53, 80, 110, 143, 443, 993, 995, 8080, 8443]
                
                # Создаем задачи для параллельного сканирования всех портов хоста
                port_tasks = [self.probe_port_async(host, port) for port in common_ports]
                
                # Выполняем все порты параллельно
                port_results = await asyncio.gather(*port_tasks, return_exceptions=True)
                
                # Обрабатываем результаты
                for i, result in enumerate(port_results):
                    port = common_ports[i]
                    if isinstance(result, Exception):
                        scanner_logger.log_port_scan(host, port, False)
                        continue
                        
                    if result:
                        host_results.append(result)
                        open_ports.extend(result.open_ports)
                        # Логируем открытый порт
                        banner = result.banners.get(port, "")
                        scanner_logger.log_port_scan(host, port, True, banner)
                    else:
                        scanner_logger.log_port_scan(host, port, False)
                
                # Логируем результат сканирования хоста
                response_time = None
                if host_results:
                    response_time = host_results[0].response_time
                scanner_logger.log_host_result(host, open_ports, response_time)
                
                # Создаем один результат для хоста со всеми открытыми портами
                if host_results:
                    # Объединяем все баннеры
                    all_banners = {}
                    for result in host_results:
                        all_banners.update(result.banners)
                    
                    # Определяем OS info
                    os_info = None
                    for result in host_results:
                        if result.os_info and result.os_info != "Web server detected":
                            os_info = result.os_info
                            break
                    
                    # Проверяем наличие веб-портов
                    web_ports_found = []
                    for port in open_ports:
                        if port in web_ports:
                            web_ports_found.append(port)
                    
                    if web_ports_found:
                        os_info = "Web server detected"
                    
                    # Создаем единый результат для хоста
                    host_result = ScanResult(
                        host=host,
                        open_ports=open_ports,
                        banners=all_banners,
                        os_info=os_info,
                        response_time=response_time
                    )
                    await results_queue.put(host_result)
            
            # Запускаем сканирование с ограничением ресурсов
            batch_size = 200  # Увеличиваем размер батча для лучшей производительности
            total_batches = (len(active_hosts) + batch_size - 1) // batch_size
            
            for i in range(0, len(active_hosts), batch_size):
                batch = active_hosts[i:i + batch_size]
                batch_num = (i // batch_size) + 1
                
                # Логируем прогресс батча
                scanner_logger.log_batch_progress(batch_num, total_batches, len(batch))
                
                # Создаем задачи для батча
                batch_tasks = [scan_host(host) for host in batch]
                
                # Ждем завершения батча
                await asyncio.gather(*batch_tasks, return_exceptions=True)
                
                # Проверяем ресурсы между батчами
                usage = self.resource_monitor.get_current_usage()
                scanner_logger.log_resource_usage(usage['cpu_percent'], usage['memory_percent'])
                
                if usage['cpu_percent'] > self.config.max_cpu_percent:
                    scanner_logger.log_warning(f"CPU: {usage['cpu_percent']:.1f}% - пауза для снижения нагрузки")
                    await asyncio.sleep(1)
            
            # Собираем результаты
            results = []
            while not results_queue.empty():
                result = await results_queue.get()
                results.append(result)
            
            # Логируем завершение сканирования
            scan_time = time.time() - start_time
            scanner_logger.log_scan_complete(len(all_hosts), len(results), scan_time)
            
            # Дополнительная статистика по этапам
            logger.info(f"Статистика двухэтапного сканирования:")
            logger.info(f"  Всего хостов в сети: {len(all_hosts)}")
            logger.info(f"  Обнаружено активных: {len(active_hosts)}")
            logger.info(f"  Найдено с открытыми портами: {len(results)}")
            if len(all_hosts) > 0:
                efficiency = (len(active_hosts) / len(all_hosts)) * 100
                logger.info(f"  Эффективность обнаружения: {efficiency:.1f}%")
            else:
                logger.warning("  Нет хостов для сканирования в сети")
            
            return results
            
        except Exception as e:
            scanner_logger.log_error(str(e), f"сканирование сети {network}")
            return []
    
    async def get_web_ports_for_screenshots(self, scan_results: List[ScanResult]) -> List[str]:
        """Получить список хостов с веб-портами для создания скриншотов"""
        web_hosts = []
        web_ports = self._get_web_ports()
        
        for result in scan_results:
            # Создаем скриншоты для всех веб-портов хоста
            for port in result.open_ports:
                if port in web_ports:
                    protocol = "https" if port in [443, 8443, 9443] else "http"
                    web_hosts.append(f"{protocol}://{result.host}:{port}")
        
        # Логируем найденные веб-хосты
        scanner_logger = get_scanner_logger()
        scanner_logger.log_web_hosts_found(web_hosts)
        
        return web_hosts


# Глобальный экземпляр сканера
_scanner_instance: Optional[NetworkScanner] = None


def get_network_scanner() -> NetworkScanner:
    """Получить глобальный экземпляр сетевого сканера"""
    global _scanner_instance
    if _scanner_instance is None:
        _scanner_instance = NetworkScanner()
    return _scanner_instance
