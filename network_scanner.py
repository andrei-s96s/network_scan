#!/usr/bin/env python3
"""
Оптимизированный сетевой сканер с асинхронным сканированием
"""

import socket
import logging
import asyncio
import time
from typing import Dict, Optional, List, Tuple
from dataclasses import dataclass
from concurrent.futures import ThreadPoolExecutor
import threading
from collections import deque

from config import ScannerConfig


@dataclass
class ScanResult:
    """Результат сканирования одного хоста"""

    ip: str
    open_ports: Dict[int, str]
    detected_os: Optional[str] = None
    screenshots_count: int = 0
    scan_time: float = 0.0  # Время сканирования в секундах

    def __post_init__(self):
        """Валидация результата"""
        if not self.ip:
            raise ValueError("IP адрес не может быть пустым")
        if not isinstance(self.open_ports, dict):
            raise ValueError("open_ports должен быть словарем")


class AsyncNetworkScanner:
    """Асинхронный сетевой сканер с умной регулировкой потоков"""

    def __init__(self, config: ScannerConfig):
        self.config = config
        self.logger = logging.getLogger(__name__)
        self.semaphore = None
        self.connection_pool = {}
        self.performance_metrics = {
            'total_connections': 0,
            'successful_connections': 0,
            'failed_connections': 0,
            'avg_response_time': 0.0,
            'response_times': deque(maxlen=100)
        }
        self.adaptive_limits = {
            'max_concurrent': 50,
            'min_concurrent': 10,
            'adjustment_factor': 1.2
        }

    def create_snmp_get_request(
        self, community: str = "public", oid: str = "1.3.6.1.2.1.1.1.0"
    ) -> bytes:
        """Создает SNMP GET-REQUEST пакет"""
        # Простой SNMP v1 GET-REQUEST
        sequence = b"\x30"
        version = b"\x02\x01\x00"

        community_bytes = community.encode("ascii")
        community_len = len(community_bytes)
        community_octet = b"\x04" + bytes([community_len]) + community_bytes

        pdu_type = b"\xa0"  # GET-REQUEST

        request_id = b"\x02\x01\x01"
        error_status = b"\x02\x01\x00"
        error_index = b"\x02\x01\x00"

        # OID
        oid_parts = [int(x) for x in oid.split(".")]
        oid_bytes = b""
        for part in oid_parts:
            if part < 128:
                oid_bytes += bytes([part])
            else:
                # Для больших чисел используем два байта
                oid_bytes += bytes([128 | (part >> 7), part & 127])

        oid_len = len(oid_bytes)
        oid_octet = b"\x06" + bytes([oid_len]) + oid_bytes

        # NULL value
        null_value = b"\x05\x00"

        # Собираем PDU
        pdu_content = request_id + error_status + error_index + oid_octet + null_value
        pdu = pdu_type + bytes([len(pdu_content)]) + pdu_content

        # Собираем сообщение
        message_content = version + community_octet + pdu
        message = sequence + bytes([len(message_content)]) + message_content

        return message

    def detect_os_from_banner(self, banner: str, port: int) -> Optional[str]:
        """Определяет ОС по баннеру сервиса"""
        banner_lower = banner.lower()

        # Windows
        if any(x in banner_lower for x in ["microsoft", "iis", "exchange", "windows"]):
            return "Windows"
        if port in [135, 139, 445] and any(
            x in banner_lower for x in ["smb", "netbios", "microsoft"]
        ):
            return "Windows"
        if port in [3389] and "rdp" in banner_lower:
            return "Windows"
        if port in [5985, 5986] and "winrm" in banner_lower:
            return "Windows"

        # Linux
        if any(
            x in banner_lower
            for x in ["ubuntu", "debian", "centos", "redhat", "fedora"]
        ):
            return "Linux"
        if "openssh" in banner_lower:
            return "Linux"
        if any(x in banner_lower for x in ["apache", "nginx"]) and port in [80, 443]:
            return "Linux"

        # Unix
        if any(x in banner_lower for x in ["freebsd", "openbsd", "netbsd", "solaris"]):
            return "Unix"

        # Network devices
        if port == 161 and "public" in banner_lower:
            return "Network Device"

        # IP Phones
        if port in [5060, 5061] and "sip" in banner_lower:
            return "IP Phone"
        if port == 10000 and any(
            x in banner_lower for x in ["phone", "sip", "asterisk"]
        ):
            return "IP Phone"

        # IP Cameras
        if port == 554 and "rtsp" in banner_lower:
            return "IP Camera"
        if port in [8000, 37777, 37778] and any(
            x in banner_lower for x in ["camera", "dahua", "hikvision"]
        ):
            return "IP Camera"

        # Определение по портам (если баннер не содержит явных признаков)
        if port == 22:  # SSH
            return "Linux"  # SSH обычно на Linux/Unix системах
        elif port in [135, 139, 445]:  # Windows-специфичные порты
            return "Windows"
        elif port == 3389:  # RDP
            return "Windows"
        elif port in [5985, 5986]:  # WinRM
            return "Windows"

        return None

    async def probe_port_async(self, ip: str, port: int) -> Tuple[int, Optional[str]]:
        """Асинхронно проверяет один порт"""
        try:
            # Создаем соединение в отдельном потоке
            loop = asyncio.get_event_loop()
            result = await loop.run_in_executor(
                None, self._probe_port_sync, ip, port
            )
            
            return port, result
                
        except Exception as e:
            return port, None

    def _probe_port_sync(self, ip: str, port: int) -> Optional[str]:
        """Синхронная версия проверки порта"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.config.probe_timeout)

            result = sock.connect_ex((ip, port))
            if result != 0:
                return None

            # Отправляем пробу если есть
            probe_data = self.config.ports_tcp_probe.get(port, b"")
            if probe_data:
                try:
                    sock.send(probe_data)
                    sock.settimeout(2)  # Уменьшаем timeout для чтения
                    response = sock.recv(1024)

                    # Специальная валидация для определенных портов
                    if port == 3389:  # RDP
                        if not response.startswith(b"\x03\x00"):
                            return None
                    elif port == 5432:  # PostgreSQL
                        if not response.startswith(b"\x4e"):  # N - Authentication
                            return None
                    elif port == 554:  # RTSP
                        if b"RTSP/1.0" not in response:
                            return None

                    return response.decode("utf-8", errors="ignore").strip()
                except (socket.timeout, ConnectionResetError, BrokenPipeError):
                    return "open"

            sock.close()
            return "open"

        except (socket.timeout, ConnectionRefusedError, OSError) as e:
            self.logger.debug(f"Ошибка при сканировании {ip}:{port}: {e}")
            return None
        except Exception as e:
            self.logger.warning(f"Неожиданная ошибка при сканировании {ip}:{port}: {e}")
            return None

    def _update_performance_metrics(self, success: bool, response_time: float):
        """Обновляет метрики производительности"""
        self.performance_metrics['total_connections'] += 1
        if success:
            self.performance_metrics['successful_connections'] += 1
        else:
            self.performance_metrics['failed_connections'] += 1
        
        self.performance_metrics['response_times'].append(response_time)
        
        # Обновляем среднее время ответа
        if self.performance_metrics['response_times']:
            self.performance_metrics['avg_response_time'] = sum(
                self.performance_metrics['response_times']
            ) / len(self.performance_metrics['response_times'])

    def _calculate_optimal_concurrency(self) -> int:
        """Вычисляет оптимальное количество одновременных соединений"""
        if not self.performance_metrics['response_times']:
            return self.adaptive_limits['max_concurrent']
        
        avg_time = self.performance_metrics['avg_response_time']
        success_rate = (
            self.performance_metrics['successful_connections'] / 
            max(self.performance_metrics['total_connections'], 1)
        )
        
        # Адаптивная настройка на основе производительности
        if success_rate > 0.8 and avg_time < 1.0:
            # Хорошая производительность - увеличиваем
            new_limit = min(
                int(self.adaptive_limits['max_concurrent'] * self.adaptive_limits['adjustment_factor']),
                200  # Максимальный лимит
            )
        elif success_rate < 0.5 or avg_time > 5.0:
            # Плохая производительность - уменьшаем
            new_limit = max(
                int(self.adaptive_limits['max_concurrent'] / self.adaptive_limits['adjustment_factor']),
                self.adaptive_limits['min_concurrent']
            )
        else:
            new_limit = self.adaptive_limits['max_concurrent']
        
        self.adaptive_limits['max_concurrent'] = new_limit
        return new_limit

    async def scan_host_async(self, ip: str) -> ScanResult:
        """Асинхронно сканирует один хост"""
        start_time = time.time()
        self.logger.info(f"Сканирование {ip}")

        open_ports = {}
        detected_os = None

        # Создаем задачи для всех портов без семафора
        tasks = [
            self.probe_port_async(ip, port)
            for port in self.config.ports_tcp_probe.keys()
        ]

        # Выполняем все задачи одновременно
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        # Обрабатываем результаты
        for result in results:
            if isinstance(result, Exception):
                continue
                
            port, banner = result
            if banner:
                open_ports[port] = banner
                
                # Определяем ОС по первому открытому порту
                if detected_os is None:
                    detected_os = self.detect_os_from_banner(banner, port)

        # Если ОС не определена, пробуем определить по портам
        if detected_os is None and open_ports:
            detected_os = self.detect_os_from_banner("", list(open_ports.keys())[0])

        scan_time = time.time() - start_time
        
        return ScanResult(
            ip=ip,
            open_ports=open_ports,
            detected_os=detected_os,
            scan_time=scan_time
        )

    async def scan_network_async(self, network: str, max_workers: int = 10) -> List[ScanResult]:
        """Асинхронно сканирует всю сеть"""
        import ipaddress

        try:
            network_obj = ipaddress.IPv4Network(network, strict=False)
        except ValueError as e:
            raise ValueError(f"Неверный формат сети: {e}")

        self.logger.info(
            f"Начинаем асинхронное сканирование сети {network} ({network_obj.num_addresses} адресов)"
        )

        # Создаем задачи для всех хостов
        host_tasks = [
            self.scan_host_async(str(ip))
            for ip in network_obj.hosts()
        ]

        # Выполняем все задачи одновременно без ограничений
        results = await asyncio.gather(*host_tasks, return_exceptions=True)

        # Фильтруем результаты
        valid_results = []
        for result in results:
            if isinstance(result, Exception):
                continue
            if result.open_ports:  # Только хосты с открытыми портами
                valid_results.append(result)
                self.logger.info(
                    f"Найдены открытые порты на {result.ip}: {list(result.open_ports.keys())}"
                )

        self.logger.info(
            f"Асинхронное сканирование завершено. Найдено {len(valid_results)} хостов с открытыми портами"
        )
        
        return valid_results

    # Оставляем старые методы для обратной совместимости
    def probe_port(self, ip: str, port: int) -> Optional[str]:
        """Синхронная версия для обратной совместимости"""
        return self._probe_port_sync(ip, port)

    def scan_host(self, ip: str) -> ScanResult:
        """Синхронная версия для обратной совместимости"""
        start_time = time.time()
        self.logger.info(f"Сканирование {ip}")

        open_ports = {}
        detected_os = None

        # Сканируем все порты синхронно
        for port in self.config.ports_tcp_probe.keys():
            banner = self._probe_port_sync(ip, port)
            if banner:
                open_ports[port] = banner
                
                # Определяем ОС по первому открытому порту
                if detected_os is None:
                    detected_os = self.detect_os_from_banner(banner, port)

        # Если ОС не определена, пробуем определить по портам
        if detected_os is None and open_ports:
            detected_os = self.detect_os_from_banner("", list(open_ports.keys())[0])

        scan_time = time.time() - start_time
        
        return ScanResult(
            ip=ip,
            open_ports=open_ports,
            detected_os=detected_os,
            scan_time=scan_time
        )

    def scan_network(self, network: str, max_workers: int = 10) -> List[ScanResult]:
        """Синхронная версия для обратной совместимости"""
        import ipaddress
        from concurrent.futures import ThreadPoolExecutor

        try:
            network_obj = ipaddress.IPv4Network(network, strict=False)
        except ValueError as e:
            raise ValueError(f"Неверный формат сети: {e}")

        self.logger.info(
            f"Начинаем синхронное сканирование сети {network} ({network_obj.num_addresses} адресов)"
        )

        # Сканируем хосты с использованием ThreadPoolExecutor
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            host_tasks = [
                executor.submit(self.scan_host, str(ip))
                for ip in network_obj.hosts()
            ]
            
            results = []
            for future in host_tasks:
                try:
                    result = future.result()
                    if result.open_ports:  # Только хосты с открытыми портами
                        results.append(result)
                        self.logger.info(
                            f"Найдены открытые порты на {result.ip}: {list(result.open_ports.keys())}"
                        )
                except Exception as e:
                    self.logger.debug(f"Ошибка при сканировании хоста: {e}")

        self.logger.info(
            f"Синхронное сканирование завершено. Найдено {len(results)} хостов с открытыми портами"
        )
        
        return results


# Оставляем старый класс для обратной совместимости
class NetworkScanner(AsyncNetworkScanner):
    """Обратная совместимость с старым API"""
    pass
