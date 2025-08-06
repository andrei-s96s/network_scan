#!/usr/bin/env python3
"""
Оптимизированный сетевой сканер
"""

import socket
import logging
from typing import Dict, Optional, List
from dataclasses import dataclass
from concurrent.futures import ThreadPoolExecutor, as_completed

from config import ScannerConfig


@dataclass
class ScanResult:
    """Результат сканирования одного хоста"""

    ip: str
    open_ports: Dict[int, str]
    detected_os: Optional[str] = None
    screenshots_count: int = 0

    def __post_init__(self):
        """Валидация результата"""
        if not self.ip:
            raise ValueError("IP адрес не может быть пустым")
        if not isinstance(self.open_ports, dict):
            raise ValueError("open_ports должен быть словарем")


class NetworkScanner:
    """Оптимизированный сетевой сканер"""

    def __init__(self, config: ScannerConfig):
        self.config = config
        self.logger = logging.getLogger(__name__)

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

        return None

    def probe_port(self, ip: str, port: int) -> Optional[str]:
        """Проверяет один порт с улучшенной обработкой ошибок"""
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
                    elif port in [5060, 5061]:  # SIP - строгая валидация
                        # Для SIP требуем хотя бы какой-то ответ
                        # Если устройство принимает соединение, но не отвечает на SIP OPTIONS,
                        # то это не SIP сервер
                        if response and len(response) > 0:
                            return response.decode("utf-8", errors="ignore").strip()
                        else:
                            # Если нет ответа на SIP OPTIONS, считаем порт закрытым
                            # Это предотвращает ложные срабатывания на устройствах, которые
                            # принимают TCP соединения, но не являются SIP серверами
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

    def scan_host(self, ip: str) -> ScanResult:
        """Сканирует один хост"""
        self.logger.info(f"Сканирование {ip}")

        open_ports = {}
        detected_os = None

        # Сканируем все порты параллельно
        with ThreadPoolExecutor(
            max_workers=min(20, len(self.config.ports_tcp_probe))
        ) as executor:
            # Фильтруем порты для сканирования
            ports_to_scan = {}
            for port, probe_data in self.config.ports_tcp_probe.items():
                if self.config.skip_sip_ports and port in [5060, 5061]:
                    self.logger.debug(f"Пропускаем SIP порт {port}")
                    continue
                ports_to_scan[port] = probe_data
            
            future_to_port = {
                executor.submit(self.probe_port, ip, port): port
                for port in ports_to_scan.keys()
            }

            for future in as_completed(future_to_port):
                port = future_to_port[future]
                try:
                    result = future.result()
                    if result:
                        open_ports[port] = result
                        # Определяем ОС по первому найденному баннеру
                        if detected_os is None and result != "open":
                            detected_os = self.detect_os_from_banner(result, port)
                    # Добавляем отладочную информацию для порта 5060
                    if port == 5060:
                        self.logger.info(f"Порт 5060 на {ip}: результат = {result}")
                        if result is None:
                            self.logger.debug(f"Порт 5060 на {ip}: соединение не установлено или нет ответа на SIP OPTIONS")
                        elif result == "open":
                            self.logger.debug(f"Порт 5060 на {ip}: соединение установлено, но нет ответа на SIP OPTIONS")
                        else:
                            self.logger.debug(f"Порт 5060 на {ip}: получен ответ: {result[:100]}...")
                    # Добавляем отладочную информацию для всех портов в DEBUG режиме
                    self.logger.debug(f"Порт {port} на {ip}: результат = {result}")
                except Exception as e:
                    self.logger.error(
                        f"Ошибка при сканировании порта {port} на {ip}: {e}"
                    )

        return ScanResult(ip=ip, open_ports=open_ports, detected_os=detected_os)

    def scan_network(self, network: str, max_workers: int = 10) -> List[ScanResult]:
        """Сканирует всю сеть"""
        import ipaddress

        try:
            network_obj = ipaddress.IPv4Network(network, strict=False)
        except ValueError as e:
            raise ValueError(f"Неверный формат сети: {e}")

        self.logger.info(
            f"Начинаем сканирование сети {network} ({network_obj.num_addresses} адресов)"
        )

        results = []
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            future_to_ip = {
                executor.submit(self.scan_host, str(ip)): str(ip)
                for ip in network_obj.hosts()
            }

            for future in as_completed(future_to_ip):
                ip = future_to_ip[future]
                try:
                    result = future.result()
                    if result.open_ports:  # Только хосты с открытыми портами
                        results.append(result)
                        self.logger.info(
                            f"Найдены открытые порты на {ip}: {list(result.open_ports.keys())}"
                        )
                except Exception as e:
                    self.logger.error(f"Ошибка при сканировании {ip}: {e}")

        self.logger.info(
            f"Сканирование завершено. Найдено {len(results)} хостов с открытыми портами"
        )
        return results
