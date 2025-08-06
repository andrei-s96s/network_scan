#!/usr/bin/env python3
"""
Сетевой сканер с веб-скриншотами
Usage:
    python web.py 172.30.1.0/24 [threads]
"""

import os
import sys
import ipaddress
import socket
import logging
import yaml
import json
from concurrent.futures import ThreadPoolExecutor, as_completed
from tqdm import tqdm
from playwright.sync_api import sync_playwright
from typing import Dict, Optional, Tuple, List
from dataclasses import dataclass
import struct

# ---------- конфигурация ----------
@dataclass
class Config:
    """Конфигурация сканера"""
    # TCP сканирование
    ports_tcp_probe: Dict[int, bytes] = None
    probe_timeout: int = 5
    web_timeout: int = 10
    
    # Веб-скриншоты
    viewport_width: int = 1280
    viewport_height: int = 720
    max_browsers: int = 3
    
    # Логирование
    log_level: str = "INFO"
    log_file: str = "scanner.log"
    
    def __post_init__(self):
        if self.ports_tcp_probe is None:
            self.ports_tcp_probe = {
                22:    b'',                    # SSH
                80:    b'HEAD / HTTP/1.0\r\n\r\n',
                443:   b'',                    # HTTPS
                135:   b'',                    # RPC
                139:   b'',                    # NetBIOS
                445:   b'',                    # SMB
                3389:  b'',                    # RDP
                5985:  b'',                    # WinRM HTTP
                5986:  b'',                    # WinRM HTTPS
                1433:  b'',                    # MSSQL
                3306:  b'\x0a',               # MySQL - простой ping
                5432:  b'\x00\x00\x00\x08\x04\xd2\x16\x2f',  # PostgreSQL startup message
                161:   b'',                    # SNMP
                # IP Phones
                5060:  b'OPTIONS sip:test@test.com SIP/2.0\r\nVia: SIP/2.0/UDP test.com\r\nFrom: <sip:test@test.com>\r\nTo: <sip:test@test.com>\r\nCall-ID: test@test.com\r\nCSeq: 1 OPTIONS\r\n\r\n',  # SIP OPTIONS
                5061:  b'OPTIONS sip:test@test.com SIP/2.0\r\nVia: SIP/2.0/TLS test.com\r\nFrom: <sip:test@test.com>\r\nTo: <sip:test@test.com>\r\nCall-ID: test@test.com\r\nCSeq: 1 OPTIONS\r\n\r\n',  # SIP over TLS
                10000: b'HEAD / HTTP/1.0\r\n\r\n',  # IP Phone web interface
                8080:  b'HEAD / HTTP/1.0\r\n\r\n',  # Alternative web interface
                # IP Cameras
                554:   b'OPTIONS rtsp://test.com/test RTSP/1.0\r\nCSeq: 1\r\n\r\n',  # RTSP OPTIONS
                8000:  b'HEAD / HTTP/1.0\r\n\r\n',  # IP Camera web interface
                37777: b'HEAD / HTTP/1.0\r\n\r\n',  # Dahua cameras web interface
                37778: b'HEAD / HTTP/1.0\r\n\r\n',  # Dahua cameras web interface
            }

def load_config(config_file: str = "config.yaml") -> Config:
    """Загружает конфигурацию из YAML файла"""
    if os.path.exists(config_file):
        try:
            with open(config_file, 'r', encoding='utf-8') as f:
                data = yaml.safe_load(f)
                return Config(**data)
        except Exception as e:
            logging.warning(f"Не удалось загрузить конфигурацию из {config_file}: {e}")
    
    return Config()

def setup_logging(config: Config):
    """Настраивает логирование"""
    logging.basicConfig(
        level=getattr(logging, config.log_level),
        format='%(asctime)s - %(levelname)s - %(message)s',
        handlers=[
            logging.FileHandler(config.log_file, encoding='utf-8')
        ]
    )

# ---------- TCP probe ----------
def create_snmp_get_request(community: str = "public", oid: str = "1.3.6.1.2.1.1.1.0") -> bytes:
    """Создает SNMP GET-REQUEST пакет"""
    # Простой SNMP v1 GET-REQUEST
    # SEQUENCE
    sequence = b'\x30'
    
    # Version (INTEGER 0)
    version = b'\x02\x01\x00'
    
    # Community string
    community_bytes = community.encode('ascii')
    community_len = len(community_bytes)
    community_octet = b'\x04' + bytes([community_len]) + community_bytes
    
    # PDU
    pdu_type = b'\xa0'  # GET-REQUEST
    pdu_length = b'\x1c'
    
    # Request ID
    request_id = b'\x02\x01\x01'
    
    # Error status
    error_status = b'\x02\x01\x00'
    
    # Error index
    error_index = b'\x02\x01\x00'
    
    # Varbind list
    varbind_list = b'\x30\x0e'
    
    # Varbind
    varbind = b'\x30\x0c'
    
    # OID
    oid_parts = [int(x) for x in oid.split('.')]
    oid_bytes = b''
    for part in oid_parts:
        if part < 128:
            oid_bytes += bytes([part])
        else:
            # Для больших чисел нужна более сложная логика
            oid_bytes += bytes([part])
    
    oid_len = len(oid_bytes)
    oid_octet = b'\x06' + bytes([oid_len]) + oid_bytes
    
    # Null value
    null_value = b'\x05\x00'
    
    # Собираем пакет
    varbind_content = oid_octet + null_value
    varbind_list_content = varbind + varbind_content
    pdu_content = request_id + error_status + error_index + varbind_list_content
    
    # Вычисляем длины
    total_length = len(version + community_octet + pdu_type + bytes([len(pdu_content)]) + pdu_content)
    
    return sequence + bytes([total_length]) + version + community_octet + pdu_type + bytes([len(pdu_content)]) + pdu_content

def detect_os_from_banner(banner: str, port: int) -> Optional[str]:
    """Определяет ОС по баннеру сервиса"""
    banner_lower = banner.lower()
    
    # Windows признаки
    if any(keyword in banner_lower for keyword in ['windows', 'microsoft', 'iis', 'exchange']):
        return "Windows"
    if 'smb' in banner_lower or port in (135, 139, 445):
        return "Windows"
    if 'rdp' in banner_lower or port == 3389:
        return "Windows"
    if 'winrm' in banner_lower or port in (5985, 5986):
        return "Windows"
    
    # Linux признаки
    if any(keyword in banner_lower for keyword in ['linux', 'ubuntu', 'debian', 'centos', 'redhat', 'fedora']):
        return "Linux"
    if 'openssh' in banner_lower and port == 22:
        return "Linux"  # Чаще всего SSH на Linux
    if 'apache' in banner_lower and 'linux' in banner_lower:
        return "Linux"
    
    # Unix признаки
    if any(keyword in banner_lower for keyword in ['freebsd', 'openbsd', 'netbsd', 'solaris']):
        return "Unix"
    if 'openssh' in banner_lower and 'bsd' in banner_lower:
        return "Unix"
    
    # Специфичные сервисы
    if 'nginx' in banner_lower:
        return "Linux"  # Nginx чаще на Linux
    if 'apache' in banner_lower:
        return "Linux"  # Apache чаще на Linux
    
    # SNMP устройства
    if 'snmp' in banner_lower or port == 161:
        return "Network Device"  # Сетевые устройства
    
    # IP Phones
    if any(keyword in banner_lower for keyword in ['sip', 'asterisk', 'freepbx', 'cisco', 'yealink', 'grandstream']):
        return "IP Phone"
    if port in (5060, 5061, 10000):
        return "IP Phone"
    
    # IP Cameras
    if any(keyword in banner_lower for keyword in ['rtsp', 'dahua', 'hikvision', 'axis', 'foscam', 'ip camera', 'ipcam']):
        return "IP Camera"
    if port in (554, 8000, 37777, 37778):
        return "IP Camera"
    
    return None

def probe_port(ip: str, port: int, config: Config) -> Optional[str]:
    """Вернёт первую строку ответа или 'open', если порт открыт без данных."""
    try:
        with socket.create_connection((ip, port), timeout=config.probe_timeout) as s:
            s.settimeout(config.probe_timeout)
            
            # Специальная обработка для разных типов портов
            if port == 3389:  # RDP
                # RDP требует специальной обработки - отправляем RDP connection request
                try:
                    # Простой RDP connection request
                    rdp_request = b'\x03\x00\x00\x13\x0e\xe0\x00\x00\x00\x00\x00\x01\x00\x08\x00\x03\x00\x00\x00'
                    s.send(rdp_request)
                    s.settimeout(config.probe_timeout * 2)
                    try:
                        response = s.recv(256)
                        if response:
                            # Проверяем, что это RDP ответ
                            if response.startswith(b'\x03\x00'):
                                return "RDP"
                            else:
                                # Если получили ответ, но это не RDP - игнорируем порт
                                return None
                        else:
                            # Нет ответа на RDP probe - игнорируем порт
                            return None
                    except socket.timeout:
                        # Таймаут на RDP probe - игнорируем порт
                        return None
                except Exception:
                    # Если не удалось отправить RDP probe - игнорируем порт
                    return None
            elif port == 5432:  # PostgreSQL
                # Отправляем PostgreSQL startup message
                probe = config.ports_tcp_probe.get(port, b'')
                if probe:
                    s.send(probe)
                    s.settimeout(config.probe_timeout * 2)
                    try:
                        response = s.recv(256)
                        if response:
                            # Проверяем, что это PostgreSQL ответ
                            response_text = response.decode('utf-8', errors='ignore').lower()
                            if 'postgresql' in response_text or 'postgres' in response_text:
                                return "PostgreSQL"
                            else:
                                # Если получили ответ, но это не PostgreSQL - игнорируем порт
                                return None
                        else:
                            # Нет ответа на PostgreSQL probe - игнорируем порт
                            return None
                    except socket.timeout:
                        # Таймаут на PostgreSQL probe - игнорируем порт
                        return None
                else:
                    return None
            elif port == 1433:  # MSSQL
                return "MSSQL"
            elif port == 3306:  # MySQL
                return "MySQL"
            elif port in (135, 139, 445):  # Windows services
                return "Windows Service"
            elif port in (5985, 5986):  # WinRM
                return "WinRM"
            elif port == 161:  # SNMP
                return "SNMP"
            elif port in (5060, 5061):  # SIP
                # Отправляем SIP OPTIONS probe
                probe = config.ports_tcp_probe.get(port, b'')
                if probe:
                    s.send(probe)
                    s.settimeout(config.probe_timeout * 2)
                    try:
                        response = s.recv(256)
                        if response:
                            # Проверяем, что это SIP ответ
                            response_text = response.decode('utf-8', errors='ignore').lower()
                            if 'sip/2.0' in response_text or 'sip' in response_text:
                                return "SIP"
                            else:
                                # Если получили ответ, но это не SIP - игнорируем порт
                                return None
                        else:
                            # Нет ответа на SIP probe - игнорируем порт
                            return None
                    except socket.timeout:
                        # Таймаут на SIP probe - игнорируем порт
                        return None
                else:
                    return None
            elif port == 10000:  # IP Phone web interface
                return "IP Phone"
            elif port == 8080:  # Alternative web interface
                return "Alternative Web"
            elif port == 554:  # RTSP
                # Отправляем RTSP OPTIONS probe
                probe = config.ports_tcp_probe.get(port, b'')
                if probe:
                    s.send(probe)
                    s.settimeout(config.probe_timeout * 2)
                    try:
                        response = s.recv(256)
                        if response:
                            # Проверяем, что это RTSP ответ
                            response_text = response.decode('utf-8', errors='ignore').lower()
                            if 'rtsp/1.0' in response_text or 'rtsp' in response_text:
                                return "RTSP"
                            else:
                                # Если получили ответ, но это не RTSP - игнорируем порт
                                return None
                        else:
                            # Нет ответа на RTSP probe - игнорируем порт
                            return None
                    except socket.timeout:
                        # Таймаут на RTSP probe - игнорируем порт
                        return None
                else:
                    return None
            elif port == 8000:  # IP Camera web interface
                return "IP Camera"
            elif port in (37777, 37778):  # Dahua cameras
                return "Dahua Camera"
            
            # Для остальных портов пробуем получить banner
            probe = config.ports_tcp_probe.get(port, b'')
            if probe:
                s.send(probe)
                # Увеличиваем таймаут для получения ответа
                s.settimeout(config.probe_timeout * 2)
            
            # Специальная обработка для SNMP
            if port == 161:
                try:
                    # Создаем UDP сокет для SNMP
                    udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                    udp_socket.settimeout(config.probe_timeout)
                    
                    # Отправляем SNMP GET-REQUEST
                    snmp_packet = create_snmp_get_request()
                    udp_socket.sendto(snmp_packet, (ip, 161))
                    
                    # Пытаемся получить ответ
                    response, addr = udp_socket.recvfrom(1024)
                    udp_socket.close()
                    
                    if response:
                        # Проверяем, что это SNMP ответ
                        if response.startswith(b'\x30'):
                            return "SNMP (public)"
                        else:
                            return "SNMP"
                except (socket.timeout, OSError):
                    udp_socket.close()
                    return "SNMP"
            
            try:
                response = s.recv(256)
                if response:
                    # Пытаемся декодировать как текст
                    try:
                        banner = response.splitlines()[0].decode(errors='ignore').strip()
                        return banner or "open"
                    except (IndexError, UnicodeDecodeError):
                        # Если не удалось декодировать как текст, но есть данные
                        return "open"
                else:
                    return "open"
            except (socket.timeout, IndexError):
                # Если не получили ответ, но соединение установлено - порт открыт
                return "open"
                
    except OSError as e:
        logging.debug(f"Порт {port} на {ip} закрыт: {e}")
        return None
    except Exception as e:
        logging.error(f"Ошибка при сканировании порта {port} на {ip}: {e}")
        return None

def tcp_scan(ip: str, config: Config) -> Tuple[Dict[int, str], Optional[str]]:
    """{port: response} для всех открытых портов и определение ОС."""
    results = {}
    detected_os = None
    
    for port in config.ports_tcp_probe:
        resp = probe_port(ip, port, config)
        if resp is not None:
            results[port] = resp
            logging.info(f"Открыт порт {port} на {ip}: {resp}")
            
            # Пытаемся определить ОС по баннеру
            if detected_os is None and resp != "open":
                detected_os = detect_os_from_banner(resp, port)
    
    return results, detected_os

def save_result(ip: str, results: Dict[int, str], outfile: str):
    """Записывает строку вида IP  port:resp port:resp ..."""
    if not results:
        return
    parts = [f"{p}:{v}" for p, v in sorted(results.items())]
    line = f"{ip}  {'  '.join(parts)}\n"
    try:
        with open(outfile, 'a', encoding='utf-8') as f:
            f.write(line)
    except Exception as e:
        logging.error(f"Ошибка при записи результата для {ip}: {e}")

def save_result_json(ip: str, results: Dict[int, str], json_data: List[Dict], screenshots_count: int = 0, detected_os: Optional[str] = None):
    """Добавляет результат в JSON структуру"""
    if not results:
        return
    
    # Определяем сервисы по портам
    services = {
        22: "SSH", 80: "HTTP", 443: "HTTPS", 135: "RPC", 139: "NetBIOS",
        445: "SMB", 3389: "RDP", 5985: "WinRM-HTTP", 5986: "WinRM-HTTPS",
        1433: "MSSQL", 3306: "MySQL", 5432: "PostgreSQL", 161: "SNMP",
        # IP Phones
        5060: "SIP", 5061: "SIP-TLS", 10000: "IP Phone Web", 8080: "Alternative Web",
        # IP Cameras
        554: "RTSP", 8000: "IP Camera Web", 37777: "Dahua Camera", 37778: "Dahua Camera"
    }
    
    host_data = {
        "ip": ip,
        "ports": {},
        "screenshots": screenshots_count,
        "os": detected_os,
        "summary": {
            "total_ports": len(results),
            "web_ports": len([p for p in results if p in (80, 443)]),
            "services": []
        }
    }
    
    for port, response in sorted(results.items()):
        service_name = services.get(port, f"Unknown-{port}")
        host_data["ports"][str(port)] = {
            "service": service_name,
            "response": response,
            "status": "open"
        }
        host_data["summary"]["services"].append(service_name)
    
    json_data.append(host_data)

def save_json_report(json_data: List[Dict], network: str, output_file: str):
    """Сохраняет полный JSON отчет"""
    from datetime import datetime
    
    report = {
        "scan_info": {
            "network": network,
            "scan_time": datetime.now().isoformat(),
            "total_hosts": len(json_data),
            "hosts_with_ports": len([h for h in json_data if h["ports"]]),
            "hosts_with_screenshots": len([h for h in json_data if h["screenshots"] > 0])
        },
        "hosts": json_data,
        "summary": {
            "total_ports_found": sum(len(h["ports"]) for h in json_data),
            "services_found": list(set(
                service for host in json_data 
                for port_data in host["ports"].values() 
                for service in [port_data["service"]]
            )),
            "web_services": len([h for h in json_data if h["summary"]["web_ports"] > 0])
        }
    }
    
    try:
        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(report, f, indent=2, ensure_ascii=False)
        logging.info(f"JSON отчет сохранен: {output_file}")
    except Exception as e:
        logging.error(f"Ошибка при сохранении JSON отчета: {e}")

def save_html_report(json_data: List[Dict], network: str, output_file: str):
    """Создает красивый HTML отчет на основе JSON данных"""
    from datetime import datetime
    
    def get_port_ending(count):
        """Возвращает правильное окончание для слова 'порт'"""
        if count % 10 == 1 and count % 100 != 11:
            return ""
        elif count % 10 in [2, 3, 4] and count % 100 not in [12, 13, 14]:
            return "а"
        else:
            return "ов"
    
    def get_screenshot_ending(count):
        """Возвращает правильное окончание для слова 'скриншот'"""
        if count % 10 == 1 and count % 100 != 11:
            return ""
        elif count % 10 in [2, 3, 4] and count % 100 not in [12, 13, 14]:
            return "а"
        else:
            return "ов"
    
    html_template = """
<!DOCTYPE html>
<html lang="ru">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Отчет сканирования сети {network}</title>
    <style>
        body {{
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            margin: 0;
            padding: 20px;
            background: linear-gradient(135deg, #1e3c72 0%, #2a5298 100%);
            min-height: 100vh;
        }}
        .container {{
            max-width: 1200px;
            margin: 0 auto;
            background: white;
            border-radius: 15px;
            box-shadow: 0 20px 40px rgba(0,0,0,0.1);
            overflow: hidden;
        }}
        .header {{
            background: linear-gradient(135deg, #1e3c72 0%, #2a5298 100%);
            color: white;
            padding: 30px;
            text-align: center;
        }}
        .header h1 {{
            margin: 0;
            font-size: 2.5em;
            font-weight: 300;
        }}
        .header .subtitle {{
            margin-top: 10px;
            opacity: 0.9;
            font-size: 1.1em;
        }}
        .logo-section {{
            display: flex;
            align-items: center;
            justify-content: center;
            gap: 20px;
        }}
        .logo {{
            font-size: 3em;
            background: rgba(255,255,255,0.1);
            border-radius: 50%;
            width: 80px;
            height: 80px;
            display: flex;
            align-items: center;
            justify-content: center;
            backdrop-filter: blur(10px);
        }}
        .title-section {{
            text-align: left;
        }}
        .stats {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            padding: 30px;
            background: #f8f9fa;
        }}
        .stat-card {{
            background: white;
            padding: 20px;
            border-radius: 10px;
            text-align: center;
            box-shadow: 0 5px 15px rgba(0,0,0,0.08);
        }}
        .stat-number {{
            font-size: 2.5em;
            font-weight: bold;
            color: #1e3c72;
            margin-bottom: 5px;
        }}
        .stat-label {{
            color: #666;
            font-size: 0.9em;
            text-transform: uppercase;
            letter-spacing: 1px;
        }}
        .hosts-section {{
            padding: 30px;
        }}
        .host-card {{
            background: white;
            border: 1px solid #e9ecef;
            border-radius: 10px;
            margin-bottom: 20px;
            overflow: hidden;
            box-shadow: 0 5px 15px rgba(0,0,0,0.08);
        }}
        .host-header {{
            background: #f8f9fa;
            padding: 15px 20px;
            border-bottom: 1px solid #e9ecef;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }}
        .host-ip {{
            font-size: 1.2em;
            font-weight: bold;
            color: #333;
        }}
        .host-summary {{
            display: flex;
            gap: 15px;
            font-size: 0.9em;
            color: #666;
        }}
        .port-item {{
            padding: 10px 20px;
            border-bottom: 1px solid #f1f3f4;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }}
        .port-item:last-child {{
            border-bottom: none;
        }}
        .port-info {{
            display: flex;
            align-items: center;
            gap: 15px;
        }}
        .port-number {{
            background: #1e3c72;
            color: white;
            padding: 5px 10px;
            border-radius: 15px;
            font-weight: bold;
            font-size: 0.9em;
        }}
        .service-name {{
            font-weight: bold;
            color: #333;
        }}
        .port-response {{
            color: #666;
            font-family: monospace;
            font-size: 0.9em;
        }}
        .screenshots-info {{
            background: #e3f2fd;
            color: #1976d2;
            padding: 10px 20px;
            font-size: 0.9em;
            display: flex;
            align-items: center;
            gap: 10px;
        }}
        .no-hosts {{
            text-align: center;
            padding: 50px;
            color: #666;
            font-style: italic;
        }}
        .services-summary {{
            background: #f8f9fa;
            padding: 20px;
            margin-top: 20px;
            border-radius: 10px;
        }}
        .services-list {{
            display: flex;
            flex-wrap: wrap;
            gap: 10px;
            margin-top: 10px;
        }}
        .service-tag {{
            background: #1e3c72;
            color: white;
            padding: 5px 12px;
            border-radius: 20px;
            font-size: 0.8em;
            font-weight: bold;
        }}
        .screenshots-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
            gap: 10px;
            margin-top: 10px;
        }}
        .screenshot-item {{
            position: relative;
            cursor: pointer;
            border-radius: 8px;
            overflow: hidden;
            box-shadow: 0 2px 8px rgba(0,0,0,0.1);
            transition: transform 0.2s;
        }}
        .screenshot-item:hover {{
            transform: scale(1.05);
        }}
        .screenshot-item img {{
            width: 100%;
            height: 100px;
            object-fit: cover;
            display: block;
        }}
        .screenshot-label {{
            position: absolute;
            bottom: 0;
            left: 0;
            right: 0;
            background: rgba(0,0,0,0.7);
            color: white;
            padding: 5px;
            font-size: 0.8em;
            text-align: center;
        }}
        .modal {{
            display: none;
            position: fixed;
            z-index: 1000;
            left: 0;
            top: 0;
            width: 100%;
            height: 100%;
            background-color: rgba(0,0,0,0.9);
        }}
        .modal-content {{
            margin: auto;
            display: block;
            width: 90%;
            max-width: 1200px;
            max-height: 90%;
            object-fit: contain;
        }}
        .close {{
            position: absolute;
            top: 15px;
            right: 35px;
            color: #f1f1f1;
            font-size: 40px;
            font-weight: bold;
            cursor: pointer;
        }}
        .close:hover {{
            color: #bbb;
        }}
        .footer {{
            background: #1e3c72;
            color: white;
            padding: 20px;
            font-size: 0.9em;
        }}
        .footer-content {{
            display: flex;
            justify-content: space-between;
            align-items: center;
            max-width: 1200px;
            margin: 0 auto;
        }}
        .footer-logo {{
            font-weight: bold;
            font-size: 1.1em;
        }}
        .footer-info {{
            opacity: 0.8;
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <div class="logo-section">
                <div class="logo">🔒</div>
                <div class="title-section">
                    <h1>Отчет сканирования сети</h1>
                    <div class="subtitle">
                        Сеть: {network} | Время: {scan_time}
                    </div>
                </div>
            </div>
        </div>
        
        <div class="stats">
            <div class="stat-card">
                <div class="stat-number">{total_hosts}</div>
                <div class="stat-label">Всего хостов</div>
            </div>
            <div class="stat-card">
                <div class="stat-number">{hosts_with_ports}</div>
                <div class="stat-label">Хостов с портами</div>
            </div>
            <div class="stat-card">
                <div class="stat-number">{total_ports}</div>
                <div class="stat-label">Открытых портов</div>
            </div>
            <div class="stat-card">
                <div class="stat-number">{web_services}</div>
                <div class="stat-label">Веб-сервисов</div>
            </div>
        </div>
        
        <div class="hosts-section">
            <h2>📋 Результаты сканирования</h2>
            {hosts_html}
        </div>
        
                 <div class="services-summary">
             <h3>🔧 Обнаруженные сервисы</h3>
             <div class="services-list">
                 {services_html}
             </div>
         </div>
         
         {os_stats_html}
        
        <div class="footer">
            <div class="footer-content">
                <div class="footer-info">
                    Отчет сгенерирован автоматически | Сетевой сканер v1.0
                </div>
            </div>
        </div>
    </div>
    
    <!-- Модальное окно для скриншотов -->
    <div id="screenshotModal" class="modal">
        <span class="close">&times;</span>
        <img class="modal-content" id="modalImage">
    </div>
    
    <script>
        // Модальное окно для скриншотов
        var modal = document.getElementById("screenshotModal");
        var modalImg = document.getElementById("modalImage");
        var span = document.getElementsByClassName("close")[0];
        
        // Открытие модального окна
        function openModal(imgSrc) {{
            modal.style.display = "block";
            modalImg.src = imgSrc;
        }}
        
        // Закрытие модального окна
        span.onclick = function() {{
            modal.style.display = "none";
        }}
        
        // Закрытие по клику вне изображения
        modal.onclick = function(e) {{
            if (e.target === modal) {{
                modal.style.display = "none";
            }}
        }}
        
        // Закрытие по клавише Escape
        document.addEventListener('keydown', function(e) {{
            if (e.key === 'Escape' && modal.style.display === 'block') {{
                modal.style.display = "none";
            }}
        }});
    </script>
</body>
</html>
"""
    
    # Подготавливаем данные для отчета
    total_hosts = len(json_data)
    hosts_with_ports = len([h for h in json_data if h["ports"]])
    total_ports = sum(len(h["ports"]) for h in json_data)
    web_services = len([h for h in json_data if h["summary"]["web_ports"] > 0])
    
    # Статистика по ОС
    os_stats = {}
    for host in json_data:
        if host.get('os'):
            os_stats[host['os']] = os_stats.get(host['os'], 0) + 1
    
    # Собираем все уникальные сервисы
    all_services = set()
    for host in json_data:
        for service in host["summary"]["services"]:
            all_services.add(service)
    
    # Генерируем HTML для хостов
    hosts_html = ""
    if json_data:
        for host in json_data:
            if host["ports"]:
                host_html = f"""
                <div class="host-card">
                    <div class="host-header">
                        <div class="host-ip">🌐 {host['ip']}</div>
                                                 <div class="host-summary">
                             <span>📊 {host['summary']['total_ports']} порт{get_port_ending(host['summary']['total_ports'])}</span>
                             <span>🌍 {host['summary']['web_ports']} веб-порт{get_port_ending(host['summary']['web_ports'])}</span>
                             <span>📸 {host['screenshots']} скриншот{get_screenshot_ending(host['screenshots'])}</span>
                             {f'<span>💻 {host["os"]}</span>' if host.get('os') else ''}
                         </div>
                    </div>
                """
                
                for port_num, port_data in sorted(host["ports"].items()):
                    host_html += f"""
                    <div class="port-item">
                        <div class="port-info">
                            <span class="port-number">{port_num}</span>
                            <span class="service-name">{port_data['service']}</span>
                        </div>
                        <div class="port-response">{port_data['response']}</div>
                    </div>
                    """
                
                if host["screenshots"] > 0:
                    host_html += f"""
                    <div class="screenshots-info">
                        📸 Скриншоты ({host['screenshots']} шт.)
                    </div>
                    <div class="screenshots-grid">
                    """
                    
                    # Добавляем скриншоты для портов 80 и 443
                    for port in [80, 443]:
                        screenshot_path = f"./web/{host['ip']}/{port}.png"
                        if os.path.exists(screenshot_path):
                            protocol = "HTTPS" if port == 443 else "HTTP"
                            host_html += f"""
                            <div class="screenshot-item" onclick="openModal('{screenshot_path}')">
                                <img src="{screenshot_path}" alt="{protocol} скриншот">
                                <div class="screenshot-label">{protocol} (порт {port})</div>
                            </div>
                            """
                    
                    host_html += "</div>"
                
                host_html += "</div>"
                hosts_html += host_html
    else:
        hosts_html = '<div class="no-hosts">😔 Открытых портов не найдено</div>'
    
    # Генерируем HTML для сервисов
    services_html = ""
    for service in sorted(all_services):
        services_html += f'<span class="service-tag">{service}</span>'
    
    # Генерируем HTML для статистики ОС
    os_stats_html = ""
    if os_stats:
        os_stats_html = """
        <div class="services-summary">
            <h3>💻 Операционные системы</h3>
            <div class="services-list">
        """
        for os_name, count in sorted(os_stats.items()):
            os_stats_html += f'<span class="service-tag">{os_name} ({count})</span>'
        os_stats_html += """
            </div>
        </div>
        """
    
    # Заполняем шаблон
    html_content = html_template.format(
         network=network,
         scan_time=datetime.now().strftime("%d.%m.%Y %H:%M:%S"),
         total_hosts=total_hosts,
         hosts_with_ports=hosts_with_ports,
         total_ports=total_ports,
         web_services=web_services,
         hosts_html=hosts_html,
         services_html=services_html,
         os_stats_html=os_stats_html
     )
    
    try:
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write(html_content)
        logging.info(f"HTML отчет сохранен: {output_file}")
    except Exception as e:
        logging.error(f"Ошибка при сохранении HTML отчета: {e}")

# ---------- web screenshot ----------
class BrowserManager:
    """Менеджер браузеров для оптимизации ресурсов"""
    
    def __init__(self, config: Config):
        self.config = config
        self.playwright = None
        self.browser = None
        self.context = None
        self._lock = None
        
    def __enter__(self):
        self.playwright = sync_playwright().start()
        self.browser = self.playwright.chromium.launch(
            headless=True,
            args=['--no-sandbox', '--disable-dev-shm-usage']
        )
        self.context = self.browser.new_context(
            viewport={'width': self.config.viewport_width, 'height': self.config.viewport_height},
            ignore_https_errors=True
        )
        return self
        
    def __exit__(self, exc_type, exc_val, exc_tb):
        if self.context:
            self.context.close()
        if self.browser:
            self.browser.close()
        if self.playwright:
            self.playwright.stop()

def screenshot_ip(ip: str, config: Config) -> int:
    """Делает скриншоты веб-страниц для IP"""
    ok = 0
    try:
        with BrowserManager(config) as browser_mgr:
            # Список всех веб-портов для скриншотов
            web_ports = {
                80: 'http',      # HTTP
                443: 'https',    # HTTPS
                8080: 'http',    # Alternative Web
                10000: 'http',   # IP Phone Web
                8000: 'http',    # IP Camera Web
                37777: 'http',   # Dahua Camera Web
                37778: 'http',   # Dahua Camera Web
            }
            
            for port, protocol in web_ports.items():
                try:
                    page = browser_mgr.context.new_page()
                    page.goto(f"{protocol}://{ip}:{port}", timeout=config.web_timeout * 1000)
                    
                    folder = os.path.join("web", str(ip))
                    os.makedirs(folder, exist_ok=True)
                    
                    page.screenshot(path=os.path.join(folder, f"{port}.png"), full_page=True)
                    logging.info(f"Скриншот {protocol}://{ip}:{port} сохранен")
                    ok += 1
                except Exception as e:
                    logging.debug(f"Не удалось сделать скриншот {protocol}://{ip}:{port}: {e}")
                finally:
                    page.close()
    except Exception as e:
        logging.error(f"Ошибка при создании браузера для {ip}: {e}")
    
    return ok

# ---------- валидация ----------
def validate_network(network_str: str) -> ipaddress.IPv4Network:
    """Валидирует сетевой адрес"""
    try:
        network = ipaddress.ip_network(network_str, strict=False)
        if not network.is_private:
            logging.warning(f"Сканирование публичной сети: {network_str}")
        return network
    except ValueError as e:
        raise ValueError(f"Неверный сетевой адрес: {e}")

def validate_threads(threads: int) -> int:
    """Валидирует количество потоков"""
    if threads < 1:
        raise ValueError("Количество потоков должно быть больше 0")
    if threads > 50:
        logging.warning(f"Большое количество потоков: {threads}")
    return threads

# ---------- main ----------
def scan_host(ip: str, result_file: str, config: Config, json_data: List[Dict] = None) -> Tuple[str, int, bool]:
    """Сканирует один хост"""
    try:
        tcp_results, detected_os = tcp_scan(ip, config)
        save_result(ip, tcp_results, result_file)
        
        # Делаем веб-скриншоты только если есть открытые веб-порты
        web_ports = {80, 443, 8080, 10000, 8000, 37777, 37778}
        if any(port in tcp_results for port in web_ports):
            web_ok = screenshot_ip(ip, config)
        else:
            web_ok = 0
        
        # Добавляем в JSON если передан
        if json_data is not None:
            save_result_json(ip, tcp_results, json_data, web_ok, detected_os)
            
        return ip, web_ok, bool(tcp_results)
    except Exception as e:
        logging.error(f"Ошибка при сканировании {ip}: {e}")
        return ip, 0, False

def main():
    """Основная функция"""
    if len(sys.argv) < 2:
        print("Usage: python web.py <network> [threads] [--no-json]")
        print("Example: python web.py 172.30.1.0/24 10")
        print("Example: python web.py 172.30.1.0/24 10 --no-json")
        sys.exit(1)

    # Загружаем конфигурацию
    config = load_config()
    setup_logging(config)
    
    # Парсим аргументы
    network_str = sys.argv[1]
    threads = int(sys.argv[2]) if len(sys.argv) > 2 and not sys.argv[2].startswith('--') else 10
    export_json = '--no-json' not in sys.argv  # По умолчанию включен
    
    try:
        network = validate_network(network_str)
        threads = validate_threads(threads)
    except ValueError as e:
        print(f"Ошибка: {e}")
        sys.exit(1)

    result_file = f"scan-{network_str.replace('/', '_')}.txt"
    json_file = f"scan-{network_str.replace('/', '_')}.json" if export_json else None
    html_file = f"scan-{network_str.replace('/', '_')}.html" if export_json else None
    
    if os.path.exists(result_file):
        os.remove(result_file)
        logging.info(f"Удален старый файл результатов: {result_file}")
    
    if json_file and os.path.exists(json_file):
        os.remove(json_file)
        logging.info(f"Удален старый JSON файл: {json_file}")
    
    if html_file and os.path.exists(html_file):
        os.remove(html_file)
        logging.info(f"Удален старый HTML файл: {html_file}")

    hosts = list(network.hosts())
    logging.info(f"Начинаем сканирование {len(hosts)} хостов с {threads} потоками")
    print(f"Сканирование {len(hosts)} хостов с {threads} потоками...")
    if export_json:
        print("JSON и HTML отчеты включены")
    else:
        print("JSON и HTML отчеты отключены")

    # Список для JSON данных
    json_data = [] if export_json else None

    with tqdm(total=len(hosts), unit="ip") as pbar:
        with ThreadPoolExecutor(max_workers=threads) as ex:
            futures = {ex.submit(scan_host, str(ip), result_file, config, json_data): ip for ip in hosts}
            for fut in as_completed(futures):
                try:
                    ip, web_ok, tcp_ok = fut.result()
                    pbar.set_postfix(ip=ip[-10:], w=web_ok, t=tcp_ok)
                    pbar.update(1)
                except Exception as e:
                    logging.error(f"Ошибка в потоке: {e}")
                    pbar.update(1)

    # Сохраняем отчеты если нужно
    if export_json and json_data:
        save_json_report(json_data, network_str, json_file)
        save_html_report(json_data, network_str, html_file)

    logging.info("Сканирование завершено")
    print("Готово.")
    print("Скриншоты → ./web/")
    print("TCP scan   →", result_file)
    if export_json:
        print("JSON отчет →", json_file)
        print("HTML отчет →", html_file)

if __name__ == "__main__":
    # Отключаем предупреждения
    import urllib3, warnings
    urllib3.disable_warnings()
    warnings.filterwarnings("ignore")
    
    main()