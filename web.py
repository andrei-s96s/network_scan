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
from concurrent.futures import ThreadPoolExecutor, as_completed
from tqdm import tqdm
from playwright.sync_api import sync_playwright
from typing import Dict, Optional, Tuple
from dataclasses import dataclass

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
                22:    b'',            # SSH
                80:    b'HEAD / HTTP/1.0\r\n\r\n',
                443:   b'',            # HTTPS
                135:   b'',            # RPC
                139:   b'',            # NetBIOS
                445:   b'',            # SMB
                3389:  b'',            # RDP
                5985:  b'',            # WinRM HTTP
                5986:  b'',            # WinRM HTTPS
                1433:  b'',            # MSSQL
                3306:  b'',            # MySQL
                5432:  b'',            # PostgreSQL
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
            logging.FileHandler(config.log_file, encoding='utf-8'),
            logging.StreamHandler()
        ]
    )

# ---------- TCP probe ----------
def probe_port(ip: str, port: int, config: Config) -> Optional[str]:
    """Вернёт первую строку ответа или 'open', если порт открыт без данных."""
    try:
        with socket.create_connection((ip, port), timeout=config.probe_timeout) as s:
            s.settimeout(config.probe_timeout)
            probe = config.ports_tcp_probe.get(port, b'')
            if probe:
                s.send(probe)
            banner = s.recv(256).splitlines()[0].decode(errors='ignore').strip()
            return banner or "open"
    except OSError as e:
        logging.debug(f"Порт {port} на {ip} закрыт: {e}")
        return None
    except Exception as e:
        logging.error(f"Ошибка при сканировании порта {port} на {ip}: {e}")
        return None

def tcp_scan(ip: str, config: Config) -> Dict[int, str]:
    """{port: response} для всех открытых портов."""
    results = {}
    for port in config.ports_tcp_probe:
        resp = probe_port(ip, port, config)
        if resp is not None:
            results[port] = resp
            logging.info(f"Открыт порт {port} на {ip}: {resp}")
    return results

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
            for port in (80, 443):
                protocol = 'https' if port == 443 else 'http'
                try:
                    page = browser_mgr.context.new_page()
                    page.goto(f"{protocol}://{ip}", timeout=config.web_timeout * 1000)
                    
                    folder = os.path.join("web", str(ip))
                    os.makedirs(folder, exist_ok=True)
                    
                    page.screenshot(path=os.path.join(folder, f"{port}.png"), full_page=True)
                    logging.info(f"Скриншот {protocol}://{ip} сохранен")
                    ok += 1
                except Exception as e:
                    logging.debug(f"Не удалось сделать скриншот {protocol}://{ip}: {e}")
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
def scan_host(ip: str, result_file: str, config: Config) -> Tuple[str, int, bool]:
    """Сканирует один хост"""
    try:
        tcp_results = tcp_scan(ip, config)
        save_result(ip, tcp_results, result_file)
        
        # Делаем веб-скриншоты только если есть открытые веб-порты
        web_ports = {80, 443}
        if any(port in tcp_results for port in web_ports):
            web_ok = screenshot_ip(ip, config)
        else:
            web_ok = 0
            
        return ip, web_ok, bool(tcp_results)
    except Exception as e:
        logging.error(f"Ошибка при сканировании {ip}: {e}")
        return ip, 0, False

def main():
    """Основная функция"""
    if len(sys.argv) < 2:
        print("Usage: python web.py <network> [threads]")
        print("Example: python web.py 172.30.1.0/24 10")
        sys.exit(1)

    # Загружаем конфигурацию
    config = load_config()
    setup_logging(config)
    
    # Парсим аргументы
    network_str = sys.argv[1]
    threads = int(sys.argv[2]) if len(sys.argv) > 2 else 10
    
    try:
        network = validate_network(network_str)
        threads = validate_threads(threads)
    except ValueError as e:
        print(f"Ошибка: {e}")
        sys.exit(1)

    result_file = f"scan-{network_str.replace('/', '_')}.txt"
    if os.path.exists(result_file):
        os.remove(result_file)
        logging.info(f"Удален старый файл результатов: {result_file}")

    hosts = list(network.hosts())
    logging.info(f"Начинаем сканирование {len(hosts)} хостов с {threads} потоками")
    print(f"Сканирование {len(hosts)} хостов с {threads} потоками...")

    with tqdm(total=len(hosts), unit="ip") as pbar:
        with ThreadPoolExecutor(max_workers=threads) as ex:
            futures = {ex.submit(scan_host, str(ip), result_file, config): ip for ip in hosts}
            for fut in as_completed(futures):
                try:
                    ip, web_ok, tcp_ok = fut.result()
                    pbar.set_postfix(ip=ip[-10:], w=web_ok, t=tcp_ok)
                    pbar.update(1)
                except Exception as e:
                    logging.error(f"Ошибка в потоке: {e}")
                    pbar.update(1)

    logging.info("Сканирование завершено")
    print("Готово.")
    print("Скриншоты → ./web/")
    print("TCP scan   →", result_file)

if __name__ == "__main__":
    # Отключаем предупреждения
    import urllib3, warnings
    urllib3.disable_warnings()
    warnings.filterwarnings("ignore")
    
    main()