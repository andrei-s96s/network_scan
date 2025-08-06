#!/usr/bin/env python3
"""
Основные тесты для сетевого сканера
Объединенный файл всех тестов
"""

import unittest
import tempfile
import os
import sys
import ipaddress
import json
from unittest.mock import patch, Mock

# Добавляем родительскую директорию в путь для импорта
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from web import (
    Config, load_config, validate_network, validate_threads,
    probe_port, detect_os_from_banner, save_result_json,
    create_snmp_get_request
)


class TestConfig(unittest.TestCase):
    """Тесты для конфигурации"""
    
    def test_config_defaults(self):
        """Тест значений по умолчанию"""
        config = Config()
        self.assertEqual(config.probe_timeout, 5)
        self.assertEqual(config.web_timeout, 10)
        self.assertEqual(config.viewport_width, 1280)
        self.assertEqual(config.viewport_height, 720)
        self.assertIsNotNone(config.ports_tcp_probe)
        self.assertIn(80, config.ports_tcp_probe)
        self.assertIn(443, config.ports_tcp_probe)
        
        # Проверяем порты для IP устройств
        self.assertIn(5060, config.ports_tcp_probe)  # SIP
        self.assertIn(5061, config.ports_tcp_probe)  # SIP-TLS
        self.assertIn(10000, config.ports_tcp_probe)  # IP Phone Web
        self.assertIn(554, config.ports_tcp_probe)   # RTSP
        self.assertIn(8000, config.ports_tcp_probe)  # IP Camera Web
        self.assertIn(37777, config.ports_tcp_probe) # Dahua Camera
        self.assertIn(37778, config.ports_tcp_probe) # Dahua Camera
    
    def test_config_custom(self):
        """Тест пользовательской конфигурации"""
        config = Config(
            probe_timeout=10,
            web_timeout=20,
            viewport_width=1920,
            viewport_height=1080
        )
        self.assertEqual(config.probe_timeout, 10)
        self.assertEqual(config.web_timeout, 20)
        self.assertEqual(config.viewport_width, 1920)
        self.assertEqual(config.viewport_height, 1080)


class TestValidation(unittest.TestCase):
    """Тесты валидации"""
    
    def test_validate_network_valid(self):
        """Тест валидного сетевого адреса"""
        network = validate_network("192.168.1.0/24")
        self.assertIsInstance(network, ipaddress.IPv4Network)
        self.assertEqual(str(network), "192.168.1.0/24")
    
    def test_validate_network_invalid(self):
        """Тест невалидного сетевого адреса"""
        with self.assertRaises(ValueError):
            validate_network("invalid")
    
    def test_validate_threads_valid(self):
        """Тест валидного количества потоков"""
        result = validate_threads(10)
        self.assertEqual(result, 10)
    
    def test_validate_threads_invalid(self):
        """Тест невалидного количества потоков"""
        with self.assertRaises(ValueError):
            validate_threads(0)
        with self.assertRaises(ValueError):
            validate_threads(-1)


class TestConfigLoading(unittest.TestCase):
    """Тесты загрузки конфигурации"""
    
    def test_load_config_default(self):
        """Тест загрузки конфигурации по умолчанию"""
        config = load_config("nonexistent.yaml")
        self.assertIsInstance(config, Config)
        self.assertEqual(config.probe_timeout, 5)
    
    def test_load_config_from_file(self):
        """Тест загрузки конфигурации из файла"""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False) as f:
            f.write("""
probe_timeout: 10
web_timeout: 20
log_level: "DEBUG"
""")
            config_file = f.name
        
        try:
            config = load_config(config_file)
            self.assertEqual(config.probe_timeout, 10)
            self.assertEqual(config.web_timeout, 20)
            self.assertEqual(config.log_level, "DEBUG")
        finally:
            os.unlink(config_file)


class TestOSDetection(unittest.TestCase):
    """Тесты определения ОС"""
    
    def test_detect_windows(self):
        """Тест определения Windows"""
        banners = [
            "Microsoft Windows",
            "Windows Server",
            "IIS/8.5",
            "Microsoft-IIS/10.0"
        ]
        for banner in banners:
            os_type = detect_os_from_banner(banner, 80)
            self.assertIn("Windows", os_type)
    
    def test_detect_linux(self):
        """Тест определения Linux"""
        banners = [
            "Linux",
            "Ubuntu",
            "CentOS",
            "Apache/2.4.41 (Ubuntu)"
        ]
        for banner in banners:
            os_type = detect_os_from_banner(banner, 80)
            self.assertIn("Linux", os_type)
    
    def test_detect_network_device(self):
        """Тест определения сетевого устройства"""
        banners = [
            "Cisco",
            "Router",
            "Switch",
            "TP-Link"
        ]
        for banner in banners:
            os_type = detect_os_from_banner(banner, 161)
            self.assertIn("Network Device", os_type)


class TestIPDevices(unittest.TestCase):
    """Тесты для IP устройств"""
    
    def test_strict_validation(self):
        """Тест строгой валидации для специальных портов"""
        config = Config()

        # Тестируем, что невалидные ответы возвращают None
        with patch('socket.create_connection') as mock_conn:
            mock_socket = Mock()
            mock_socket.recv.return_value = b'HTTP/1.1 200 OK\r\n'  # Не SIP ответ
            mock_conn.return_value.__enter__.return_value = mock_socket

            result = probe_port("192.168.1.1", 5060, config)
            self.assertIsNone(result)  # Должен вернуть None для невалидного SIP ответа


class TestSNMP(unittest.TestCase):
    """Тесты для SNMP"""
    
    def test_snmp_packet_creation(self):
        """Тест создания SNMP пакета"""
        packet = create_snmp_get_request("public", "1.3.6.1.2.1.1.1.0")
        self.assertIsInstance(packet, bytes)
        self.assertGreater(len(packet), 0)


class TestJSONExport(unittest.TestCase):
    """Тесты для JSON экспорта"""
    
    def test_save_result_json(self):
        """Тест сохранения JSON"""
        test_data = {
            "192.168.1.1": {
                "80": "HTTP",
                "443": "HTTPS"
            }
        }
        
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            json_file = f.name
        
        try:
            save_result_json("192.168.1.1", test_data["192.168.1.1"], [], 2, "Linux")
            
            # Проверяем, что функция выполняется без ошибок
            self.assertTrue(True)
            
        finally:
            if os.path.exists(json_file):
                os.unlink(json_file)


class TestBasic(unittest.TestCase):
    """Базовые тесты для проверки работоспособности"""
    
    def test_import_web(self):
        """Тест импорта основного модуля"""
        try:
            import web
            self.assertTrue(True, "Модуль web успешно импортирован")
        except ImportError as e:
            self.fail(f"Не удалось импортировать модуль web: {e}")
    
    def test_file_structure(self):
        """Тест структуры файлов"""
        required_files = [
            "web.py",
            "config.yaml", 
            "requirements.txt",
            "README.md"
        ]
        
        for file_name in required_files:
            self.assertTrue(
                os.path.exists(file_name),
                f"Файл {file_name} должен существовать"
            )


if __name__ == '__main__':
    unittest.main()
