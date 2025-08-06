#!/usr/bin/env python3
"""
Тесты для сетевого сканера
"""

import unittest
import os
import sys
import ipaddress

# Добавляем родительскую директорию в путь для импорта
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# Импортируем модули для тестирования
from config import ScannerConfig, load_config
from network_scanner import NetworkScanner, ScanResult
from main import validate_network, validate_threads


class TestConfig(unittest.TestCase):
    """Тесты для конфигурации"""

    def test_config_defaults(self):
        """Тест значений по умолчанию"""
        config = ScannerConfig()
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
        self.assertIn(554, config.ports_tcp_probe)  # RTSP
        self.assertIn(8000, config.ports_tcp_probe)  # IP Camera Web
        self.assertIn(37777, config.ports_tcp_probe)  # Dahua Camera
        self.assertIn(37778, config.ports_tcp_probe)  # Dahua Camera

    def test_config_custom(self):
        """Тест пользовательской конфигурации"""
        config = ScannerConfig(
            probe_timeout=10, web_timeout=20, viewport_width=1920, viewport_height=1080
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
        self.assertEqual(network, "192.168.1.0/24")

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
        config = load_config()
        self.assertIsInstance(config, ScannerConfig)
        self.assertEqual(config.probe_timeout, 5)
        self.assertEqual(config.web_timeout, 10)


class TestOSDetection(unittest.TestCase):
    """Тесты определения ОС"""

    def test_detect_windows(self):
        """Тест определения Windows"""
        scanner = NetworkScanner(ScannerConfig())
        banners = [
            "Microsoft Windows",
            "Windows Server",
            "IIS/8.5",
            "Microsoft-IIS/10.0",
        ]
        for banner in banners:
            result = scanner.detect_os_from_banner(banner, 80)
            self.assertEqual(result, "Windows")

    def test_detect_linux(self):
        """Тест определения Linux"""
        scanner = NetworkScanner(ScannerConfig())
        banners = [
            "SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.2",
            "Apache/2.4.41 (Ubuntu)",
            "nginx/1.18.0 (Ubuntu)",
        ]
        for banner in banners:
            result = scanner.detect_os_from_banner(banner, 22)
            self.assertEqual(result, "Linux")

    def test_detect_network_device(self):
        """Тест определения сетевого устройства"""
        scanner = NetworkScanner(ScannerConfig())
        
        # Тест для SIP (IP Phone)
        result = scanner.detect_os_from_banner("SIP/2.0 200 OK", 5060)
        self.assertEqual(result, "IP Phone")
        
        # Тест для RTSP (IP Camera)
        result = scanner.detect_os_from_banner("RTSP/1.0 200 OK", 554)
        self.assertEqual(result, "IP Camera")


class TestIPDevices(unittest.TestCase):
    """Тесты для IP устройств"""

    def test_strict_validation(self):
        """Тест строгой валидации для специальных портов"""
        scanner = NetworkScanner(ScannerConfig())
        # Проверяем, что SNMP пакет создается корректно
        packet = scanner.create_snmp_get_request()
        self.assertIsInstance(packet, bytes)
        self.assertGreater(len(packet), 0)


class TestSNMP(unittest.TestCase):
    """Тесты SNMP"""

    def test_snmp_packet_creation(self):
        """Тест создания SNMP пакета"""
        scanner = NetworkScanner(ScannerConfig())
        packet = scanner.create_snmp_get_request()
        self.assertIsInstance(packet, bytes)
        self.assertGreater(len(packet), 0)


class TestJSONExport(unittest.TestCase):
    """Тесты экспорта JSON"""

    def test_save_result_json(self):
        """Тест сохранения JSON"""
        from report_generator import ReportGenerator
        import tempfile
        import json
        from pathlib import Path

        # Создаем временную директорию
        with tempfile.TemporaryDirectory() as temp_dir:
            report_gen = ReportGenerator(Path(temp_dir))
            
            # Тестовые данные
            scan_results = [
                ScanResult(
                    ip="192.168.1.1",
                    open_ports={80: "HTTP/1.1 200 OK"},
                    detected_os="Linux"
                )
            ]
            
            # Сохраняем JSON
            json_path = report_gen.save_json_report(scan_results, "192.168.1.0/24")
            
            # Проверяем, что файл создан
            self.assertTrue(json_path.exists())
            
            # Проверяем содержимое
            with open(json_path, "r", encoding="utf-8") as f:
                data = json.load(f)
                self.assertEqual(data["scan_info"]["network"], "192.168.1.0/24")
                self.assertEqual(len(data["hosts"]), 1)


class TestBasic(unittest.TestCase):
    """Базовые тесты"""

    def test_import_web(self):
        """Тест импорта основного модуля"""
        try:
            # Проверяем, что новые модули импортируются
            from config import ScannerConfig
            from network_scanner import NetworkScanner
            from screenshot_manager import ScreenshotManager
            from report_generator import ReportGenerator
            from main import validate_network, validate_threads
            
            self.assertTrue(True, "Все модули успешно импортированы")
        except ImportError as e:
            self.fail("Не удалось импортировать модули: " + str(e))

    def test_file_structure(self):
        """Тест структуры файлов"""
        required_files = [
            "main.py", "config.py", "network_scanner.py", 
            "screenshot_manager.py", "report_generator.py",
            "requirements.txt", "README.md"
        ]
        
        for file_name in required_files:
            self.assertTrue(
                os.path.exists(file_name),
                f"Файл {file_name} не найден"
            )


if __name__ == "__main__":
    unittest.main()
