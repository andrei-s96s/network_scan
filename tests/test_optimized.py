#!/usr/bin/env python3
"""
Тесты для оптимизированного сетевого сканера
"""

import unittest
import tempfile
import os
import sys
import json
from pathlib import Path
from unittest.mock import patch, Mock

# Добавляем родительскую директорию в путь для импорта
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# Импортируем модули для тестирования
from config import ScannerConfig, load_config
from network_scanner import NetworkScanner, ScanResult
from screenshot_manager import ScreenshotManager, ScreenshotTask
from report_generator import ReportGenerator
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

    def test_config_validation(self):
        """Тест валидации конфигурации"""
        # Валидная конфигурация
        config = ScannerConfig(
            probe_timeout=10, web_timeout=20, viewport_width=1920, viewport_height=1080
        )
        self.assertEqual(config.probe_timeout, 10)
        self.assertEqual(config.web_timeout, 20)

        # Невалидная конфигурация
        with self.assertRaises(ValueError):
            ScannerConfig(probe_timeout=0)

        with self.assertRaises(ValueError):
            ScannerConfig(web_timeout=-1)

        with self.assertRaises(ValueError):
            ScannerConfig(max_browsers=0)

    def test_setup_logging(self):
        """Тест настройки логирования"""
        config = ScannerConfig()
        config.setup_logging()
        # Проверяем, что логирование настроено
        self.assertIsNotNone(config.log_level)


class TestNetworkScanner(unittest.TestCase):
    """Тесты для сетевого сканера"""

    def setUp(self):
        """Настройка тестов"""
        self.config = ScannerConfig()
        self.scanner = NetworkScanner(self.config)

    def test_create_snmp_get_request(self):
        """Тест создания SNMP пакета"""
        packet = self.scanner.create_snmp_get_request()
        self.assertIsInstance(packet, bytes)
        self.assertGreater(len(packet), 0)

    def test_detect_os_from_banner(self):
        """Тест определения ОС по баннеру"""
        # Windows
        self.assertEqual(
            self.scanner.detect_os_from_banner("Microsoft-IIS/10.0", 80), "Windows"
        )

        # Linux
        self.assertEqual(
            self.scanner.detect_os_from_banner("SSH-2.0-OpenSSH_8.2p1", 22), "Linux"
        )

        # IP Phone
        self.assertEqual(
            self.scanner.detect_os_from_banner("SIP/2.0 200 OK", 5060), "IP Phone"
        )

        # IP Camera
        self.assertEqual(
            self.scanner.detect_os_from_banner("RTSP/1.0 200 OK", 554), "IP Camera"
        )

        # Неизвестная ОС
        self.assertIsNone(self.scanner.detect_os_from_banner("Unknown Service", 1234))

    @patch("socket.socket")
    def test_probe_port_success(self, mock_socket):
        """Тест успешного сканирования порта"""
        mock_sock = Mock()
        mock_socket.return_value = mock_sock
        mock_sock.connect_ex.return_value = 0
        mock_sock.recv.return_value = b"HTTP/1.1 200 OK\r\n"

        result = self.scanner.probe_port("192.168.1.1", 80)
        self.assertEqual(result, "HTTP/1.1 200 OK")

    @patch("socket.socket")
    def test_probe_port_connection_refused(self, mock_socket):
        """Тест сканирования закрытого порта"""
        mock_sock = Mock()
        mock_socket.return_value = mock_sock
        mock_sock.connect_ex.return_value = 1

        result = self.scanner.probe_port("192.168.1.1", 1234)
        self.assertIsNone(result)

    def test_scan_result_validation(self):
        """Тест валидации результата сканирования"""
        # Валидный результат
        result = ScanResult(ip="192.168.1.1", open_ports={80: "HTTP/1.1 200 OK"})
        self.assertEqual(result.ip, "192.168.1.1")
        self.assertEqual(len(result.open_ports), 1)

        # Невалидный результат
        with self.assertRaises(ValueError):
            ScanResult(ip="", open_ports={})

        with self.assertRaises(ValueError):
            ScanResult(ip="192.168.1.1", open_ports="invalid")


class TestScreenshotManager(unittest.TestCase):
    """Тесты для менеджера скриншотов"""

    def setUp(self):
        """Настройка тестов"""
        self.config = ScannerConfig()

    def test_screenshot_task_validation(self):
        """Тест валидации задачи скриншота"""
        # Валидная задача
        task = ScreenshotTask(ip="192.168.1.1", port=80, protocol="http")
        self.assertEqual(task.ip, "192.168.1.1")
        self.assertEqual(task.port, 80)
        self.assertEqual(task.protocol, "http")

        # Невалидная задача
        with self.assertRaises(ValueError):
            ScreenshotTask(ip="", port=80)

        with self.assertRaises(ValueError):
            ScreenshotTask(ip="192.168.1.1", port=0)

        with self.assertRaises(ValueError):
            ScreenshotTask(ip="192.168.1.1", port=80, protocol="ftp")

    def test_get_web_ports(self):
        """Тест получения веб-портов"""
        scan_result = ScanResult(
            ip="192.168.1.1",
            open_ports={80: "HTTP", 443: "HTTPS", 22: "SSH", 8080: "HTTP"},
        )

        manager = ScreenshotManager(self.config)
        tasks = manager._get_web_ports(scan_result)

        # Проверяем, что найдены веб-порты
        ports = [task.port for task in tasks]
        self.assertIn(80, ports)
        self.assertIn(443, ports)
        self.assertIn(8080, ports)
        self.assertNotIn(22, ports)  # SSH не веб-порт


class TestReportGenerator(unittest.TestCase):
    """Тесты для генератора отчетов"""

    def setUp(self):
        """Настройка тестов"""
        self.temp_dir = tempfile.mkdtemp()
        self.output_dir = Path(self.temp_dir)
        self.report_gen = ReportGenerator(self.output_dir)

        # Тестовые данные
        self.scan_results = [
            ScanResult(
                ip="192.168.1.1",
                open_ports={80: "HTTP/1.1 200 OK", 443: "open"},
                detected_os="Linux",
            ),
            ScanResult(
                ip="192.168.1.2",
                open_ports={22: "SSH-2.0-OpenSSH_8.2p1"},
                detected_os="Linux",
            ),
        ]

    def tearDown(self):
        """Очистка после тестов"""
        import shutil

        shutil.rmtree(self.temp_dir)

    def test_save_text_report(self):
        """Тест сохранения текстового отчета"""
        network = "192.168.1.0/24"
        report_path = self.report_gen.save_text_report(self.scan_results, network)

        self.assertTrue(report_path.exists())

        with open(report_path, "r", encoding="utf-8") as f:
            content = f.read()
            self.assertIn("192.168.1.1", content)
            self.assertIn("192.168.1.2", content)

    def test_save_json_report(self):
        """Тест сохранения JSON отчета"""
        network = "192.168.1.0/24"
        screenshots_count = {"192.168.1.1": 2}

        report_path = self.report_gen.save_json_report(
            self.scan_results, network, screenshots_count
        )

        self.assertTrue(report_path.exists())

        with open(report_path, "r", encoding="utf-8") as f:
            data = json.load(f)
            self.assertEqual(data["scan_info"]["network"], network)
            self.assertEqual(len(data["hosts"]), 2)
            self.assertIn("192.168.1.1", [h["ip"] for h in data["hosts"]])

    def test_save_html_report(self):
        """Тест сохранения HTML отчета"""
        network = "192.168.1.0/24"
        screenshots_count = {"192.168.1.1": 2}

        report_path = self.report_gen.save_html_report(
            self.scan_results, network, screenshots_count
        )

        self.assertTrue(report_path.exists())

        with open(report_path, "r", encoding="utf-8") as f:
            content = f.read()
            self.assertIn("192.168.1.1", content)
            self.assertIn("192.168.1.2", content)
            self.assertIn("<!DOCTYPE html>", content)

    def test_get_service_name(self):
        """Тест получения названия сервиса"""
        self.assertEqual(self.report_gen._get_service_name(80), "HTTP")
        self.assertEqual(self.report_gen._get_service_name(443), "HTTPS")
        self.assertEqual(self.report_gen._get_service_name(22), "SSH")
        self.assertEqual(self.report_gen._get_service_name(1234), "Unknown")


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

        with self.assertRaises(ValueError):
            validate_network("not.an.ip.address")

    def test_validate_threads_valid(self):
        """Тест валидного количества потоков"""
        self.assertEqual(validate_threads(10), 10)
        self.assertEqual(validate_threads(1), 1)
        self.assertEqual(validate_threads(50), 50)

    def test_validate_threads_invalid(self):
        """Тест невалидного количества потоков"""
        with self.assertRaises(ValueError):
            validate_threads(0)

        with self.assertRaises(ValueError):
            validate_threads(-1)

        with self.assertRaises(ValueError):
            validate_threads(101)


class TestIntegration(unittest.TestCase):
    """Интеграционные тесты"""

    def test_load_config(self):
        """Тест загрузки конфигурации"""
        config = load_config()
        self.assertIsInstance(config, ScannerConfig)
        self.assertEqual(config.probe_timeout, 5)

    def test_report_generator_service_names(self):
        """Тест соответствия названий сервисов"""
        report_gen = ReportGenerator()

        # Проверяем основные сервисы
        self.assertEqual(report_gen._get_service_name(80), "HTTP")
        self.assertEqual(report_gen._get_service_name(443), "HTTPS")
        self.assertEqual(report_gen._get_service_name(22), "SSH")
        self.assertEqual(report_gen._get_service_name(5060), "Unknown")
        self.assertEqual(report_gen._get_service_name(554), "Unknown")


if __name__ == "__main__":
    unittest.main()
