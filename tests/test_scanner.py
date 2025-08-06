#!/usr/bin/env python3
"""
Тесты для сетевого сканера
"""

import unittest
import tempfile
import os
import sys
from unittest.mock import patch, MagicMock
import ipaddress

# Добавляем родительскую директорию в путь для импорта
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from web import (
    Config, load_config, setup_logging, probe_port, tcp_scan,
    validate_network, validate_threads, BrowserManager
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


class TestTCPScan(unittest.TestCase):
    """Тесты TCP сканирования"""
    
    def setUp(self):
        """Настройка тестов"""
        self.config = Config()
    
    @patch('web.socket.create_connection')
    def test_probe_port_open(self, mock_socket):
        """Тест открытого порта"""
        # Мокаем сокет
        mock_socket.return_value.__enter__.return_value.recv.return_value = b"SSH-2.0-OpenSSH_8.2p1\n"
        
        result = probe_port("192.168.1.1", 22, self.config)
        self.assertEqual(result, "SSH-2.0-OpenSSH_8.2p1")
    
    @patch('web.socket.create_connection')
    def test_probe_port_closed(self, mock_socket):
        """Тест закрытого порта"""
        # Мокаем исключение для закрытого порта
        mock_socket.side_effect = OSError("Connection refused")
        
        result = probe_port("192.168.1.1", 9999, self.config)
        self.assertIsNone(result)
    
    @patch('web.probe_port')
    def test_tcp_scan(self, mock_probe):
        """Тест TCP сканирования"""
        # Мокаем результаты сканирования
        mock_probe.side_effect = lambda ip, port, config: "open" if port in [80, 443] else None
        
        results = tcp_scan("192.168.1.1", self.config)
        self.assertIn(80, results)
        self.assertIn(443, results)
        self.assertEqual(results[80], "open")
        self.assertEqual(results[443], "open")


class TestBrowserManager(unittest.TestCase):
    """Тесты менеджера браузера"""
    
    def setUp(self):
        """Настройка тестов"""
        self.config = Config()
    
    @patch('web.sync_playwright')
    def test_browser_manager_context(self, mock_playwright):
        """Тест контекстного менеджера браузера"""
        # Мокаем Playwright
        mock_pw = MagicMock()
        mock_browser = MagicMock()
        mock_context = MagicMock()
        
        mock_playwright.return_value.__enter__.return_value = mock_pw
        mock_pw.chromium.launch.return_value = mock_browser
        mock_browser.new_context.return_value = mock_context
        
        with BrowserManager(self.config) as bm:
            self.assertEqual(bm.config, self.config)
            self.assertEqual(bm.browser, mock_browser)
            self.assertEqual(bm.context, mock_context)


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


if __name__ == '__main__':
    unittest.main() 