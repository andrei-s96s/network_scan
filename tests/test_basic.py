#!/usr/bin/env python3
"""
Простые базовые тесты для CI/CD
"""

import unittest
import sys
import os

# Добавляем родительскую директорию в путь для импорта
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

class TestBasic(unittest.TestCase):
    """Базовые тесты для проверки работоспособности"""
    
    def test_import_web(self):
        """Тест импорта основного модуля"""
        try:
            import web
            self.assertTrue(True, "Модуль web успешно импортирован")
        except ImportError as e:
            self.fail(f"Не удалось импортировать модуль web: {e}")
    
    def test_config_exists(self):
        """Тест существования конфигурации"""
        try:
            from web import Config
            config = Config()
            self.assertIsNotNone(config)
            self.assertEqual(config.probe_timeout, 5)
        except Exception as e:
            self.fail(f"Ошибка при создании конфигурации: {e}")
    
    def test_validation_functions(self):
        """Тест функций валидации"""
        try:
            from web import validate_network, validate_threads
            import ipaddress
            
            # Тест валидации сети
            network = validate_network("127.0.0.1/32")
            self.assertIsInstance(network, ipaddress.IPv4Network)
            
            # Тест валидации потоков
            threads = validate_threads(10)
            self.assertEqual(threads, 10)
            
        except Exception as e:
            self.fail(f"Ошибка в функциях валидации: {e}")
    
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
