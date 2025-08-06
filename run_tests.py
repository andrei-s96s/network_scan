#!/usr/bin/env python3
"""
Скрипт для запуска тестов
"""

import unittest
import sys
import os

def run_tests():
    """Запуск всех тестов"""
    print("🧪 Запуск тестов...")
    
    # Добавляем текущую директорию в путь
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    
    # Загружаем тесты из test_main.py
    loader = unittest.TestLoader()
    start_dir = 'tests'
    suite = loader.discover(start_dir, pattern='test_*.py')
    
    # Запускаем тесты
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    
    if result.wasSuccessful():
        print("✅ Все тесты прошли успешно!")
        return True
    else:
        print("❌ Некоторые тесты не прошли")
        return False

if __name__ == "__main__":
    success = run_tests()
    sys.exit(0 if success else 1) 