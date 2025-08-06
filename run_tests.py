#!/usr/bin/env python3
"""
Скрипт для запуска тестов оптимизированного сетевого сканера
"""

import unittest
import sys
import os
import subprocess
from pathlib import Path


def run_tests():
    """Запуск всех тестов"""
    print("🧪 Запуск тестов оптимизированного сетевого сканера...")

    # Добавляем текущую директорию в путь
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

    # Загружаем тесты
    loader = unittest.TestLoader()
    start_dir = "tests"
    suite = loader.discover(start_dir, pattern="test_*.py")

    # Запускаем тесты с подробным выводом
    runner = unittest.TextTestRunner(verbosity=2, stream=sys.stdout)
    result = runner.run(suite)

    # Выводим статистику
    print(f"\n📊 Статистика тестов:")
    print(f"   • Запущено тестов: {result.testsRun}")
    print(
        f"   • Успешно: {result.testsRun - len(result.failures) - len(result.errors)}"
    )
    print(f"   • Ошибок: {len(result.errors)}")
    print(f"   • Провалов: {len(result.failures)}")

    if result.wasSuccessful():
        print("✅ Все тесты прошли успешно!")
        return True
    else:
        print("❌ Некоторые тесты не прошли")

        # Выводим детали ошибок
        if result.errors:
            print("\n🔴 Ошибки:")
            for test, traceback in result.errors:
                print(f"   • {test}: {traceback.split('AssertionError:')[-1].strip()}")

        if result.failures:
            print("\n🟡 Провалы:")
            for test, traceback in result.failures:
                print(f"   • {test}: {traceback.split('AssertionError:')[-1].strip()}")

        return False


def run_linting():
    """Запуск линтинга кода"""
    print("\n🔍 Запуск линтинга кода...")

    try:
        result = subprocess.run(
            [
                sys.executable,
                "-m",
                "flake8",
                "config.py",
                "network_scanner.py",
                "screenshot_manager.py",
                "report_generator.py",
                "main.py",
                "tests/",
            ],
            capture_output=True,
            text=True,
        )

        if result.returncode == 0:
            print("✅ Линтинг прошел успешно!")
            return True
        else:
            print("❌ Ошибки линтинга:")
            print(result.stdout)
            return False
    except Exception as e:
        print(f"❌ Ошибка при запуске линтинга: {e}")
        return False


def run_type_checking():
    """Запуск проверки типов"""
    print("\n🔍 Запуск проверки типов...")

    try:
        result = subprocess.run(
            [
                sys.executable,
                "-m",
                "mypy",
                "config.py",
                "network_scanner.py",
                "screenshot_manager.py",
                "report_generator.py",
                "main.py",
            ],
            capture_output=True,
            text=True,
        )

        if result.returncode == 0:
            print("✅ Проверка типов прошла успешно!")
            return True
        else:
            print("❌ Ошибки типизации:")
            print(result.stdout)
            return False
    except Exception as e:
        print(f"❌ Ошибка при проверке типов: {e}")
        return False


def run_security_check():
    """Запуск проверки безопасности"""
    print("\n🔒 Запуск проверки безопасности...")

    try:
        result = subprocess.run(
            [sys.executable, "-m", "bandit", "-r", "."], capture_output=True, text=True
        )

        if result.returncode == 0:
            print("✅ Проверка безопасности прошла успешно!")
            return True
        else:
            print("⚠️  Предупреждения безопасности:")
            print(result.stdout)
            return False
    except Exception as e:
        print(f"❌ Ошибка при проверке безопасности: {e}")
        return False


def main():
    """Главная функция запуска всех проверок"""
    print("🚀 Запуск полной проверки проекта")
    print("=" * 50)

    # Запускаем все проверки
    tests_ok = run_tests()
    lint_ok = run_linting()
    type_ok = run_type_checking()
    security_ok = run_security_check()

    # Итоговая статистика
    print("\n" + "=" * 50)
    print("📈 ИТОГОВАЯ СТАТИСТИКА:")
    print(f"   • Тесты: {'✅' if tests_ok else '❌'}")
    print(f"   • Линтинг: {'✅' if lint_ok else '❌'}")
    print(f"   • Типизация: {'✅' if type_ok else '❌'}")
    print(f"   • Безопасность: {'✅' if security_ok else '❌'}")

    all_passed = tests_ok and lint_ok and type_ok and security_ok

    if all_passed:
        print("\n🎉 Все проверки прошли успешно!")
        sys.exit(0)
    else:
        print("\n⚠️  Некоторые проверки не прошли")
        sys.exit(1)


if __name__ == "__main__":
    main()
