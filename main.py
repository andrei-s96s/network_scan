#!/usr/bin/env python3
"""
Оптимизированный сетевой сканер с веб-скриншотами и асинхронным сканированием
"""

import sys
import argparse
import logging
import asyncio
from pathlib import Path
from colorama import init, Fore, Back, Style

from config import load_config
from network_scanner import AsyncNetworkScanner
from screenshot_manager import ScreenshotManager, AsyncScreenshotManager
from report_generator import ReportGenerator

# Инициализация colorama для цветного вывода
init(autoreset=True)


def validate_network(network_str: str) -> str:
    """Валидирует сетевой адрес"""
    import ipaddress

    try:
        network = ipaddress.IPv4Network(network_str, strict=False)
        return str(network)
    except ValueError:
        raise ValueError(f"Неверный формат сети: {network_str}")


def validate_threads(threads: int) -> int:
    """Валидирует количество потоков"""
    if threads <= 0:
        raise ValueError("Количество потоков должно быть положительным")
    if threads > 100:
        raise ValueError("Количество потоков не может превышать 100")
    return threads


def print_colored(text: str, color: str = Fore.WHITE, style: str = ""):
    """Выводит цветной текст"""
    print(f"{color}{style}{text}{Style.RESET_ALL}")


async def main_async():
    """Асинхронная главная функция"""
    parser = argparse.ArgumentParser(
        description="Сетевой сканер с веб-скриншотами и асинхронным сканированием",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Примеры использования:
  python main.py 172.30.1.0/24 10
  python main.py 192.168.1.0/24 5 --no-reports
  python main.py 10.0.0.0/24 20 --config custom_config.yaml
  python main.py 192.168.1.0/24 --async  # Асинхронное сканирование
        """,
    )

    parser.add_argument(
        "network", help="Сеть для сканирования (например: 192.168.1.0/24)"
    )

    parser.add_argument(
        "threads",
        type=int,
        nargs="?",
        default=10,
        help="Количество потоков (по умолчанию: 10)",
    )

    parser.add_argument(
        "--no-reports",
        action="store_true",
        help="Не создавать JSON и HTML отчеты (только текстовый)",
    )

    parser.add_argument("--config", type=Path, help="Путь к файлу конфигурации")

    parser.add_argument(
        "--output-dir",
        type=Path,
        default=Path("."),
        help="Директория для сохранения результатов",
    )

    parser.add_argument("--verbose", "-v", action="store_true", help="Подробный вывод")

    parser.add_argument(
        "--async-scan", 
        action="store_true", 
        help="Использовать асинхронное сканирование (рекомендуется)"
    )

    args = parser.parse_args()

    try:
        # Валидация аргументов
        network = validate_network(args.network)
        threads = validate_threads(args.threads)

        # Загружаем конфигурацию
        config = load_config()
        
        # Применяем опции командной строки
        if args.verbose:
            config.log_level = "DEBUG"
        config.output_dir = args.output_dir

        # Настройка логирования
        config.setup_logging()
        logger = logging.getLogger(__name__)

        print_colored("🚀 Запуск оптимизированного сетевого сканера", Fore.CYAN, Style.BRIGHT)
        print_colored(f"Сеть: {network}", Fore.GREEN)
        print_colored(f"Потоки: {threads}", Fore.GREEN)
        print_colored(f"Выходная директория: {config.output_dir}", Fore.GREEN)
        
        if args.async_scan:
            print_colored("⚡ Асинхронное сканирование включено", Fore.YELLOW, Style.BRIGHT)

        # Проверка безопасности
        if not network.startswith(("192.168.", "172.", "10.", "127.")):
            print_colored("⚠️  ВНИМАНИЕ: Сканирование публичной сети!", Fore.RED, Style.BRIGHT)
            print_colored(
                "Убедитесь, что у вас есть разрешение на сканирование этой сети",
                Fore.RED
            )

        # Создание компонентов
        scanner = AsyncNetworkScanner(config)
        report_gen = ReportGenerator(config.output_dir)

        # Сканирование сети
        print_colored("🔍 Начинаем сканирование сети...", Fore.CYAN)
        
        if args.async_scan:
            # Асинхронное сканирование
            scan_results = await scanner.scan_network_async(network, max_workers=threads)
        else:
            # Синхронное сканирование (для обратной совместимости)
            scan_results = scanner.scan_network(network, max_workers=threads)

        if not scan_results:
            print_colored("📭 Не найдено хостов с открытыми портами", Fore.YELLOW)
            return

        print_colored(f"✅ Сканирование завершено. Найдено {len(scan_results)} хостов", Fore.GREEN)

        # Создание скриншотов
        screenshots_count = {}
        if scan_results:
            print_colored("📸 Создание скриншотов...", Fore.CYAN)
            
            # Создаем каталог для сети
            network_name = network.replace('/', '_')
            network_dir = config.output_dir / f"scan-{network_name}"
            network_dir.mkdir(parents=True, exist_ok=True)
            
            if args.async_scan:
                # Асинхронное создание скриншотов
                async with AsyncScreenshotManager(config) as screenshot_mgr:
                    screenshots_count = await screenshot_mgr.create_screenshots_async(
                        scan_results, network_dir
                    )
            else:
                # Синхронное создание скриншотов (для обратной совместимости)
                with ScreenshotManager(config) as screenshot_mgr:
                    screenshots_count = screenshot_mgr.create_screenshots(
                        scan_results, network_dir
                    )

        # Генерация отчетов
        print_colored("📊 Создание отчетов...", Fore.CYAN)

        # Текстовый отчет всегда создается
        text_report = report_gen.save_text_report(scan_results, network)
        print_colored(f"📄 Текстовый отчет: {text_report}", Fore.GREEN)

        # JSON и HTML отчеты (по умолчанию создаются)
        if not args.no_reports:
            json_report = report_gen.save_json_report(
                scan_results, network, screenshots_count
            )
            html_report = report_gen.save_html_report(
                scan_results, network, screenshots_count
            )
            print_colored(f"📊 JSON отчет: {json_report}", Fore.GREEN)
            print_colored(f"🌐 HTML отчет: {html_report}", Fore.GREEN)

        # Финальная статистика
        total_ports = sum(len(result.open_ports) for result in scan_results)
        total_screenshots = sum(screenshots_count.values())
        total_scan_time = sum(result.scan_time for result in scan_results)

        print_colored("🎉 Сканирование завершено успешно!", Fore.GREEN, Style.BRIGHT)
        print_colored("📈 Статистика:", Fore.CYAN)
        print_colored(f"   • Найдено хостов: {len(scan_results)}", Fore.WHITE)
        print_colored(f"   • Открытых портов: {total_ports}", Fore.WHITE)
        print_colored(f"   • Создано скриншотов: {total_screenshots}", Fore.WHITE)
        print_colored(f"   • Общее время сканирования: {total_scan_time:.2f}с", Fore.WHITE)

        # Список найденных сервисов
        all_services = set()
        for result in scan_results:
            for port in result.open_ports.keys():
                all_services.add(report_gen._get_service_name(port))

        if all_services:
            print_colored("🔧 Обнаруженные сервисы: " + ", ".join(sorted(all_services)), Fore.YELLOW)

    except KeyboardInterrupt:
        print_colored("⏹️  Сканирование прервано пользователем", Fore.RED)
        sys.exit(1)
    except ValueError as e:
        print_colored(f"❌ Ошибка валидации: {e}", Fore.RED)
        sys.exit(1)
    except Exception as e:
        print_colored(f"❌ Неожиданная ошибка: {e}", Fore.RED)
        if args.verbose:
            import traceback
            print_colored(traceback.format_exc(), Fore.RED)
        sys.exit(1)


def main():
    """Главная функция с улучшенной обработкой ошибок"""
    try:
        asyncio.run(main_async())
    except KeyboardInterrupt:
        print_colored("⏹️  Сканирование прервано пользователем", Fore.RED)
        sys.exit(1)


if __name__ == "__main__":
    main()
