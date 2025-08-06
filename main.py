#!/usr/bin/env python3
"""
Оптимизированный сетевой сканер с веб-скриншотами
"""

import sys
import argparse
import logging
from pathlib import Path

from config import load_config
from network_scanner import NetworkScanner
from screenshot_manager import ScreenshotManager
from report_generator import ReportGenerator


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


def main():
    """Главная функция с улучшенной обработкой ошибок"""
    parser = argparse.ArgumentParser(
        description="Сетевой сканер с веб-скриншотами",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Примеры использования:
  python main.py 172.30.1.0/24 10
  python main.py 192.168.1.0/24 5 --no-reports
  python main.py 10.0.0.0/24 20 --config custom_config.yaml
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

        logger.info("🚀 Запуск оптимизированного сетевого сканера")
        logger.info(f"Сеть: {network}")
        logger.info(f"Потоки: {threads}")
        logger.info(f"Выходная директория: {config.output_dir}")

        # Проверка безопасности
        if not network.startswith(("192.168.", "172.", "10.", "127.")):
            logger.warning("⚠️  ВНИМАНИЕ: Сканирование публичной сети!")
            logger.warning(
                "Убедитесь, что у вас есть разрешение на сканирование этой сети"
            )

        # Создание компонентов
        scanner = NetworkScanner(config)
        report_gen = ReportGenerator(config.output_dir)

        # Сканирование сети
        logger.info("🔍 Начинаем сканирование сети...")
        scan_results = scanner.scan_network(network, max_workers=threads)

        if not scan_results:
            logger.info("📭 Не найдено хостов с открытыми портами")
            return

        logger.info(f"✅ Сканирование завершено. Найдено {len(scan_results)} хостов")

        # Создание скриншотов
        screenshots_count = {}
        if scan_results:
            logger.info("📸 Создание скриншотов...")
            with ScreenshotManager(config) as screenshot_mgr:
                # Создаем каталог для сети
                network_name = network.replace('/', '_')
                network_dir = config.output_dir / f"scan-{network_name}"
                network_dir.mkdir(parents=True, exist_ok=True)
                
                screenshots_count = screenshot_mgr.create_screenshots(
                    scan_results, network_dir
                )

        # Генерация отчетов
        logger.info("📊 Создание отчетов...")

        # Текстовый отчет всегда создается
        text_report = report_gen.save_text_report(scan_results, network)
        logger.info(f"📄 Текстовый отчет: {text_report}")

        # JSON и HTML отчеты (по умолчанию создаются)
        if not args.no_reports:
            json_report = report_gen.save_json_report(
                scan_results, network, screenshots_count
            )
            html_report = report_gen.save_html_report(
                scan_results, network, screenshots_count
            )
            logger.info(f"📊 JSON отчет: {json_report}")
            logger.info(f"🌐 HTML отчет: {html_report}")

        # Финальная статистика
        total_ports = sum(len(result.open_ports) for result in scan_results)
        total_screenshots = sum(screenshots_count.values())

        logger.info("🎉 Сканирование завершено успешно!")
        logger.info("📈 Статистика:")
        logger.info(f"   • Найдено хостов: {len(scan_results)}")
        logger.info(f"   • Открытых портов: {total_ports}")
        logger.info(f"   • Создано скриншотов: {total_screenshots}")

        # Список найденных сервисов
        all_services = set()
        for result in scan_results:
            for port in result.open_ports.keys():
                all_services.add(report_gen._get_service_name(port))

        if all_services:
            logger.info("🔧 Обнаруженные сервисы: " + ", ".join(sorted(all_services)))

    except KeyboardInterrupt:
        logger.info("⏹️  Сканирование прервано пользователем")
        sys.exit(1)
    except ValueError as e:
        logger.error(f"❌ Ошибка валидации: {e}")
        sys.exit(1)
    except Exception as e:
        logger.error(f"❌ Неожиданная ошибка: {e}")
        if args.verbose:
            import traceback

            logger.error(traceback.format_exc())
        sys.exit(1)


if __name__ == "__main__":
    main()
