#!/usr/bin/env python3
"""
Менеджер скриншотов для сетевого сканера
"""

import logging
from pathlib import Path
from typing import List, Optional, Dict
from dataclasses import dataclass
from playwright.sync_api import sync_playwright, Browser
from concurrent.futures import ThreadPoolExecutor, as_completed

from config import ScannerConfig
from network_scanner import ScanResult


@dataclass
class ScreenshotTask:
    """Задача для создания скриншота"""

    ip: str
    port: int
    protocol: str = "http"

    def __post_init__(self):
        """Валидация задачи"""
        if not self.ip:
            raise ValueError("IP адрес не может быть пустым")
        if not 1 <= self.port <= 65535:
            raise ValueError("Порт должен быть в диапазоне 1-65535")
        if self.protocol not in ["http", "https"]:
            raise ValueError("Протокол должен быть http или https")


class ScreenshotManager:
    """Оптимизированный менеджер скриншотов"""

    def __init__(self, config: ScannerConfig):
        self.config = config
        self.logger = logging.getLogger(__name__)
        self._browser_pool: List[Browser] = []
        self._current_browser_index = 0

    def __enter__(self):
        """Контекстный менеджер - инициализация браузеров"""
        self._init_browsers()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """Контекстный менеджер - закрытие браузеров"""
        self._close_browsers()

    def _init_browsers(self):
        """Инициализирует пул браузеров"""
        try:
            self.playwright = sync_playwright().start()

            for _ in range(self.config.max_browsers):
                browser = self.playwright.chromium.launch(
                    headless=True,
                    args=[
                        "--no-sandbox",
                        "--disable-dev-shm-usage",
                        "--disable-gpu",
                        "--disable-web-security",
                        "--disable-features=VizDisplayCompositor",
                    ],
                )
                self._browser_pool.append(browser)

            self.logger.info(f"Инициализировано {len(self._browser_pool)} браузеров")

        except Exception as e:
            self.logger.error(f"Ошибка при инициализации браузеров: {e}")
            raise

    def _close_browsers(self):
        """Закрывает все браузеры"""
        for browser in self._browser_pool:
            try:
                browser.close()
            except Exception as e:
                self.logger.warning(f"Ошибка при закрытии браузера: {e}")

        try:
            self.playwright.stop()
        except Exception as e:
            self.logger.warning(f"Ошибка при остановке playwright: {e}")

    def _get_next_browser(self) -> Browser:
        """Получает следующий браузер из пула"""
        browser = self._browser_pool[self._current_browser_index]
        self._current_browser_index = (self._current_browser_index + 1) % len(
            self._browser_pool
        )
        return browser

    def _create_screenshot(self, task: ScreenshotTask, network_dir: Path) -> Optional[Path]:
        """Создает скриншот для одного порта"""
        try:
            browser = self._get_next_browser()
            context = browser.new_context(
                viewport={
                    "width": self.config.viewport_width,
                    "height": self.config.viewport_height,
                },
                ignore_https_errors=True,
            )

            page = context.new_page()

            # Формируем URL
            url = f"{task.protocol}://{task.ip}:{task.port}/"

            # Пытаемся загрузить страницу
            try:
                response = page.goto(
                    url,
                    wait_until="domcontentloaded",
                    timeout=self.config.web_timeout * 1000,
                )

                if response and response.status < 400:
                    # Создаем директорию для скриншотов в каталоге сети
                    screenshots_dir = network_dir / "screenshots"
                    screenshots_dir.mkdir(parents=True, exist_ok=True)

                    # Сохраняем скриншот с именем IP_порт.png
                    screenshot_path = screenshots_dir / f"{task.ip}_{task.port}.png"
                    page.screenshot(path=str(screenshot_path), full_page=True)

                    self.logger.debug(f"Скриншот создан: {screenshot_path}")
                    return screenshot_path
                else:
                    self.logger.debug(
                        f"HTTP ошибка для {url}: {response.status if response else 'No response'}"
                    )

            except Exception as e:
                self.logger.debug(f"Ошибка при загрузке {url}: {e}")

            finally:
                page.close()
                context.close()

        except Exception as e:
            self.logger.warning(
                f"Ошибка при создании скриншота для {task.ip}:{task.port}: {e}"
            )

        return None

    def _get_web_ports(self, scan_result: ScanResult) -> List[ScreenshotTask]:
        """Получает список веб-портов для скриншотов"""
        web_ports = []

        # Порты для HTTP
        http_ports = {80, 8080, 10000, 8000, 37777, 37778}
        # Порты для HTTPS
        https_ports = {443}

        for port in scan_result.open_ports.keys():
            if port in http_ports:
                web_ports.append(ScreenshotTask(scan_result.ip, port, "http"))
            elif port in https_ports:
                web_ports.append(ScreenshotTask(scan_result.ip, port, "https"))

        return web_ports

    def create_screenshots(
        self, scan_results: List[ScanResult], network_dir: Path, max_workers: int = 3
    ) -> Dict[str, int]:
        """Создает скриншоты для всех результатов сканирования"""
        if not scan_results:
            return {}

        # Собираем все задачи для скриншотов
        all_tasks = []
        for result in scan_results:
            tasks = self._get_web_ports(result)
            all_tasks.extend(tasks)

        if not all_tasks:
            self.logger.info("Нет веб-портов для создания скриншотов")
            return {}

        self.logger.info(f"Создание скриншотов для {len(all_tasks)} портов")

        # Создаем скриншоты последовательно для избежания проблем с многопоточностью
        screenshots_created = {}
        for task in all_tasks:
            try:
                screenshot_path = self._create_screenshot(task, network_dir)
                if screenshot_path:
                    screenshots_created[task.ip] = (
                        screenshots_created.get(task.ip, 0) + 1
                    )
            except Exception as e:
                self.logger.error(
                    f"Ошибка при создании скриншота для {task.ip}:{task.port}: {e}"
                )

        self.logger.info(
            f"Создано скриншотов: {sum(screenshots_created.values())} для {len(screenshots_created)} хостов"
        )
        return screenshots_created
