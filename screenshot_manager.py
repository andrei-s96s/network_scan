#!/usr/bin/env python3
"""
Менеджер скриншотов с поддержкой асинхронного режима
"""

import asyncio
import logging
from pathlib import Path
from typing import Dict, List, Optional
from contextlib import asynccontextmanager

from config import ScannerConfig
from network_scanner import ScanResult


class AsyncScreenshotManager:
    """Асинхронный менеджер скриншотов с поддержкой Playwright Async API"""

    def __init__(self, config: ScannerConfig):
        self.config = config
        self.logger = logging.getLogger(__name__)
        self.browsers = []
        self.browser_contexts = []

    async def __aenter__(self):
        """Асинхронный вход в контекст"""
        await self._initialize_browsers()
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Асинхронный выход из контекста"""
        await self._cleanup_browsers()

    async def _initialize_browsers(self):
        """Инициализирует браузеры асинхронно"""
        try:
            from playwright.async_api import async_playwright

            self.playwright = await async_playwright().start()
            
            # Создаем несколько браузеров для параллельной работы
            for i in range(self.config.max_browsers):
                browser = await self.playwright.chromium.launch(
                    headless=True,
                    args=[
                        f"--window-size={self.config.viewport_width},{self.config.viewport_height}",
                        "--no-sandbox",
                        "--disable-dev-shm-usage",
                        "--disable-gpu",
                        "--disable-web-security",
                        "--disable-features=VizDisplayCompositor"
                    ]
                )
                context = await browser.new_context(
                    viewport={
                        "width": self.config.viewport_width,
                        "height": self.config.viewport_height
                    }
                )
                self.browsers.append(browser)
                self.browser_contexts.append(context)

            self.logger.info(f"Инициализировано {len(self.browsers)} браузеров")
            
        except Exception as e:
            self.logger.error(f"Ошибка при инициализации браузеров: {e}")
            raise

    async def _cleanup_browsers(self):
        """Очищает ресурсы браузеров"""
        for browser in self.browsers:
            try:
                await browser.close()
            except Exception as e:
                self.logger.warning(f"Ошибка при закрытии браузера: {e}")

        if hasattr(self, 'playwright'):
            try:
                await self.playwright.stop()
            except Exception as e:
                self.logger.warning(f"Ошибка при остановке Playwright: {e}")

    def _get_web_ports(self) -> List[int]:
        """Возвращает список портов для веб-скриншотов"""
        return [80, 443, 8080, 10000, 8000, 37777, 37778]

    async def create_screenshots_async(self, scan_results: List[ScanResult], network_dir: Path) -> Dict[str, int]:
        """Асинхронно создает скриншоты для найденных веб-сервисов"""
        screenshots_dir = network_dir / "screenshots"
        screenshots_dir.mkdir(exist_ok=True)

        # Собираем задачи для скриншотов
        screenshot_tasks = []
        for result in scan_results:
            for port in result.open_ports.keys():
                if port in self._get_web_ports():
                    task = self._create_screenshot_task(
                        result.ip, port, screenshots_dir
                    )
                    screenshot_tasks.append(task)

        if not screenshot_tasks:
            self.logger.info("Нет веб-портов для создания скриншотов")
            return {}

        self.logger.info(f"Создание скриншотов для {len(screenshot_tasks)} портов")

        # Выполняем все задачи параллельно
        results = await asyncio.gather(*screenshot_tasks, return_exceptions=True)

        # Подсчитываем результаты
        screenshots_count = {}
        successful_screenshots = 0

        for i, result in enumerate(results):
            if isinstance(result, Exception):
                self.logger.warning(f"Ошибка при создании скриншота: {result}")
                continue
            if result:
                successful_screenshots += 1
                # Определяем IP из задачи (упрощенно)
                for scan_result in scan_results:
                    for port in scan_result.open_ports.keys():
                        if port in self._get_web_ports():
                            screenshots_count[scan_result.ip] = screenshots_count.get(scan_result.ip, 0) + 1
                            break

        self.logger.info(f"Создано скриншотов: {successful_screenshots} для {len(screenshots_count)} хостов")
        return screenshots_count

    async def _create_screenshot_task(self, ip: str, port: int, screenshots_dir: Path) -> bool:
        """Создает задачу для скриншота"""
        try:
            # Выбираем браузер из пула
            browser_index = hash(f"{ip}:{port}") % len(self.browser_contexts)
            context = self.browser_contexts[browser_index]

            # Определяем протокол
            protocol = "https" if port in [443] else "http"
            url = f"{protocol}://{ip}:{port}"

            # Создаем страницу
            page = await context.new_page()
            
            try:
                # Устанавливаем таймаут
                page.set_default_timeout(self.config.web_timeout * 1000)
                
                # Переходим на страницу
                await page.goto(url, wait_until="networkidle")
                
                # Делаем скриншот
                screenshot_path = screenshots_dir / f"{ip}_{port}.png"
                await page.screenshot(path=str(screenshot_path), full_page=True)
                
                self.logger.debug(f"Скриншот создан: {screenshot_path}")
                return True
                
            except Exception as e:
                self.logger.debug(f"Ошибка при создании скриншота {url}: {e}")
                return False
            finally:
                await page.close()
                
        except Exception as e:
            self.logger.warning(f"Ошибка при создании скриншота для {ip}:{port}: {e}")
            return False


class ScreenshotManager:
    """Синхронный менеджер скриншотов для обратной совместимости"""

    def __init__(self, config: ScannerConfig):
        self.config = config
        self.logger = logging.getLogger(__name__)
        self.browsers = []
        self.browser_contexts = []

    def __enter__(self):
        """Синхронный вход в контекст"""
        self._initialize_browsers()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """Синхронный выход из контекста"""
        self._cleanup_browsers()

    def _initialize_browsers(self):
        """Инициализирует браузеры синхронно"""
        try:
            from playwright.sync_api import sync_playwright

            self.playwright = sync_playwright().start()
            
            # Создаем несколько браузеров для параллельной работы
            for i in range(self.config.max_browsers):
                browser = self.playwright.chromium.launch(
                    headless=True,
                    args=[
                        f"--window-size={self.config.viewport_width},{self.config.viewport_height}",
                        "--no-sandbox",
                        "--disable-dev-shm-usage",
                        "--disable-gpu",
                        "--disable-web-security",
                        "--disable-features=VizDisplayCompositor"
                    ]
                )
                context = browser.new_context(
                    viewport={
                        "width": self.config.viewport_width,
                        "height": self.config.viewport_height
                    }
                )
                self.browsers.append(browser)
                self.browser_contexts.append(context)

            self.logger.info(f"Инициализировано {len(self.browsers)} браузеров")
            
        except Exception as e:
            self.logger.error(f"Ошибка при инициализации браузеров: {e}")
            raise

    def _cleanup_browsers(self):
        """Очищает ресурсы браузеров"""
        for browser in self.browsers:
            try:
                browser.close()
            except Exception as e:
                self.logger.warning(f"Ошибка при закрытии браузера: {e}")

        if hasattr(self, 'playwright'):
            try:
                self.playwright.stop()
            except Exception as e:
                self.logger.warning(f"Ошибка при остановке Playwright: {e}")

    def _get_web_ports(self) -> List[int]:
        """Возвращает список портов для веб-скриншотов"""
        return [80, 443, 8080, 10000, 8000, 37777, 37778]

    def create_screenshots(self, scan_results: List[ScanResult], network_dir: Path) -> Dict[str, int]:
        """Создает скриншоты для найденных веб-сервисов"""
        screenshots_dir = network_dir / "screenshots"
        screenshots_dir.mkdir(exist_ok=True)

        # Собираем задачи для скриншотов
        screenshot_tasks = []
        for result in scan_results:
            for port in result.open_ports.keys():
                if port in self._get_web_ports():
                    task = (result.ip, port, screenshots_dir)
                    screenshot_tasks.append(task)

        if not screenshot_tasks:
            self.logger.info("Нет веб-портов для создания скриншотов")
            return {}

        self.logger.info(f"Создание скриншотов для {len(screenshot_tasks)} портов")

        # Выполняем задачи последовательно (для совместимости)
        screenshots_count = {}
        successful_screenshots = 0

        for ip, port, screenshots_dir in screenshot_tasks:
            try:
                if self._create_screenshot_sync(ip, port, screenshots_dir):
                    successful_screenshots += 1
                    screenshots_count[ip] = screenshots_count.get(ip, 0) + 1
            except Exception as e:
                self.logger.warning(f"Ошибка при создании скриншота для {ip}:{port}: {e}")

        self.logger.info(f"Создано скриншотов: {successful_screenshots} для {len(screenshots_count)} хостов")
        return screenshots_count

    def _create_screenshot_sync(self, ip: str, port: int, screenshots_dir: Path) -> bool:
        """Создает скриншот синхронно"""
        try:
            # Выбираем браузер из пула
            browser_index = hash(f"{ip}:{port}") % len(self.browser_contexts)
            context = self.browser_contexts[browser_index]

            # Определяем протокол
            protocol = "https" if port in [443] else "http"
            url = f"{protocol}://{ip}:{port}"

            # Создаем страницу
            page = context.new_page()
            
            try:
                # Устанавливаем таймаут
                page.set_default_timeout(self.config.web_timeout * 1000)
                
                # Переходим на страницу
                page.goto(url, wait_until="networkidle")
                
                # Делаем скриншот
                screenshot_path = screenshots_dir / f"{ip}_{port}.png"
                page.screenshot(path=str(screenshot_path), full_page=True)
                
                self.logger.debug(f"Скриншот создан: {screenshot_path}")
                return True
                
            except Exception as e:
                self.logger.debug(f"Ошибка при создании скриншота {url}: {e}")
                return False
            finally:
                page.close()
                
        except Exception as e:
            self.logger.warning(f"Ошибка при создании скриншота для {ip}:{port}: {e}")
            return False
