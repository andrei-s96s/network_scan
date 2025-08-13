#!/usr/bin/env python3
"""
Улучшенный менеджер скриншотов с поддержкой сертификатов и ожиданием загрузки
"""

import asyncio
import logging
from pathlib import Path
from typing import Dict, List, Optional
import time

from config import ScannerConfig
from .network_scanner import ScanResult


class ImprovedScreenshotManager:
    """Улучшенный менеджер скриншотов с поддержкой сертификатов и ожиданием загрузки"""

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
        """Инициализирует браузеры с улучшенными настройками"""
        try:
            from playwright.async_api import async_playwright

            self.playwright = await async_playwright().start()

            # Создаем браузеры с улучшенными настройками
            for i in range(self.config.max_browsers):
                browser = await self.playwright.chromium.launch(
                    headless=True,
                    args=[
                        f"--window-size={self.config.viewport_width},{self.config.viewport_height}",
                        "--no-sandbox",
                        "--disable-dev-shm-usage",
                        "--disable-gpu",
                        "--disable-web-security",
                        "--disable-features=VizDisplayCompositor",
                        "--ignore-certificate-errors",  # Игнорируем ошибки сертификатов
                        "--ignore-ssl-errors",  # Игнорируем SSL ошибки
                        "--ignore-certificate-errors-spki-list",
                        "--ignore-ssl-errors-spki-list",
                        "--disable-extensions",
                        "--disable-plugins",
                        "--disable-images",  # Отключаем загрузку изображений для ускорения
                        "--disable-javascript",  # Отключаем JavaScript для безопасности
                    ],
                )
                
                # Создаем контекст с улучшенными настройками
                context = await browser.new_context(
                    viewport={
                        "width": self.config.viewport_width,
                        "height": self.config.viewport_height,
                    },
                    ignore_https_errors=True,  # Игнорируем HTTPS ошибки
                    user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
                    extra_http_headers={
                        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
                        'Accept-Language': 'en-US,en;q=0.5',
                        'Accept-Encoding': 'gzip, deflate',
                        'Connection': 'keep-alive',
                        'Upgrade-Insecure-Requests': '1'
                    }
                )
                
                self.browsers.append(browser)
                self.browser_contexts.append(context)

            self.logger.info(f"Инициализировано {len(self.browsers)} браузеров с улучшенными настройками")

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

        if hasattr(self, "playwright"):
            try:
                await self.playwright.stop()
            except Exception as e:
                self.logger.warning(f"Ошибка при остановке Playwright: {e}")

    def _get_web_ports(self) -> List[int]:
        """Возвращает список портов для веб-скриншотов"""
        return [80, 443, 8080, 10000, 8000, 37777, 37778, 8443, 9443]

    async def create_screenshots_async(
        self, scan_results: List[ScanResult], network_dir: Path
    ) -> Dict[str, int]:
        """Создает скриншоты с улучшенной обработкой ошибок и ожиданием загрузки"""
        screenshots_dir = network_dir / "screenshots"
        screenshots_dir.mkdir(exist_ok=True)

        # Собираем задачи для скриншотов
        screenshot_tasks = []
        task_info = []

        for result in scan_results:
            for port in result.open_ports.keys():
                if port in self._get_web_ports():
                    task = self._create_screenshot_task(
                        result.ip, port, screenshots_dir
                    )
                    screenshot_tasks.append(task)
                    task_info.append((result.ip, port))

        if not screenshot_tasks:
            self.logger.info("Нет веб-портов для создания скриншотов")
            return {}

        self.logger.info(f"Создание скриншотов для {len(screenshot_tasks)} портов")

        # Выполняем задачи с ограничением параллельности
        semaphore = asyncio.Semaphore(5)  # Максимум 5 параллельных скриншотов
        
        async def limited_screenshot(task):
            async with semaphore:
                return await task

        results = await asyncio.gather(
            *[limited_screenshot(task) for task in screenshot_tasks], 
            return_exceptions=True
        )

        # Подсчитываем результаты
        screenshots_count = {}
        successful_screenshots = 0

        for i, result in enumerate(results):
            if isinstance(result, Exception):
                self.logger.warning(f"Ошибка при создании скриншота: {result}")
                continue
            if result:
                successful_screenshots += 1
                task_ip, task_port = task_info[i]
                screenshots_count[task_ip] = screenshots_count.get(task_ip, 0) + 1

        self.logger.info(
            f"Создано скриншотов: {successful_screenshots} "
            f"для {len(screenshots_count)} хостов"
        )
        return screenshots_count

    async def _create_screenshot_task(
        self, ip: str, port: int, screenshots_dir: Path
    ) -> bool:
        """Создает скриншот с улучшенной обработкой ошибок"""
        try:
            # Выбираем браузер из пула
            browser_index = hash(f"{ip}:{port}") % len(self.browser_contexts)
            context = self.browser_contexts[browser_index]

            # Создаем страницу
            page = await context.new_page()

            try:
                # Устанавливаем таймауты
                page.set_default_timeout(30000)  # 30 секунд на загрузку
                page.set_default_navigation_timeout(30000)

                # Обработчики для автоматического принятия сертификатов и диалогов
                page.on("dialog", lambda dialog: dialog.accept())
                page.on("pageerror", lambda error: self.logger.debug(f"Page error: {error}"))
                
                # Дополнительные обработчики для SSL
                page.on("requestfailed", lambda request: self.logger.debug(f"Request failed: {request.url}"))
                
                # Пытаемся подключиться с правильным протоколом
                response = None
                url = None
                
                # Для портов 443, 8443, 9443 пробуем сначала HTTPS, потом HTTP
                if port in [443, 8443, 9443]:
                    protocols_to_try = ["https", "http"]
                else:
                    protocols_to_try = ["http", "https"]
                
                for protocol in protocols_to_try:
                    try:
                        url = f"{protocol}://{ip}:{port}"
                        self.logger.info(f"Пробуем подключиться к {url}")
                        
                        response = await page.goto(
                            url, 
                            wait_until="domcontentloaded",
                            timeout=15000  # Уменьшаем таймаут для быстрой проверки
                        )
                        
                        if response and response.status < 400:
                            self.logger.info(f"✅ Успешное подключение к {url} (статус: {response.status})")
                            break
                        else:
                            status = response.status if response else 'None'
                            self.logger.info(f"❌ Неудачное подключение к {url} (статус: {status})")
                            
                    except Exception as e:
                        self.logger.info(f"❌ Ошибка при подключении к {url}: {e}")
                        continue
                
                if not response or response.status >= 400:
                    self.logger.debug(f"Не удалось подключиться к {ip}:{port} ни по одному протоколу")
                    return False

                # Ждем дополнительное время для полной загрузки
                await asyncio.sleep(2)

                # Проверяем, что страница загрузилась
                try:
                    # Ждем, пока страница станет стабильной
                    await page.wait_for_load_state("networkidle", timeout=10000)
                except:
                    # Если не удалось дождаться networkidle, продолжаем
                    pass

                # Делаем скриншот с уменьшенным размером
                screenshot_path = screenshots_dir / f"{ip}_{port}.png"
                await page.screenshot(
                    path=str(screenshot_path), 
                    full_page=False,  # Только видимая область
                    timeout=10000
                )

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

    async def create_screenshots_for_hosts(
        self, 
        hosts_with_web_ports: List[tuple], 
        screenshots_dir: Path
    ) -> Dict[str, int]:
        """Создает скриншоты для списка хостов с веб-портами"""
        if not hosts_with_web_ports:
            self.logger.info("Нет хостов с веб-портами для скриншотов")
            return {}

        self.logger.info(f"Создание скриншотов для {len(hosts_with_web_ports)} хостов")

        # Создаем задачи для каждого хоста
        tasks = []
        for ip, port in hosts_with_web_ports:
            task = self._create_screenshot_task(ip, port, screenshots_dir)
            tasks.append(task)

        # Выполняем с ограничением параллельности
        semaphore = asyncio.Semaphore(3)  # Максимум 3 параллельных скриншота
        
        async def limited_screenshot(task):
            async with semaphore:
                return await task

        results = await asyncio.gather(
            *[limited_screenshot(task) for task in tasks], 
            return_exceptions=True
        )

        # Подсчитываем результаты
        screenshots_count = {}
        successful_screenshots = 0

        for i, (ip, port) in enumerate(hosts_with_web_ports):
            result = results[i]
            if isinstance(result, Exception):
                self.logger.warning(f"Ошибка при создании скриншота для {ip}:{port}: {result}")
                continue
            if result:
                successful_screenshots += 1
                screenshots_count[ip] = screenshots_count.get(ip, 0) + 1

        self.logger.info(
            f"Создано скриншотов: {successful_screenshots} "
            f"для {len(screenshots_count)} хостов"
        )
        return screenshots_count


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

            # Создаем браузеры с улучшенными настройками
            for i in range(self.config.max_browsers):
                browser = self.playwright.chromium.launch(
                    headless=True,
                    args=[
                        f"--window-size={self.config.viewport_width},{self.config.viewport_height}",
                        "--no-sandbox",
                        "--disable-dev-shm-usage",
                        "--disable-gpu",
                        "--disable-web-security",
                        "--disable-features=VizDisplayCompositor",
                        "--ignore-certificate-errors",
                        "--ignore-ssl-errors",
                        "--ignore-certificate-errors-spki-list",
                        "--ignore-ssl-errors-spki-list",
                        "--disable-extensions",
                        "--disable-plugins",
                        "--disable-images",
                        "--disable-javascript",
                    ],
                )
                
                context = browser.new_context(
                    viewport={
                        "width": self.config.viewport_width,
                        "height": self.config.viewport_height,
                    },
                    ignore_https_errors=True,
                    user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
                    extra_http_headers={
                        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
                        'Accept-Language': 'en-US,en;q=0.5',
                        'Accept-Encoding': 'gzip, deflate',
                        'Connection': 'keep-alive',
                        'Upgrade-Insecure-Requests': '1'
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

        if hasattr(self, "playwright"):
            try:
                self.playwright.stop()
            except Exception as e:
                self.logger.warning(f"Ошибка при остановке Playwright: {e}")

    def _get_web_ports(self) -> List[int]:
        """Возвращает список портов для веб-скриншотов"""
        return [80, 443, 8080, 10000, 8000, 37777, 37778, 8443, 9443]

    def create_screenshots(
        self, scan_results: List[ScanResult], network_dir: Path
    ) -> Dict[str, int]:
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
                self.logger.warning(
                    f"Ошибка при создании скриншота для {ip}:{port}: {e}"
                )

        self.logger.info(
            f"Создано скриншотов: {successful_screenshots} "
            f"для {len(screenshots_count)} хостов"
        )
        return screenshots_count

    def _create_screenshot_sync(
        self, ip: str, port: int, screenshots_dir: Path
    ) -> bool:
        """Создает скриншот синхронно с улучшенной обработкой"""
        try:
            # Выбираем браузер из пула
            browser_index = hash(f"{ip}:{port}") % len(self.browser_contexts)
            context = self.browser_contexts[browser_index]

            # Создаем страницу
            page = context.new_page()

            try:
                # Устанавливаем таймауты
                page.set_default_timeout(30000)
                page.set_default_navigation_timeout(30000)

                # Обработчик для автоматического принятия сертификатов
                page.on("dialog", lambda dialog: dialog.accept())
                
                # Пытаемся подключиться с правильным протоколом
                response = None
                url = None
                
                # Для портов 443, 8443, 9443 пробуем сначала HTTPS, потом HTTP
                if port in [443, 8443, 9443]:
                    protocols_to_try = ["https", "http"]
                else:
                    protocols_to_try = ["http", "https"]
                
                for protocol in protocols_to_try:
                    try:
                        url = f"{protocol}://{ip}:{port}"
                        self.logger.info(f"Пробуем подключиться к {url}")
                        
                        response = page.goto(
                            url, 
                            wait_until="domcontentloaded",
                            timeout=15000  # Уменьшаем таймаут для быстрой проверки
                        )
                        
                        if response and response.status < 400:
                            self.logger.info(f"✅ Успешное подключение к {url} (статус: {response.status})")
                            break
                        else:
                            status = response.status if response else 'None'
                            self.logger.info(f"❌ Неудачное подключение к {url} (статус: {status})")
                            
                    except Exception as e:
                        self.logger.info(f"❌ Ошибка при подключении к {url}: {e}")
                        continue
                
                if not response or response.status >= 400:
                    self.logger.debug(f"Не удалось подключиться к {ip}:{port} ни по одному протоколу")
                    return False

                # Ждем дополнительное время для полной загрузки
                time.sleep(2)

                # Проверяем, что страница загрузилась
                try:
                    page.wait_for_load_state("networkidle", timeout=10000)
                except:
                    pass

                # Делаем скриншот с уменьшенным размером
                screenshot_path = screenshots_dir / f"{ip}_{port}.png"
                page.screenshot(
                    path=str(screenshot_path), 
                    full_page=False,  # Только видимая область
                    timeout=10000
                )

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
