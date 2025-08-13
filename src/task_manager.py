#!/usr/bin/env python3
"""
Менеджер задач с поддержкой мониторинга ресурсов
"""
import asyncio
import logging
import time
import json
import zipfile
from pathlib import Path
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, asdict
from queue import PriorityQueue
from concurrent.futures import ThreadPoolExecutor
import threading
from datetime import datetime, timezone
import sys

# Добавляем путь к src для импорта
sys.path.append(str(Path(__file__).parent.parent))

from config import ScannerConfig
from .network_scanner import get_network_scanner, ScanResult
from .screenshot_manager import ImprovedScreenshotManager
from .report_generator import ReportGenerator
from .resource_monitor import get_resource_monitor
from .scanner_logger import get_scanner_logger

logger = logging.getLogger(__name__)


def get_current_time() -> datetime:
    """Получить текущее время в локальной временной зоне"""
    return datetime.now()


@dataclass
class Task:
    """Задача для выполнения"""
    id: str
    task_type: str
    network: str
    status: str  # pending, running, completed, failed, cancelled, paused
    created_at: datetime
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    metadata: Dict[str, Any] = None
    
    def __post_init__(self):
        if self.metadata is None:
            self.metadata = {}
    
    def to_dict(self) -> Dict[str, Any]:
        """Конвертировать в словарь для JSON сериализации"""
        def serialize_datetime(dt: datetime) -> str:
            """Сериализует datetime в ISO формат для JavaScript"""
            if dt is None:
                return None
            
            # Используем время как есть, если оно уже локальное
            if dt.tzinfo is None:
                local_dt = dt
            else:
                local_dt = dt.astimezone()
            
            # Возвращаем ISO формат, который JavaScript может легко парсить
            return local_dt.isoformat()
        
        def serialize_metadata(obj):
            """Рекурсивно сериализует объекты в metadata"""
            if isinstance(obj, dict):
                return {k: serialize_metadata(v) for k, v in obj.items()}
            elif isinstance(obj, list):
                return [serialize_metadata(item) for item in obj]
            elif isinstance(obj, Path):
                return str(obj)
            elif isinstance(obj, datetime):
                return serialize_datetime(obj)
            else:
                return obj
        
        # Создаем словарь вручную, чтобы контролировать сериализацию
        result = {
            'id': self.id,
            'task_type': self.task_type,
            'network': self.network,
            'status': self.status,
            'created_at': serialize_datetime(self.created_at),
            'started_at': serialize_datetime(self.started_at),
            'completed_at': serialize_datetime(self.completed_at),
            'metadata': serialize_metadata(self.metadata)
        }
        
        return result


class TaskManager:
    """Менеджер задач с мониторингом ресурсов"""
    
    def __init__(self, max_workers: int = 10):
        self.max_workers = max_workers
        self.executor = ThreadPoolExecutor(max_workers=max_workers)
        self.pending_tasks = PriorityQueue()
        self.running_tasks: Dict[str, Task] = {}
        self.completed_tasks: Dict[str, Task] = {}
        self.failed_tasks: Dict[str, Task] = {}
        
        # Загружаем сохраненные задачи
        self._load_tasks()
        
        # Мониторинг ресурсов
        self.resource_monitor = get_resource_monitor()
        self.resource_monitor.add_callback(self._on_resource_limit_exceeded)
        
        # Менеджеры
        self.project_root = Path(__file__).parent.parent
        self.report_generator = ReportGenerator(output_dir=str(self.project_root))
        self.cleanup_manager = None  # Инициализируем по необходимости
        self.compression_manager = None  # Инициализируем по необходимости
        
        # НЕ запускаем мониторинг автоматически - он будет запущен в веб-интерфейсе
        # asyncio.create_task(self.resource_monitor.start_monitoring())
        
        logger.info(f"TaskManager инициализирован с {max_workers} воркерами")
    
    def _save_tasks(self):
        """Сохранить задачи в JSON файл"""
        try:
            import json
            from pathlib import Path
            
            tasks_file = Path('tasks_state.json')
            tasks_data = {
                'completed_tasks': {
                    task_id: {
                        'id': task.id,
                        'task_type': task.task_type,
                        'network': task.network,
                        'status': task.status,
                        'created_at': task.created_at.isoformat(),
                        'started_at': task.started_at.isoformat() if task.started_at else None,
                        'completed_at': task.completed_at.isoformat() if task.completed_at else None,
                        'metadata': task.metadata
                    }
                    for task_id, task in self.completed_tasks.items()
                },
                'failed_tasks': {
                    task_id: {
                        'id': task.id,
                        'task_type': task.task_type,
                        'network': task.network,
                        'status': task.status,
                        'created_at': task.created_at.isoformat(),
                        'started_at': task.started_at.isoformat() if task.started_at else None,
                        'completed_at': task.completed_at.isoformat() if task.completed_at else None,
                        'metadata': task.metadata
                    }
                    for task_id, task in self.failed_tasks.items()
                }
            }
            
            with open(tasks_file, 'w', encoding='utf-8') as f:
                json.dump(tasks_data, f, ensure_ascii=False, indent=2)
            
            logger.info(f"Задачи сохранены в {tasks_file}")
        except Exception as e:
            logger.error(f"Ошибка при сохранении задач: {e}")
    
    def _load_tasks(self):
        """Загрузить задачи из JSON файла"""
        try:
            import json
            from pathlib import Path
            from datetime import datetime
            
            tasks_file = Path('tasks_state.json')
            if not tasks_file.exists():
                logger.info("Файл состояния задач не найден, начинаем с пустого состояния")
                return
            
            with open(tasks_file, 'r', encoding='utf-8') as f:
                tasks_data = json.load(f)
            
            # Загружаем завершенные задачи
            for task_id, task_dict in tasks_data.get('completed_tasks', {}).items():
                task = Task(
                    id=task_dict['id'],
                    task_type=task_dict['task_type'],
                    network=task_dict['network'],
                    status=task_dict['status'],
                    created_at=datetime.fromisoformat(task_dict['created_at']),
                    started_at=datetime.fromisoformat(task_dict['started_at']) if task_dict['started_at'] else None,
                    completed_at=datetime.fromisoformat(task_dict['completed_at']) if task_dict['completed_at'] else None,
                    metadata=task_dict.get('metadata', {})
                )
                self.completed_tasks[task_id] = task
            
            # Загружаем неудачные задачи
            for task_id, task_dict in tasks_data.get('failed_tasks', {}).items():
                task = Task(
                    id=task_dict['id'],
                    task_type=task_dict['task_type'],
                    network=task_dict['network'],
                    status=task_dict['status'],
                    created_at=datetime.fromisoformat(task_dict['created_at']),
                    started_at=datetime.fromisoformat(task_dict['started_at']) if task_dict['started_at'] else None,
                    completed_at=datetime.fromisoformat(task_dict['completed_at']) if task_dict['completed_at'] else None,
                    metadata=task_dict.get('metadata', {})
                )
                self.failed_tasks[task_id] = task
            
            logger.info(f"Загружено {len(self.completed_tasks)} завершенных и {len(self.failed_tasks)} неудачных задач")
        except Exception as e:
            logger.error(f"Ошибка при загрузке задач: {e}")
    
    def _on_resource_limit_exceeded(self, is_over_limit: bool):
        """Callback при превышении лимитов ресурсов"""
        if is_over_limit:
            logger.warning("Высокая нагрузка на ресурсы - продолжаем работу")
        else:
            logger.info("Ресурсы восстановлены")
    
    def create_task(self, task_type: str, network: str, **kwargs) -> Task:
        """Создать новую задачу"""
        task_id = f"{task_type}_{int(time.time())}_{threading.get_ident()}"
        
        task = Task(
            id=task_id,
            task_type=task_type,
            network=network,
            status="pending",
            created_at=get_current_time(),
            metadata=kwargs
        )
        
        # Добавляем в очередь с приоритетом
        self.pending_tasks.put((0, task))
        
        logger.info(f"Создана задача {task_id} для сети {network}")
        return task
    
    def get_all_tasks(self) -> Dict[str, Task]:
        """Получить все задачи без кэширования для актуальности"""
        # Собираем задачи из всех источников
        all_tasks = {}
        
        # Добавляем выполняющиеся задачи
        all_tasks.update(self.running_tasks)
        logger.info(f"Выполняющихся задач: {len(self.running_tasks)}")
        
        # Добавляем завершенные задачи
        all_tasks.update(self.completed_tasks)
        logger.info(f"Завершенных задач: {len(self.completed_tasks)}")
        
        # Добавляем неудачные задачи
        all_tasks.update(self.failed_tasks)
        logger.info(f"Неудачных задач: {len(self.failed_tasks)}")
        
        # Логируем детали каждой коллекции
        if self.running_tasks:
            logger.info(f"Выполняющиеся задачи: {list(self.running_tasks.keys())}")
        if self.completed_tasks:
            logger.info(f"Завершенные задачи: {list(self.completed_tasks.keys())}")
        if self.failed_tasks:
            logger.info(f"Неудачные задачи: {list(self.failed_tasks.keys())}")
        
        # Добавляем задачи из очереди
        pending_list = []
        while not self.pending_tasks.empty():
            try:
                priority, task = self.pending_tasks.get_nowait()
                pending_list.append((priority, task))
            except:
                break
        
        # Возвращаем задачи обратно в очередь
        for priority, task in pending_list:
            self.pending_tasks.put((priority, task))
            all_tasks[task.id] = task
        
        logger.info(f"Задач в очереди: {len(pending_list)}")
        logger.info(f"Всего задач: {len(all_tasks)}")
        
        # Дополнительная отладочная информация
        logger.info(f"=== ДЕТАЛЬНАЯ ИНФОРМАЦИЯ О ЗАДАЧАХ ===")
        logger.info(f"running_tasks: {self.running_tasks}")
        logger.info(f"completed_tasks: {self.completed_tasks}")
        logger.info(f"failed_tasks: {self.failed_tasks}")
        logger.info(f"all_tasks result: {all_tasks}")
        logger.info(f"=== КОНЕЦ ДЕТАЛЬНОЙ ИНФОРМАЦИИ ===")
        
        return all_tasks
    
    def get_task(self, task_id: str) -> Optional[Task]:
        """Получить задачу по ID"""
        all_tasks = self.get_all_tasks()
        return all_tasks.get(task_id)
    
    def delete_task(self, task_id: str) -> bool:
        """Удалить задачу полностью"""
        # Удаляем из всех списков
        self.running_tasks.pop(task_id, None)
        self.completed_tasks.pop(task_id, None)
        self.failed_tasks.pop(task_id, None)
        
        # Сохраняем состояние задач
        self._save_tasks()
        
        logger.info(f"Задача {task_id} удалена")
        return True
    
    def _execute_network_scan(self, task: Task) -> None:
        """Выполнить сетевой скан с ограничением ресурсов"""
        logger.info(f"=== НАЧАЛО ВЫПОЛНЕНИЯ ЗАДАЧИ {task.id} ===")
        
        # Получаем специальный логгер для сканера
        scanner_logger = get_scanner_logger()
        
        try:
            task.status = "running"
            task.started_at = get_current_time()
            self.running_tasks[task.id] = task
            
            logger.info(f"Начинаем выполнение задачи {task.id} для сети {task.network}")
            logger.info(f"Задача добавлена в running_tasks, размер: {len(self.running_tasks)}")
            
            # Проверяем размер сети
            import ipaddress
            try:
                network = ipaddress.IPv4Network(task.network, strict=False)
                host_count = network.num_addresses
                logger.info(f"Размер сети {task.network}: {host_count} адресов")
                
                if host_count > 256:
                    logger.warning(f"Большая сеть {task.network} ({host_count} адресов) - может занять много времени")
                    # Увеличиваем таймаут для больших сетей
                    timeout = min(host_count * 5, 7200)  # 5 секунд на хост, максимум 120 минут
                elif host_count > 64:
                    timeout = min(host_count * 5, 1800)  # 5 секунд на хост, максимум 30 минут
                else:
                    timeout = min(host_count * 5, 600)  # 5 секунд на хост, максимум 10 минут
                    
            except Exception as e:
                logger.warning(f"Не удалось определить размер сети {task.network}: {e}")
                timeout = 300
            
            # Получаем сканер
            from .network_scanner import get_network_scanner
            scanner = get_network_scanner()
            
            # Создаем event loop для асинхронного выполнения
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            
            try:
                # Выполняем сканирование с таймаутом
                logger.info(f"Начинаем сканирование сети {task.network} с таймаутом {timeout} секунд")
                scan_results = loop.run_until_complete(
                    asyncio.wait_for(
                        scanner.scan_network_async(task.network),
                        timeout=timeout  # Динамический таймаут
                    )
                )
                
                logger.info(f"Сканирование завершено, найдено {len(scan_results)} хостов")
                scanner_logger.log_scan_complete(0, len(scan_results), 0)  # Время уже залогировано в scanner
                
                # Получаем веб-хосты для скриншотов
                web_hosts = loop.run_until_complete(
                    asyncio.wait_for(
                        scanner.get_web_ports_for_screenshots(scan_results),
                        timeout=60  # 1 минута таймаут
                    )
                )
                # Создаем реальные скриншоты Playwright
                screenshots = []
                if web_hosts and task.metadata.get('create_screenshots', True):
                    logger.info(f"Найдено {len(web_hosts)} веб-хостов для скриншотов")
                    scanner_logger.log_web_hosts_found(web_hosts)
                    try:
                        # Ленивая инициализация Playwright
                        from playwright.sync_api import sync_playwright
                        import os
                        screenshots_dir = f"results/{task.id}"
                        os.makedirs(screenshots_dir, exist_ok=True)

                        p = sync_playwright().start()
                        browser = p.chromium.launch(
                            headless=True,
                            args=[
                                "--window-size=1920,1080",
                                "--no-sandbox",
                                "--disable-dev-shm-usage",
                                "--disable-gpu",
                                "--disable-web-security",
                                "--disable-features=VizDisplayCompositor",
                                "--ignore-certificate-errors",
                                "--ignore-ssl-errors",
                                "--disable-extensions",
                                "--disable-plugins",
                            ],
                        )
                        context = browser.new_context(
                            viewport={
                                "width": 1920,
                                "height": 1080,
                            },
                            ignore_https_errors=True,
                            user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114 Safari/537.36",
                        )

                        try:
                            for i, url in enumerate(web_hosts):
                                try:
                                    page = context.new_page()
                                    page.set_default_timeout(30000)
                                    page.set_default_navigation_timeout(30000)
                                    # Переход на страницу
                                    response = page.goto(url, wait_until="domcontentloaded", timeout=30000)
                                    if not response:
                                        logger.debug(f"Нет ответа от {url}")
                                        page.close()
                                        continue
                                    # Доп. ожидание
                                    try:
                                        page.wait_for_load_state("networkidle", timeout=10000)
                                    except Exception:
                                        pass
                                    screenshot_path = f"{screenshots_dir}/screenshot_{i}.png"
                                    page.screenshot(path=screenshot_path, full_page=True, timeout=10000)
                                    screenshots.append(f"screenshot_{i}.png")
                                    logger.info(f"Скриншот создан: {screenshot_path}")
                                except Exception as e:
                                    logger.warning(f"Не удалось создать скриншот для {url}: {e}")
                                finally:
                                    try:
                                        page.close()
                                    except Exception:
                                        pass
                        finally:
                            try:
                                context.close()
                            except Exception:
                                pass
                            try:
                                browser.close()
                            except Exception:
                                pass
                            try:
                                p.stop()
                            except Exception:
                                pass
                    except Exception as e:
                        logger.error(f"Ошибка при создании скриншотов: {e}")
                        screenshots = []
                
                # Сохраняем результаты
                task.metadata['scan_results'] = [
                    {
                        'host': result.host,
                        'open_ports': result.open_ports,
                        'banners': result.banners,
                        'os_info': result.os_info,
                        'response_time': result.response_time
                    }
                    for result in scan_results
                ]
                task.metadata['hosts_count'] = len(scan_results)
                task.metadata['web_hosts_count'] = len(web_hosts) if web_hosts else 0
                task.metadata['screenshots_count'] = len(screenshots)
                task.metadata['screenshots'] = screenshots
                task.metadata['web_hosts'] = web_hosts if web_hosts else []
                
                # Генерируем отчеты
                if task.metadata.get('generate_reports', True):
                    logger.info(f"Генерируем отчеты для {len(scan_results)} хостов")
                    self._generate_report(task, scan_results)
                
                task.status = "completed"
                task.completed_at = get_current_time()
                
                logger.info(f"Задача {task.id} завершена успешно. Найдено {len(scan_results)} хостов")
                
            except asyncio.TimeoutError:
                logger.error(f"Таймаут при выполнении задачи {task.id}")
                task.status = "failed"
                task.completed_at = get_current_time()
                task.metadata['error'] = "Превышено время выполнения (таймаут)"
                
                logger.info(f"Задача {task.id} завершена по таймауту")
                
            except Exception as e:
                logger.error(f"Ошибка при выполнении задачи {task.id}: {e}")
                task.status = "failed"
                task.completed_at = get_current_time()
                task.metadata['error'] = str(e)
                
                logger.info(f"Задача {task.id} завершена с ошибкой")
                
            finally:
                loop.close()
                
        except Exception as e:
            logger.error(f"Критическая ошибка при выполнении задачи {task.id}: {e}")
            task.status = "failed"
            task.completed_at = get_current_time()
            task.metadata['error'] = str(e)
            
            logger.info(f"Задача {task.id} завершена с критической ошибкой")
        
        logger.info(f"=== КОНЕЦ ВЫПОЛНЕНИЯ ЗАДАЧИ {task.id} ===")
        # Обрабатываем завершение задачи
        self._handle_task_completion(task)
    
    def _generate_report(self, task: Task, scan_results: List[Dict]) -> None:
        """Генерировать отчет по результатам сканирования"""
        logger.info(f"Начинаем генерацию отчета для задачи {task.id}")
        try:
            import json
            import zipfile
            from pathlib import Path
            
            # Создаем каталог для отчетов
            reports_dir = Path('reports')
            reports_dir.mkdir(exist_ok=True)
            
            # Создаем каталог для временных файлов
            temp_dir = reports_dir / f"temp_{task.id}"
            temp_dir.mkdir(exist_ok=True)
            
            # Сохраняем результаты в JSON
            results_file = temp_dir / 'scan_results.json'
            # Преобразуем ScanResult объекты в словари
            scan_results_dict = []
            for host in scan_results:
                scan_results_dict.append({
                    'host': host.host,
                    'open_ports': host.open_ports,
                    'banners': host.banners,
                    'os_info': host.os_info,
                    'response_time': host.response_time
                })
            
            with open(results_file, 'w', encoding='utf-8') as f:
                json.dump(scan_results_dict, f, ensure_ascii=False, indent=2, default=str)
            
            # Создаем текстовый отчет
            report_file = temp_dir / 'report.txt'
            with open(report_file, 'w', encoding='utf-8') as f:
                f.write(f"ОТЧЕТ ПО СКАНИРОВАНИЮ СЕТИ\n")
                f.write(f"=" * 50 + "\n")
                f.write(f"Задача: {task.id}\n")
                f.write(f"Сеть: {task.network}\n")
                f.write(f"Дата создания: {task.created_at}\n")
                f.write(f"Дата завершения: {task.completed_at}\n")
                f.write(f"Статус: {task.status}\n\n")
                
                f.write(f"РЕЗУЛЬТАТЫ СКАНИРОВАНИЯ\n")
                f.write(f"-" * 30 + "\n")
                f.write(f"Всего хостов найдено: {len(scan_results)}\n")
                
                # Группируем по портам
                port_stats = {}
                for host in scan_results:
                    # ScanResult - это dataclass, используем атрибуты напрямую
                    for port in host.open_ports:
                        port_stats[port] = port_stats.get(port, 0) + 1
                
                f.write(f"Порты найдены:\n")
                for port, count in sorted(port_stats.items()):
                    f.write(f"  Порт {port}: {count} хостов\n")
                
                f.write(f"\nДЕТАЛЬНАЯ ИНФОРМАЦИЯ ПО ХОСТАМ\n")
                f.write(f"-" * 40 + "\n")
                
                for i, host in enumerate(scan_results, 1):
                    f.write(f"\n{i}. {host.host}\n")
                    f.write(f"   Статус: {'Активен' if host.open_ports else 'Неактивен'}\n")
                    
                    for port in host.open_ports:
                        banner = host.banners.get(port, 'N/A')
                        f.write(f"   Порт {port}: Открыт\n")
                        if banner and banner != 'N/A':
                            f.write(f"     Баннер: {banner}\n")
            
            # Создаем HTML отчет
            html_file = temp_dir / 'report.html'
            
            # Сортируем хосты по IP-адресам
            sorted_hosts = sorted(scan_results, key=lambda x: [int(part) for part in x.host.split('.')])
            
            # Создаем маппинг хостов к скриншотам
            host_screenshots = {}
            if task.metadata.get('screenshots') and task.metadata.get('web_hosts'):
                web_hosts = task.metadata.get('web_hosts', [])
                screenshots = task.metadata.get('screenshots', [])
                
                for i, url in enumerate(web_hosts):
                    if i < len(screenshots):
                        # Извлекаем IP из URL
                        from urllib.parse import urlparse
                        parsed = urlparse(url)
                        host_ip = parsed.hostname
                        if host_ip:
                            if host_ip not in host_screenshots:
                                host_screenshots[host_ip] = []
                            host_screenshots[host_ip].append({
                                'screenshot': screenshots[i],
                                'url': url,
                                'port': parsed.port or (443 if parsed.scheme == 'https' else 80)
                            })
            
            with open(html_file, 'w', encoding='utf-8') as f:
                f.write(f"""<!DOCTYPE html>
<html lang="ru">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Отчет по сканированию - {task.network}</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 20px; background-color: #f5f5f5; }}
        .container {{ max-width: 1400px; margin: 0 auto; background: white; padding: 20px; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }}
        .header {{ background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 20px; border-radius: 8px; margin-bottom: 20px; }}
        .stats {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 15px; margin-bottom: 30px; }}
        .stat-card {{ background: #f8f9fa; padding: 15px; border-radius: 8px; border-left: 4px solid #667eea; }}
        .host-card {{ background: #f8f9fa; margin: 15px 0; padding: 20px; border-radius: 8px; border: 1px solid #dee2e6; }}
        .host-header {{ margin-bottom: 15px; }}
        .host-info {{ margin-bottom: 15px; }}
        .host-screenshots {{ margin-top: 15px; }}
        .port-item {{ background: white; margin: 8px 0; padding: 12px; border-radius: 6px; border-left: 4px solid #28a745; }}
        .banner {{ background: #e9ecef; padding: 10px; border-radius: 4px; font-family: monospace; font-size: 12px; margin-top: 8px; overflow-x: auto; }}
        .screenshot-container {{ text-align: center; margin-bottom: 15px; }}
        .screenshot-container img {{ 
            max-width: 300px; 
            max-height: 200px; 
            cursor: pointer; 
            border-radius: 8px; 
            box-shadow: 0 2px 8px rgba(0,0,0,0.1);
            transition: transform 0.2s ease;
        }}
        .screenshot-container img:hover {{ 
            transform: scale(1.05); 
            box-shadow: 0 4px 12px rgba(0,0,0,0.15);
        }}
        .screenshot-info {{ font-size: 12px; color: #6c757d; margin-top: 5px; }}
        
        /* Модальное окно для увеличенного скриншота */
        .screenshot-modal {{ 
            display: none; 
            position: fixed; 
            z-index: 1000; 
            left: 0; 
            top: 0; 
            width: 100%; 
            height: 100%; 
            background-color: rgba(0,0,0,0.8); 
        }}
        .screenshot-modal-content {{ 
            margin: auto; 
            display: block; 
            max-width: 90%; 
            max-height: 90%; 
            margin-top: 5%; 
        }}
        .screenshot-modal-close {{ 
            position: absolute; 
            top: 15px; 
            right: 35px; 
            color: #f1f1f1; 
            font-size: 40px; 
            font-weight: bold; 
            cursor: pointer; 
        }}
        .screenshot-modal-close:hover {{ 
            color: #bbb; 
        }}
        .timestamp {{ color: #6c757d; font-size: 14px; }}
        .no-screenshots {{ color: #6c757d; font-style: italic; text-align: center; padding: 20px; }}
        .web-service-badge {{ background: #ffc107; color: #212529; padding: 4px 8px; border-radius: 4px; font-size: 12px; font-weight: bold; margin-left: 10px; }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1><i class="fas fa-network-wired"></i> Отчет по сканированию сети</h1>
            <p class="timestamp">Сеть: {task.network} | Задача: {task.id}</p>
            <p class="timestamp">Создано: {task.created_at} | Завершено: {task.completed_at}</p>
        </div>
        
        <div class="stats">
            <div class="stat-card">
                <h3>Всего хостов</h3>
                <p style="font-size: 24px; font-weight: bold; color: #667eea;">{len(sorted_hosts)}</p>
            </div>
            <div class="stat-card">
                <h3>Активных хостов</h3>
                <p style="font-size: 24px; font-weight: bold; color: #28a745;">{len([h for h in sorted_hosts if h.open_ports])}</p>
            </div>
            <div class="stat-card">
                <h3>Веб-сервисов</h3>
                <p style="font-size: 24px; font-weight: bold; color: #ffc107;">{task.metadata.get('web_hosts_count', 0)}</p>
            </div>
            <div class="stat-card">
                <h3>Скриншотов</h3>
                <p style="font-size: 24px; font-weight: bold; color: #dc3545;">{task.metadata.get('screenshots_count', 0)}</p>
            </div>
        </div>
        
        <h2>Детальная информация по хостам (отсортировано по IP)</h2>""")
                
                # Группируем по портам для статистики
                port_stats = {}
                for host in sorted_hosts:
                    for port in host.open_ports:
                        port_stats[port] = port_stats.get(port, 0) + 1
                
                if port_stats:
                    f.write(f"""
        <div class="stats">
            <div class="stat-card">
                <h3>Статистика портов</h3>""")
                    
                    for port, count in sorted(port_stats.items()):
                        f.write(f"""
                <p><strong>Порт {port}:</strong> {count} хостов</p>""")
                    
                    f.write(f"""
            </div>
        </div>""")
                
                # Детальная информация по хостам
                for i, host in enumerate(sorted_hosts, 1):
                    status = "Активен" if host.open_ports else "Неактивен"
                    status_color = "#28a745" if host.open_ports else "#6c757d"
                    has_web_service = host.host in host_screenshots
                    
                    f.write(f"""
        <div class="host-card">
            <div class="host-header">
                <div class="host-info">
                    <h3 style="color: {status_color}; margin: 0;">
                        {i}. {host.host} - {status}
                        {f'<span class="web-service-badge">Веб-сервис</span>' if has_web_service else ''}
                    </h3>
                </div>
            </div>""")
                    
                    if host.open_ports:
                        for port in host.open_ports:
                            banner = host.banners.get(port, 'N/A')
                            f.write(f"""
            <div class="port-item">
                <strong>Порт {port}:</strong> Открыт
                {f'<div class="banner">{banner}</div>' if banner and banner != 'N/A' else ''}
            </div>""")
                    else:
                        f.write(f"""
            <p style="color: #6c757d;">Нет открытых портов</p>""")
                    
                    # Показываем скриншоты для этого хоста
                    if has_web_service:
                        f.write(f"""
            <div class="host-screenshots">
                <h4>Скриншоты веб-сервисов:</h4>""")
                        
                        for screenshot_info in host_screenshots[host.host]:
                            f.write(f"""
                <div class="screenshot-container">
                    <img src="screenshots/{screenshot_info['screenshot']}" 
                         alt="Скриншот {host.host}" 
                         onclick="openScreenshotModal('screenshots/{screenshot_info['screenshot']}', '{screenshot_info['url']}')"
                         class="screenshot-thumbnail">
                    <div class="screenshot-info">
                        <div><strong>URL:</strong> {screenshot_info['url']}</div>
                        <div><small>Нажмите на изображение для увеличения</small></div>
                    </div>
                </div>""")
                        
                        f.write(f"""
            </div>""")
                    
                    f.write(f"""
        </div>""")
                
                f.write(f"""
    </div>
    
    <!-- Модальное окно для увеличенного скриншота -->
    <div id="screenshotModal" class="screenshot-modal">
        <span class="screenshot-modal-close" onclick="closeScreenshotModal()">&times;</span>
        <img class="screenshot-modal-content" id="modalImage">
        <div id="modalCaption" style="margin: auto; display: block; width: 80%; max-width: 700px; text-align: center; color: white; padding: 10px 0; height: 150px;"></div>
    </div>
    
    <script>
        // Функция для открытия модального окна
        function openScreenshotModal(imageSrc, url) {{
            var modal = document.getElementById("screenshotModal");
            var modalImg = document.getElementById("modalImage");
            var captionText = document.getElementById("modalCaption");
            
            modal.style.display = "block";
            modalImg.src = imageSrc;
            captionText.innerHTML = "<strong>URL:</strong> " + url + "<br><small>Нажмите на X или вне изображения для закрытия</small>";
        }}
        
        // Функция для закрытия модального окна
        function closeScreenshotModal() {{
            document.getElementById("screenshotModal").style.display = "none";
        }}
        
        // Закрытие модального окна при клике вне изображения
        var modal = document.getElementById("screenshotModal");
        modal.onclick = function(e) {{
            if (e.target === modal) {{
                closeScreenshotModal();
            }}
        }}
        
        // Закрытие модального окна по клавише Escape
        document.addEventListener('keydown', function(e) {{
            if (e.key === 'Escape') {{
                closeScreenshotModal();
            }}
        }});
    </script>
</body>
</html>""")
            
            # Создаем ZIP архив
            zip_file = reports_dir / f"{task.id}.zip"
            with zipfile.ZipFile(zip_file, 'w', zipfile.ZIP_DEFLATED) as zipf:
                # Добавляем файлы в архив
                zipf.write(results_file, 'scan_results.json')
                zipf.write(report_file, 'report.txt')
                zipf.write(html_file, 'report.html')
                
                # Добавляем скриншоты, если есть
                screenshots_dir = Path('results') / task.id
                if screenshots_dir.exists():
                    for screenshot_file in screenshots_dir.glob('*.png'):
                        zipf.write(screenshot_file, f'screenshots/{screenshot_file.name}')
            
            # Удаляем временный каталог
            import shutil
            shutil.rmtree(temp_dir)
            
            logger.info(f"Отчет для задачи {task.id} создан: {zip_file}")
            logger.info(f"Размер ZIP файла: {zip_file.stat().st_size} байт")
            
        except Exception as e:
            logger.error(f"Ошибка при генерации отчета для задачи {task.id}: {e}")
    
    def _create_post_scan_tasks(self, scan_task: Task, hosts_count: int):
        """Создать задачи после сканирования"""
        # Пока отключаем генерацию отчетов для стабильности
        logger.info(f"Сканирование завершено для {scan_task.id}, отчеты будут генерироваться отдельно")
    
    def _handle_task_completion(self, task: Task):
        """Обработка завершения задачи"""
        logger.info(f"=== ОБРАБОТКА ЗАВЕРШЕНИЯ ЗАДАЧИ {task.id} ===")
        logger.info(f"Статус задачи: {task.status}")
        logger.info(f"Размер running_tasks до: {len(self.running_tasks)}")
        
        # Удаляем из выполняющихся
        self.running_tasks.pop(task.id, None)
        logger.info(f"Размер running_tasks после: {len(self.running_tasks)}")
        
        # Добавляем в соответствующие коллекции
        if task.status == "completed":
            self.completed_tasks[task.id] = task
            logger.info(f"Задача {task.id} перемещена в completed_tasks (размер: {len(self.completed_tasks)})")
        elif task.status == "failed":
            self.failed_tasks[task.id] = task
            logger.info(f"Задача {task.id} перемещена в failed_tasks (размер: {len(self.failed_tasks)})")
        else:
            logger.warning(f"Неизвестный статус задачи {task.id}: {task.status}")
        
        logger.info(f"Задача {task.id} завершена со статусом {task.status}")
        
        # Сохраняем состояние задач
        self._save_tasks()
        
        logger.info(f"=== КОНЕЦ ОБРАБОТКИ ЗАВЕРШЕНИЯ ЗАДАЧИ {task.id} ===")
    
    def start_worker(self):
        """Запустить воркер для обработки задач"""
        while True:
            try:
                # Получаем задачу из очереди
                if not self.pending_tasks.empty():
                    priority, task = self.pending_tasks.get()
                    
                    # Проверяем ресурсы перед выполнением
                    usage = self.resource_monitor.get_current_usage()
                    if usage['cpu_percent'] > ScannerConfig.max_cpu_percent:
                        logger.info(f"CPU: {usage['cpu_percent']:.1f}% - откладываем задачу")
                        # Возвращаем задачу в очередь
                        self.pending_tasks.put((priority, task))
                        time.sleep(2)
                        continue
                    
                    # Выполняем задачу
                    if task.task_type == "NETWORK_SCAN":
                        logger.info(f"Воркер: начинаем выполнение задачи {task.id}")
                        self._execute_network_scan(task)
                        logger.info(f"Воркер: задача {task.id} выполнена, вызываем _handle_task_completion")
                        # Обрабатываем завершение
                        self._handle_task_completion(task)
                        logger.info(f"Воркер: обработка завершения задачи {task.id} завершена")
                    else:
                        logger.warning(f"Неизвестный тип задачи: {task.task_type}")
                        task.status = "failed"
                        task.metadata['error'] = f"Неизвестный тип задачи: {task.task_type}"
                        
                        # Перемещаем в неудачные
                        self.failed_tasks[task.id] = task
                        # Обрабатываем завершение
                        self._handle_task_completion(task)
                else:
                    # Нет задач - ждем
                    time.sleep(1)
                    
            except Exception as e:
                logger.error(f"Ошибка в воркере: {e}")
                time.sleep(1)
    
    def start_workers(self):
        """Запустить все воркеры"""
        for i in range(self.max_workers):
            worker_thread = threading.Thread(
                target=self.start_worker,
                name=f"Worker-{i}",
                daemon=True
            )
            worker_thread.start()
            logger.info(f"Запущен воркер {i}")


# Глобальный экземпляр менеджера задач
_global_task_manager: Optional[TaskManager] = None


def get_task_manager() -> TaskManager:
    """Получить глобальный экземпляр менеджера задач с автоматической оптимизацией"""
    global _global_task_manager
    if _global_task_manager is None:
        # Используем оптимизированную конфигурацию
        from config import get_optimized_config
        config = get_optimized_config()
        
        _global_task_manager = TaskManager(max_workers=config.max_workers)
        _global_task_manager.start_workers()
    return _global_task_manager
