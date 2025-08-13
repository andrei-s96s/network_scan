#!/usr/bin/env python3
"""
CLI интерфейс для управления задачами сканирования
"""

import argparse
import sys
import time
from pathlib import Path
from typing import Optional, List
from rich.console import Console
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.panel import Panel
from rich.layout import Layout
from rich.live import Live
from rich.text import Text
from datetime import datetime

from config import ScannerConfig, load_config
from task_manager import TaskManager, Task, TaskStatus, TaskType


class TaskCLI:
    """CLI интерфейс для управления задачами"""
    
    def __init__(self):
        self.console = Console()
        self.config = load_config()
        self.task_manager = TaskManager(self.config, max_workers=5)
        
        # Запускаем менеджер задач
        self.task_manager.start()
        
        # Добавляем callback функции
        self.task_manager.add_completion_callback(self._on_task_completion)
        self.task_manager.add_error_callback(self._on_task_error)
    
    def _on_task_completion(self, task: Task):
        """Callback при завершении задачи"""
        self.console.print(f"[green]✓ Задача завершена: {task.name}[/green]")
    
    def _on_task_error(self, task: Task, error: Exception):
        """Callback при ошибке задачи"""
        self.console.print(f"[red]✗ Ошибка в задаче {task.name}: {error}[/red]")
    
    def run(self):
        """Запускает CLI интерфейс"""
        parser = argparse.ArgumentParser(description="Менеджер задач сетевого сканера")
        subparsers = parser.add_subparsers(dest="command", help="Доступные команды")
        
        # Команда добавления задачи сканирования
        scan_parser = subparsers.add_parser("scan", help="Добавить задачу сканирования")
        scan_parser.add_argument("network", help="Сеть для сканирования (например, 192.168.1.0/24)")
        scan_parser.add_argument("--threads", "-t", type=int, default=10, help="Количество потоков")
        # Убираем приоритеты - упрощаем систему
        scan_parser.add_argument("--name", "-n", help="Имя задачи")
        
        # Команда создания скриншотов
        screenshot_parser = subparsers.add_parser("screenshot", help="Создать скриншоты")
        screenshot_parser.add_argument("network", help="Сеть для скриншотов")
        # Убираем приоритеты - упрощаем систему
        screenshot_parser.add_argument("--name", "-n", help="Имя задачи")
        
        # Команда генерации отчетов
        report_parser = subparsers.add_parser("report", help="Генерировать отчеты")
        report_parser.add_argument("network", help="Сеть для отчетов")
        # Убираем приоритеты - упрощаем систему
        report_parser.add_argument("--name", "-n", help="Имя задачи")
        
        # Команда очистки
        cleanup_parser = subparsers.add_parser("cleanup", help="Очистка временных файлов")
        # Убираем приоритеты - упрощаем систему
        cleanup_parser.add_argument("--name", "-n", help="Имя задачи")
        
        # Команда сжатия
        compress_parser = subparsers.add_parser("compress", help="Сжатие результатов")
        compress_parser.add_argument("network", help="Сеть для сжатия")
        # Убираем приоритеты - упрощаем систему
        compress_parser.add_argument("--name", "-n", help="Имя задачи")
        
        # Команда списка задач
        list_parser = subparsers.add_parser("list", help="Показать список задач")
        list_parser.add_argument("--status", choices=["pending", "running", "completed", "failed", "cancelled", "paused"],
                               help="Фильтр по статусу")
        list_parser.add_argument("--type", choices=["network_scan", "screenshot_creation", "report_generation", "cleanup", "compression"],
                               help="Фильтр по типу")
        
        # Команда информации о задаче
        info_parser = subparsers.add_parser("info", help="Информация о задаче")
        info_parser.add_argument("task_id", help="ID задачи")
        
        # Команда управления задачами
        control_parser = subparsers.add_parser("control", help="Управление задачами")
        control_parser.add_argument("action", choices=["cancel", "pause", "resume", "delete"], help="Действие")
        control_parser.add_argument("task_id", help="ID задачи")
        
        # Команда скачивания файлов
        download_parser = subparsers.add_parser("download", help="Скачать файлы задачи")
        download_parser.add_argument("task_id", help="ID задачи")
        download_parser.add_argument("--output", "-o", help="Путь для сохранения архива")
        
        # Команда статистики
        stats_parser = subparsers.add_parser("stats", help="Статистика менеджера задач")
        
        # Команда мониторинга
        monitor_parser = subparsers.add_parser("monitor", help="Мониторинг задач в реальном времени")
        
        # Команда интерактивного режима
        interactive_parser = subparsers.add_parser("interactive", help="Интерактивный режим")
        
        args = parser.parse_args()
        
        if args.command == "scan":
            self._add_scan_task(args)
        elif args.command == "screenshot":
            self._add_screenshot_task(args)
        elif args.command == "report":
            self._add_report_task(args)
        elif args.command == "cleanup":
            self._add_cleanup_task(args)
        elif args.command == "compress":
            self._add_compress_task(args)
        elif args.command == "list":
            self._list_tasks(args)
        elif args.command == "info":
            self._show_task_info(args.task_id)
        elif args.command == "control":
            self._control_task(args.action, args.task_id)
        elif args.command == "download":
            self._download_task_files(args.task_id, args.output)
        elif args.command == "stats":
            self._show_stats()
        elif args.command == "monitor":
            self._monitor_tasks()
        elif args.command == "interactive":
            self._interactive_mode()
        else:
            parser.print_help()
    
    # Убираем приоритеты - упрощаем систему
    
    def _add_scan_task(self, args):
        """Добавляет задачу сканирования"""
        task = self.task_manager.create_network_scan_task(
            network=args.network,
            threads=args.threads,
            name=args.name
        )
        
        task_id = self.task_manager.add_task(task)
        self.console.print(f"[green]Задача сканирования добавлена: {task_id}[/green]")
    
    def _add_screenshot_task(self, args):
        """Добавляет задачу создания скриншотов"""
        # Для создания скриншотов нужны результаты сканирования
        # Пока что создаем пустую задачу
        task = self.task_manager.create_screenshot_task(
            scan_results=[],  # Пустой список, нужно будет заполнить
            network=args.network,
            name=args.name
        )
        
        task_id = self.task_manager.add_task(task)
        self.console.print(f"[green]Задача создания скриншотов добавлена: {task_id}[/green]")
    
    def _add_report_task(self, args):
        """Добавляет задачу генерации отчетов"""
        task = self.task_manager.create_report_task(
            scan_results=[],  # Пустой список, нужно будет заполнить
            network=args.network,
            screenshots_count={},  # Пустой словарь, нужно будет заполнить
            name=args.name
        )
        
        task_id = self.task_manager.add_task(task)
        self.console.print(f"[green]Задача генерации отчетов добавлена: {task_id}[/green]")
    
    def _add_cleanup_task(self, args):
        """Добавляет задачу очистки"""
        task = Task(
            name=args.name or "Очистка временных файлов",
            task_type=TaskType.CLEANUP,
            config=self.config
        )
        
        task_id = self.task_manager.add_task(task)
        self.console.print(f"[green]Задача очистки добавлена: {task_id}[/green]")
    
    def _add_compress_task(self, args):
        """Добавляет задачу сжатия"""
        task = Task(
            name=args.name or f"Сжатие результатов {args.network}",
            task_type=TaskType.COMPRESSION,
            network=args.network,
            config=self.config
        )
        
        task_id = self.task_manager.add_task(task)
        self.console.print(f"[green]Задача сжатия добавлена: {task_id}[/green]")
    
    def _list_tasks(self, args):
        """Показывает список задач"""
        tasks = self.task_manager.get_all_tasks()
        
        if args.status:
            status = TaskStatus(args.status)
            tasks = {k: v for k, v in tasks.items() if v.status == status}
        
        if args.type:
            task_type = TaskType(args.type)
            tasks = {k: v for k, v in tasks.items() if v.task_type == task_type}
        
        if not tasks:
            self.console.print("[yellow]Задачи не найдены[/yellow]")
            return
        
        table = Table(title="Список задач")
        table.add_column("ID", style="cyan")
        table.add_column("Имя", style="white")
        table.add_column("Тип", style="blue")
        table.add_column("Статус", style="green")
        # Убираем приоритеты - упрощаем систему
        table.add_column("Создана", style="magenta")
        table.add_column("Прогресс", style="green")
        
        for task_id, task in tasks.items():
            status_color = {
                TaskStatus.PENDING: "yellow",
                TaskStatus.RUNNING: "blue",
                TaskStatus.COMPLETED: "green",
                TaskStatus.FAILED: "red",
                TaskStatus.CANCELLED: "red",
                TaskStatus.PAUSED: "yellow"
            }.get(task.status, "white")
            
            table.add_row(
                task_id[:8],
                task.name,
                task.task_type.value,
                f"[{status_color}]{task.status.value}[/{status_color}]",
                # Убираем приоритеты - упрощаем систему
                task.created_at.strftime("%H:%M:%S"),
                f"{task.progress:.1f}%"
            )
        
        self.console.print(table)
    
    def _show_task_info(self, task_id: str):
        """Показывает информацию о задаче"""
        task = self.task_manager.get_task(task_id)
        if not task:
            self.console.print(f"[red]Задача {task_id} не найдена[/red]")
            return
        
        info = f"""
[bold]Информация о задаче[/bold]

ID: {task.id}
Имя: {task.name}
Тип: {task.task_type.value}
Статус: {task.status.value}
# Убираем приоритеты - упрощаем систему

Создана: {task.created_at.strftime("%Y-%m-%d %H:%M:%S")}
"""
        
        if task.started_at:
            info += f"Запущена: {task.started_at.strftime('%Y-%m-%d %H:%M:%S')}\n"
        
        if task.completed_at:
            info += f"Завершена: {task.completed_at.strftime('%Y-%m-%d %H:%M:%S')}\n"
        
        info += f"""
Прогресс: {task.progress:.1f}%
Сканировано хостов: {task.scanned_hosts}/{task.total_hosts}
"""
        
        if task.error_message:
            info += f"\n[red]Ошибка: {task.error_message}[/red]"
        
        if task.results:
            info += f"\nРезультатов: {len(task.results)}"
        
        if task.screenshots_count:
            info += f"\nСкриншотов: {sum(task.screenshots_count.values())}"
        
        self.console.print(Panel(info, title="Информация о задаче"))
    
    def _control_task(self, action: str, task_id: str):
        """Управляет задачей"""
        if action == "cancel":
            if self.task_manager.cancel_task(task_id):
                self.console.print(f"[green]Задача {task_id} отменена[/green]")
            else:
                self.console.print(f"[red]Не удалось отменить задачу {task_id}[/red]")
        
        elif action == "pause":
            if self.task_manager.pause_task(task_id):
                self.console.print(f"[green]Задача {task_id} приостановлена[/green]")
            else:
                self.console.print(f"[red]Не удалось приостановить задачу {task_id}[/red]")
        
        elif action == "resume":
            if self.task_manager.resume_task(task_id):
                self.console.print(f"[green]Задача {task_id} возобновлена[/green]")
            else:
                self.console.print(f"[red]Не удалось возобновить задачу {task_id}[/red]")
        elif action == "delete":
            if self.task_manager.delete_task(task_id):
                self.console.print(f"[green]Задача {task_id} удалена[/green]")
            else:
                self.console.print(f"[red]Не удалось удалить задачу {task_id}[/red]")
    
    def _download_task_files(self, task_id: str, output_path: Optional[str] = None):
        """Скачивает файлы задачи"""
        task = self.task_manager.get_task(task_id)
        if not task:
            self.console.print(f"[red]Задача {task_id} не найдена[/red]")
            return
        
        if task.status != TaskStatus.COMPLETED:
            self.console.print(f"[red]Задача {task_id} еще не завершена[/red]")
            return
        
        try:
            from pathlib import Path
            import zipfile
            import tempfile
            import os
            
            # Определяем директорию с результатами
            scan_dir = Path(f"scan-{task.network.replace('/', '_')}")
            if not scan_dir.exists():
                self.console.print(f"[red]Файлы задачи {task_id} не найдены[/red]")
                return
            
            # Определяем путь для сохранения
            if output_path:
                archive_path = Path(output_path)
            else:
                archive_path = Path(f"task_{task_id}_{task.network.replace('/', '_')}.zip")
            
            # Создаем архив
            with zipfile.ZipFile(archive_path, 'w', zipfile.ZIP_DEFLATED) as zipf:
                for root, dirs, files in os.walk(scan_dir):
                    for file in files:
                        file_path = Path(root) / file
                        arcname = file_path.relative_to(scan_dir)
                        zipf.write(file_path, arcname)
            
            self.console.print(f"[green]Файлы задачи {task_id} сохранены в {archive_path}[/green]")
            
        except Exception as e:
            self.console.print(f"[red]Ошибка при создании архива: {e}[/red]")
    
    def _show_stats(self):
        """Показывает статистику"""
        stats = self.task_manager.get_stats()
        
        info = f"""
[bold]Статистика менеджера задач[/bold]

Всего задач: {stats['total_tasks']}
Выполняется: {stats['running_tasks']}
В очереди: {stats['pending_tasks']}
Завершено: {stats['completed_tasks']}
Ошибок: {stats['failed_tasks']}
Отменено: {stats['cancelled_tasks']}

Максимум исполнителей: {stats['max_workers']}
Статус: {'Запущен' if stats['is_running'] else 'Остановлен'}
"""
        
        self.console.print(Panel(info, title="Статистика"))
    
    def _monitor_tasks(self):
        """Мониторинг задач в реальном времени"""
        self.console.print("[bold blue]Мониторинг задач (Ctrl+C для выхода)[/bold blue]")
        
        try:
            with Live(self._create_monitor_layout(), refresh_per_second=1) as live:
                while True:
                    live.update(self._create_monitor_layout())
                    time.sleep(1)
        except KeyboardInterrupt:
            self.console.print("\n[yellow]Мониторинг остановлен[/yellow]")
    
    def _create_monitor_layout(self):
        """Создает layout для мониторинга"""
        layout = Layout()
        
        # Статистика
        stats = self.task_manager.get_stats()
        stats_text = f"""
Всего задач: {stats['total_tasks']}
Выполняется: {stats['running_tasks']}
В очереди: {stats['pending_tasks']}
Завершено: {stats['completed_tasks']}
Ошибок: {stats['failed_tasks']}
"""
        
        layout.split_column(
            Layout(Panel(stats_text, title="Статистика"), name="stats"),
            Layout(name="tasks")
        )
        
        # Активные задачи
        running_tasks = self.task_manager.get_tasks_by_status(TaskStatus.RUNNING)
        if running_tasks:
            tasks_table = Table(title="Выполняющиеся задачи")
            tasks_table.add_column("ID")
            tasks_table.add_column("Имя")
            tasks_table.add_column("Прогресс")
            tasks_table.add_column("Время")
            
            for task in running_tasks:
                runtime = ""
                if task.started_at:
                    runtime = str(datetime.now() - task.started_at).split('.')[0]
                
                tasks_table.add_row(
                    task.id[:8],
                    task.name,
                    f"{task.progress:.1f}%",
                    runtime
                )
            
            layout["tasks"].update(Panel(tasks_table))
        else:
            layout["tasks"].update(Panel("Нет выполняющихся задач", title="Задачи"))
        
        return layout
    
    def _interactive_mode(self):
        """Интерактивный режим"""
        self.console.print("[bold blue]Интерактивный режим управления задачами[/bold blue]")
        self.console.print("Доступные команды:")
        self.console.print("  scan <сеть> [--threads N] [--priority P] - добавить сканирование")
        self.console.print("  screenshot <сеть> [--priority P] - добавить скриншоты")
        self.console.print("  report <сеть> [--priority P] - добавить отчеты")
        self.console.print("  cleanup [--priority P] - добавить очистку")
        self.console.print("  compress <сеть> [--priority P] - добавить сжатие")
        self.console.print("  list [--status S] [--type T] - список задач")
        self.console.print("  info <task_id> - информация о задаче")
        self.console.print("  cancel <task_id> - отменить задачу")
        self.console.print("  pause <task_id> - приостановить задачу")
        self.console.print("  resume <task_id> - возобновить задачу")
        self.console.print("  stats - статистика")
        self.console.print("  monitor - мониторинг")
        self.console.print("  quit - выход")
        
        while True:
            try:
                command = input("\n> ").strip()
                if command == "quit":
                    break
                elif command == "stats":
                    self._show_stats()
                elif command == "monitor":
                    self._monitor_tasks()
                elif command.startswith("list"):
                    # Простой парсинг для list команды
                    parts = command.split()
                    args = argparse.Namespace()
                    args.status = None
                    args.type = None
                    
                    for i, part in enumerate(parts):
                        if part == "--status" and i + 1 < len(parts):
                            args.status = parts[i + 1]
                        elif part == "--type" and i + 1 < len(parts):
                            args.type = parts[i + 1]
                    
                    self._list_tasks(args)
                elif command.startswith("info "):
                    task_id = command.split()[1]
                    self._show_task_info(task_id)
                elif command.startswith("cancel "):
                    task_id = command.split()[1]
                    self._control_task("cancel", task_id)
                elif command.startswith("pause "):
                    task_id = command.split()[1]
                    self._control_task("pause", task_id)
                elif command.startswith("resume "):
                    task_id = command.split()[1]
                    self._control_task("resume", task_id)
                else:
                    self.console.print("[red]Неизвестная команда[/red]")
            
            except KeyboardInterrupt:
                break
            except Exception as e:
                self.console.print(f"[red]Ошибка: {e}[/red]")
        
        self.console.print("[yellow]Интерактивный режим завершен[/yellow]")
    
    def cleanup(self):
        """Очистка ресурсов"""
        self.task_manager.stop()


def main():
    """Главная функция"""
    cli = TaskCLI()
    try:
        cli.run()
    finally:
        cli.cleanup()


if __name__ == "__main__":
    main()
