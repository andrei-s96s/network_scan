#!/usr/bin/env python3
"""
Мониторинг задач в реальном времени
"""

import time
import json
import requests
from datetime import datetime
from rich.console import Console
from rich.table import Table
from rich.live import Live
from rich.panel import Panel

console = Console()

def get_tasks():
    """Получает список задач с API"""
    try:
        response = requests.get('http://localhost:5000/api/tasks')
        if response.status_code == 200:
            return response.json()
        else:
            console.print(f"[red]Ошибка API: {response.status_code}[/red]")
            return {}
    except Exception as e:
        console.print(f"[red]Ошибка подключения: {e}[/red]")
        return {}

def get_status_emoji(status):
    """Возвращает эмодзи для статуса"""
    emojis = {
        'pending': '⏳',
        'running': '🔄',
        'completed': '✅',
        'failed': '❌',
        'cancelled': '🚫',
        'paused': '⏸️'
    }
    return emojis.get(status, '❓')

def create_table(tasks):
    """Создает таблицу с задачами"""
    table = Table(title="📊 Мониторинг задач")
    
    table.add_column("ID", style="cyan", width=10)
    table.add_column("Имя", style="green", width=20)
    table.add_column("Сеть", style="blue", width=15)
    table.add_column("Статус", style="yellow", width=12)
    table.add_column("Прогресс", style="magenta", width=15)
    table.add_column("Создана", style="white", width=20)
    
    if not tasks:
        table.add_row("", "Нет задач", "", "", "", "")
    else:
        for task_id, task in tasks.items():
            status_emoji = get_status_emoji(task['status'])
            progress_text = f"{task['progress']:.1f}%"
            if task['status'] == 'running':
                progress_text += f" ({task['scanned_hosts']}/{task['total_hosts']})"
            
            created_time = datetime.fromisoformat(task['created_at']).strftime('%H:%M:%S')
            
            table.add_row(
                task_id[:8],
                task['name'][:18],
                task['network'],
                f"{status_emoji} {task['status']}",
                progress_text,
                created_time
            )
    
    return table

def main():
    """Основная функция мониторинга"""
    console.print("[bold blue]🚀 Мониторинг задач сетевого сканера[/bold blue]")
    console.print("Нажмите Ctrl+C для выхода\n")
    
    def generate_table():
        tasks = get_tasks()
        return create_table(tasks)
    
    with Live(generate_table(), refresh_per_second=2, screen=True) as live:
        try:
            while True:
                live.update(generate_table())
                time.sleep(2)
        except KeyboardInterrupt:
            console.print("\n[yellow]Мониторинг остановлен[/yellow]")

if __name__ == "__main__":
    main()
