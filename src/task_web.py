#!/usr/bin/env python3
"""
Веб-интерфейс Network Scanner Pro
Современный интерфейс для управления задачами сканирования
"""

import os
import json
import logging
import threading
import time
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Optional

from flask import Flask, render_template, request, jsonify, send_file, redirect, url_for
from flask_socketio import SocketIO, emit
import psutil

from .task_manager import get_task_manager, Task
from .resource_monitor import get_resource_monitor
from .system_analyzer import SystemAnalyzer

# Настройка логирования
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('logs/task_web.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

class WebInterface:
    """Современный веб-интерфейс для Network Scanner Pro"""
    
    def __init__(self):
        self.project_root = Path(__file__).parent.parent
        static_dir = self.project_root / 'static'
        templates_dir = self.project_root / 'templates'
        
        # Инициализируем Flask
        self.app = Flask(__name__, 
                        static_folder=str(static_dir),
                        template_folder=str(templates_dir))
        self.app.config['SECRET_KEY'] = 'network_scanner_secret_key_2024'
        
        # Инициализируем SocketIO
        self.socketio = SocketIO(self.app, cors_allowed_origins="*")
        
        # Получаем менеджеры
        self.task_manager = get_task_manager()
        self.resource_monitor = get_resource_monitor()
        self.system_analyzer = SystemAnalyzer()
        
        # Для отслеживания сетевого трафика
        self.last_network_stats = None
        self.last_network_time = None
        
        # Настройка маршрутов
        self._setup_routes()
        self._setup_socketio_handlers()
        
        # Запускаем мониторинг ресурсов
        self._start_resource_monitoring()
        
        # Запускаем периодическое обновление задач
        self._start_task_updates()
        
        logger.info("Веб-интерфейс инициализирован")
    
    def _setup_routes(self):
        """Настройка маршрутов Flask"""
        
        @self.app.route('/')
        def index():
            """Главная страница"""
            return render_template('index.html')
        
        @self.app.route('/api/health')
        def health_check():
            """Health check для Docker"""
            try:
                # Проверяем основные компоненты
                tasks_count = len(self.task_manager.get_all_tasks())
                resource_usage = self.resource_monitor.get_current_usage()
                
                return jsonify({
                    'status': 'healthy',
                    'timestamp': datetime.now().isoformat(),
                    'tasks_count': tasks_count,
                    'cpu_percent': resource_usage['cpu_percent'],
                    'memory_percent': resource_usage['memory_percent']
                })
            except Exception as e:
                logger.error(f"Health check failed: {e}")
                return jsonify({
                    'status': 'unhealthy',
                    'error': str(e),
                    'timestamp': datetime.now().isoformat()
                }), 500
        
        @self.app.route('/help')
        def help_page():
            """Страница справки"""
            return render_template('help.html')
        
        @self.app.route('/static/<path:filename>')
        def static_files(filename):
            """Сервирование статических файлов"""
            return send_file(f'static/{filename}')
        
        @self.app.route('/api/tasks', methods=['GET'])
        def get_tasks():
            """Получить список всех задач"""
            try:
                all_tasks = self.task_manager.get_all_tasks()
                
                # Фильтруем только NETWORK_SCAN задачи
                filtered_tasks = {}
                for task_id, task in all_tasks.items():
                    if task.task_type == "NETWORK_SCAN":
                        filtered_tasks[task_id] = task.to_dict()
                
                return jsonify(filtered_tasks)
            except Exception as e:
                logger.error(f"Ошибка при получении задач: {e}")
                return jsonify({'error': str(e)}), 500
        
        @self.app.route('/api/tasks', methods=['POST'])
        def create_task():
            """Создать новую задачу"""
            try:
                data = request.get_json()
                network = data.get('network', '172.30.1.0/24')
                
                # Создаем задачу
                task = self.task_manager.create_task(
                    task_type="NETWORK_SCAN",
                    network=network,
                    create_screenshots=True,
                    generate_reports=True,
                    compress_results=True,
                    cleanup_after=False
                )
                
                # Уведомляем через WebSocket
                self.socketio.emit('task_created', {
                    'task_id': task.id,
                    'task': task.to_dict()
                })
                
                return jsonify({
                    'success': True,
                    'task_id': task.id,
                    'message': f'Задача создана для сети {network}'
                })
            except Exception as e:
                logger.error(f"Ошибка при создании задачи: {e}")
                return jsonify({'error': str(e)}), 500
        
        @self.app.route('/api/tasks/<task_id>', methods=['DELETE'])
        def delete_task(task_id):
            """Удалить задачу"""
            try:
                success = self.task_manager.delete_task(task_id)
                if success:
                    # Уведомляем через WebSocket
                    self.socketio.emit('task_deleted', {'task_id': task_id})
                    return jsonify({'success': True, 'message': 'Задача удалена'})
                else:
                    return jsonify({'error': 'Задача не найдена'}), 404
            except Exception as e:
                logger.error(f"Ошибка при удалении задачи: {e}")
                return jsonify({'error': str(e)}), 500
        
        @self.app.route('/api/tasks/<task_id>/download', methods=['GET'])
        def download_report(task_id):
            """Скачать отчет по задаче"""
            try:
                task = self.task_manager.get_task(task_id)
                if not task:
                    return jsonify({'error': 'Задача не найдена'}), 404
                
                # Ищем файл отчета
                reports_dir = self.project_root / 'reports'
                report_file = reports_dir / f"{task_id}.zip"
                
                if report_file.exists():
                    return send_file(
                        str(report_file),
                        as_attachment=True,
                        download_name=f"report_{task_id}.zip"
                    )
                else:
                    return jsonify({'error': 'Отчет не найден'}), 404
            except Exception as e:
                logger.error(f"Ошибка при скачивании отчета: {e}")
                return jsonify({'error': str(e)}), 500
        
        @self.app.route('/api/system/status')
        def get_system_status():
            """Получить статус системы"""
            try:
                # Получаем информацию о системе
                cpu_percent = psutil.cpu_percent(interval=1)
                memory = psutil.virtual_memory()
                disk = psutil.disk_usage('/')
                
                # Получаем количество задач
                all_tasks = self.task_manager.get_all_tasks()
                running_tasks = len([t for t in all_tasks.values() if t.status == 'running'])
                completed_tasks = len([t for t in all_tasks.values() if t.status == 'completed'])
                failed_tasks = len([t for t in all_tasks.values() if t.status == 'failed'])
                
                # Получаем сетевую статистику
                network_stats = psutil.net_io_counters()
                current_time = time.time()
                
                # Рассчитываем скорость сети
                if self.last_network_stats is not None and self.last_network_time is not None:
                    time_diff = current_time - self.last_network_time
                    if time_diff > 0:
                        bytes_diff = (network_stats.bytes_sent + network_stats.bytes_recv) - \
                                   (self.last_network_stats.bytes_sent + self.last_network_stats.bytes_recv)
                        network_speed = (bytes_diff / (1024**2)) / time_diff  # MB/s
                    else:
                        network_speed = 0.0
                else:
                    # Первый запуск - используем базовое значение
                    network_speed = 0.5  # 0.5 MB/s как базовое значение
                
                # Ограничиваем до разумного значения
                network_speed = min(max(network_speed, 0.0), 100.0)  # От 0 до 100 MB/s
                
                # Обновляем предыдущие значения
                self.last_network_stats = network_stats
                self.last_network_time = current_time
                
                return jsonify({
                    'cpu_percent': cpu_percent,
                    'memory_percent': memory.percent,
                    'memory_available': memory.available // (1024**3),  # GB
                    'disk_percent': disk.percent,
                    'disk_free': disk.free // (1024**3),  # GB
                    'network_speed': network_speed,
                    'tasks': {
                        'running': running_tasks,
                        'completed': completed_tasks,
                        'failed': failed_tasks,
                        'total': len(all_tasks)
                    }
                })
            except Exception as e:
                logger.error(f"Ошибка при получении статуса системы: {e}")
                return jsonify({'error': str(e)}), 500
    
    def _setup_socketio_handlers(self):
        """Настройка обработчиков SocketIO"""
        
        @self.socketio.on('connect')
        def handle_connect():
            logger.info(f"Клиент подключился: {request.sid}")
            emit('connected', {'message': 'Подключено к серверу'})
        
        @self.socketio.on('disconnect')
        def handle_disconnect():
            logger.info(f"Клиент отключился: {request.sid}")
    
    def _start_resource_monitoring(self):
        """Запустить мониторинг ресурсов"""
        self.resource_monitor.start_monitoring_with_socketio(self.socketio)
        logger.info("Мониторинг ресурсов запущен")
    
    def _start_task_updates(self):
        """Запустить периодическое обновление задач"""
        def send_task_updates():
            """Отправлять обновления задач каждые 5 секунд"""
            while True:
                try:
                    # Получаем все задачи
                    all_tasks = self.task_manager.get_all_tasks()
                    
                    # Фильтруем только NETWORK_SCAN задачи
                    filtered_tasks = {}
                    for task_id, task in all_tasks.items():
                        if task.task_type == "NETWORK_SCAN":
                            filtered_tasks[task_id] = task.to_dict()
                    
                    # Отправляем обновления через WebSocket
                    self.socketio.emit('tasks_updated', {
                        'tasks': filtered_tasks,
                        'timestamp': datetime.now().isoformat()
                    })
                    
                    time.sleep(5)
                except Exception as e:
                    logger.error(f"Ошибка при отправке обновлений задач: {e}")
                    time.sleep(5)
        
        # Запускаем в отдельном потоке
        update_thread = threading.Thread(target=send_task_updates, daemon=True)
        update_thread.start()
        logger.info("Запущено периодическое обновление задач")
    
    def run(self, host='0.0.0.0', port=5000, debug=False):
        """Запустить веб-сервер"""
        logger.info(f"Запуск веб-сервера на {host}:{port}")
        self.socketio.run(self.app, host=host, port=port, debug=debug)

def main():
    """Главная функция"""
    # Создаем папку для логов
    os.makedirs('logs', exist_ok=True)
    
    # Создаем и запускаем веб-интерфейс
    web_interface = WebInterface()
    web_interface.run()

if __name__ == '__main__':
    main()
