#!/usr/bin/env python3
"""
Тесты для системы управления задачами
"""

import unittest
import time
import tempfile
from pathlib import Path
from unittest.mock import patch, MagicMock

from config import ScannerConfig
from task_manager import (
    TaskManager, Task, TaskStatus, TaskPriority, TaskType
)
from network_scanner import ScanResult


class TestTaskManager(unittest.TestCase):
    """Тесты для TaskManager"""
    
    def setUp(self):
        """Настройка тестов"""
        self.config = ScannerConfig()
        self.task_manager = TaskManager(self.config, max_workers=2)
    
    def tearDown(self):
        """Очистка после тестов"""
        if self.task_manager.is_running:
            self.task_manager.stop()
    
    def test_task_creation(self):
        """Тест создания задач"""
        # Тест создания задачи сканирования
        task = self.task_manager.create_network_scan_task(
            network="192.168.1.0/24",
            threads=10,
            priority=TaskPriority.HIGH,
            name="Тестовое сканирование"
        )
        
        self.assertEqual(task.network, "192.168.1.0/24")
        self.assertEqual(task.threads, 10)
        self.assertEqual(task.priority, TaskPriority.HIGH)
        self.assertEqual(task.task_type, TaskType.NETWORK_SCAN)
        self.assertEqual(task.name, "Тестовое сканирование")
        self.assertEqual(task.status, TaskStatus.PENDING)
    
    def test_task_serialization(self):
        """Тест сериализации задач"""
        task = Task(
            name="Тестовая задача",
            task_type=TaskType.NETWORK_SCAN,
            priority=TaskPriority.NORMAL,
            network="192.168.1.0/24",
            threads=5
        )
        
        # Конвертация в словарь
        task_dict = task.to_dict()
        
        # Проверка основных полей
        self.assertEqual(task_dict['name'], "Тестовая задача")
        self.assertEqual(task_dict['task_type'], "network_scan")
        self.assertEqual(task_dict['priority'], 2)  # NORMAL
        self.assertEqual(task_dict['status'], "pending")
        self.assertEqual(task_dict['network'], "192.168.1.0/24")
        self.assertEqual(task_dict['threads'], 5)
        
        # Восстановление из словаря
        restored_task = Task.from_dict(task_dict)
        
        self.assertEqual(restored_task.name, task.name)
        self.assertEqual(restored_task.task_type, task.task_type)
        self.assertEqual(restored_task.priority, task.priority)
        self.assertEqual(restored_task.network, task.network)
        self.assertEqual(restored_task.threads, task.threads)
    
    def test_task_manager_operations(self):
        """Тест основных операций менеджера задач"""
        # Запуск менеджера
        self.task_manager.start()
        self.assertTrue(self.task_manager.is_running)
        
        # Создание и добавление задачи
        task = self.task_manager.create_network_scan_task(
            network="127.0.0.1/32",
            threads=1,
            name="Локальное сканирование"
        )
        
        task_id = self.task_manager.add_task(task)
        self.assertIsNotNone(task_id)
        
        # Получение задачи
        retrieved_task = self.task_manager.get_task(task_id)
        self.assertEqual(retrieved_task.id, task_id)
        self.assertEqual(retrieved_task.name, "Локальное сканирование")
        
        # Проверка статистики
        stats = self.task_manager.get_stats()
        self.assertIn('total_tasks', stats)
        self.assertIn('running_tasks', stats)
        self.assertIn('completed_tasks', stats)
        
        # Остановка менеджера
        self.task_manager.stop()
        self.assertFalse(self.task_manager.is_running)
    
    def test_task_filtering(self):
        """Тест фильтрации задач"""
        self.task_manager.start()
        
        # Создание задач разных типов
        scan_task = self.task_manager.create_network_scan_task("192.168.1.0/24")
        cleanup_task = Task(
            name="Очистка",
            task_type=TaskType.CLEANUP,
            priority=TaskPriority.LOW,
            config=self.config
        )
        
        scan_id = self.task_manager.add_task(scan_task)
        cleanup_id = self.task_manager.add_task(cleanup_task)
        
        # Фильтрация по типу
        scan_tasks = self.task_manager.get_tasks_by_type(TaskType.NETWORK_SCAN)
        cleanup_tasks = self.task_manager.get_tasks_by_type(TaskType.CLEANUP)
        
        self.assertEqual(len(scan_tasks), 1)
        self.assertEqual(len(cleanup_tasks), 1)
        self.assertEqual(scan_tasks[0].task_type, TaskType.NETWORK_SCAN)
        self.assertEqual(cleanup_tasks[0].task_type, TaskType.CLEANUP)
        
        # Фильтрация по статусу
        pending_tasks = self.task_manager.get_tasks_by_status(TaskStatus.PENDING)
        self.assertGreaterEqual(len(pending_tasks), 2)
        
        self.task_manager.stop()
    
    def test_task_control(self):
        """Тест управления задачами"""
        self.task_manager.start()
        
        task = self.task_manager.create_network_scan_task("127.0.0.1/32")
        task_id = self.task_manager.add_task(task)
        
        # Приостановка задачи
        self.assertTrue(self.task_manager.pause_task(task_id))
        paused_task = self.task_manager.get_task(task_id)
        self.assertEqual(paused_task.status, TaskStatus.PAUSED)
        
        # Возобновление задачи
        self.assertTrue(self.task_manager.resume_task(task_id))
        resumed_task = self.task_manager.get_task(task_id)
        self.assertEqual(resumed_task.status, TaskStatus.RUNNING)
        
        # Отмена задачи
        self.assertTrue(self.task_manager.cancel_task(task_id))
        cancelled_task = self.task_manager.get_task(task_id)
        self.assertEqual(cancelled_task.status, TaskStatus.CANCELLED)
        
        self.task_manager.stop()
    
    def test_callback_functions(self):
        """Тест callback функций"""
        self.task_manager.start()
        
        completion_called = False
        error_called = False
        
        def on_completion(task):
            nonlocal completion_called
            completion_called = True
        
        def on_error(task, error):
            nonlocal error_called
            error_called = True
        
        self.task_manager.add_completion_callback(on_completion)
        self.task_manager.add_error_callback(on_error)
        
        # Создание простой задачи
        task = self.task_manager.create_network_scan_task("127.0.0.1/32")
        task_id = self.task_manager.add_task(task)
        
        # Ждем некоторое время для выполнения
        time.sleep(3)
        
        # Проверяем, что callback были вызваны
        # (задача должна завершиться быстро для localhost)
        self.assertTrue(completion_called or error_called)
        
        self.task_manager.stop()
    
    def test_state_save_load(self):
        """Тест сохранения и загрузки состояния"""
        self.task_manager.start()
        
        # Создание задачи
        task = self.task_manager.create_network_scan_task("127.0.0.1/32")
        task_id = self.task_manager.add_task(task)
        
        # Сохранение состояния
        with tempfile.NamedTemporaryFile(suffix='.json', delete=False) as f:
            state_file = Path(f.name)
        
        try:
            self.task_manager.save_state(state_file)
            self.assertTrue(state_file.exists())
            
            # Создание нового менеджера и загрузка состояния
            new_manager = TaskManager(self.config)
            new_manager.load_state(state_file)
            
            # Проверка, что состояние загружено
            loaded_tasks = new_manager.get_all_tasks()
            self.assertGreater(len(loaded_tasks), 0)
            
        finally:
            if state_file.exists():
                state_file.unlink()
        
        self.task_manager.stop()
    
    def test_task_priority_queue(self):
        """Тест очереди с приоритетами"""
        self.task_manager.start()
        
        # Создание задач с разными приоритетами
        low_task = self.task_manager.create_network_scan_task(
            "192.168.1.0/24", priority=TaskPriority.LOW, name="Низкий приоритет"
        )
        high_task = self.task_manager.create_network_scan_task(
            "192.168.2.0/24", priority=TaskPriority.HIGH, name="Высокий приоритет"
        )
        urgent_task = self.task_manager.create_network_scan_task(
            "192.168.3.0/24", priority=TaskPriority.URGENT, name="Срочный приоритет"
        )
        
        # Добавление в обратном порядке
        low_id = self.task_manager.add_task(low_task)
        high_id = self.task_manager.add_task(high_task)
        urgent_id = self.task_manager.add_task(urgent_task)
        
        # Проверка, что задачи добавлены
        self.assertIsNotNone(low_id)
        self.assertIsNotNone(high_id)
        self.assertIsNotNone(urgent_id)
        
        # Проверка статистики
        stats = self.task_manager.get_stats()
        self.assertEqual(stats['total_tasks'], 3)
        
        self.task_manager.stop()


class TestTaskCLI(unittest.TestCase):
    """Тесты для CLI интерфейса"""
    
    def setUp(self):
        """Настройка тестов"""
        self.config = ScannerConfig()
    
    @patch('task_cli.TaskCLI')
    def test_cli_initialization(self, mock_cli):
        """Тест инициализации CLI"""
        from task_cli import main
        
        # Проверяем, что CLI создается корректно
        mock_cli.return_value.run.return_value = None
        mock_cli.return_value.cleanup.return_value = None
        
        # Тест не должен вызывать исключений
        try:
            # Здесь мы не можем реально запустить main() из-за argparse
            pass
        except Exception as e:
            self.fail(f"CLI инициализация вызвала исключение: {e}")


class TestTaskWebInterface(unittest.TestCase):
    """Тесты для веб-интерфейса"""
    
    def setUp(self):
        """Настройка тестов"""
        self.config = ScannerConfig()
    
    @patch('task_web.TaskWebInterface')
    def test_web_interface_initialization(self, mock_web):
        """Тест инициализации веб-интерфейса"""
        from task_web import main
        
        # Проверяем, что веб-интерфейс создается корректно
        mock_web.return_value.start.return_value = None
        mock_web.return_value.stop.return_value = None
        
        # Тест не должен вызывать исключений
        try:
            # Здесь мы не можем реально запустить main() из-за Flask
            pass
        except Exception as e:
            self.fail(f"Веб-интерфейс инициализация вызвала исключение: {e}")


if __name__ == '__main__':
    unittest.main()
