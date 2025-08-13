"""
Сетевой сканер - основной пакет
"""
__version__ = "2.0.0"
__author__ = "Network Scanner Team"

# Основные компоненты
from .task_manager import TaskManager, Task, get_task_manager
from .network_scanner import NetworkScanner, ScanResult, get_network_scanner
from .screenshot_manager import ImprovedScreenshotManager
from .report_generator import ReportGenerator
from .resource_monitor import ResourceMonitor, ResourceLimits, get_resource_monitor, get_resource_limiter

# Экспорт основных классов
__all__ = [
    'TaskManager',
    'Task', 
    'NetworkScanner',
    'ScanResult',
    'ImprovedScreenshotManager',
    'ReportGenerator',
    'ResourceMonitor',
    'ResourceLimits',
    'get_task_manager',
    'get_network_scanner',
    'get_resource_monitor',
    'get_resource_limiter'
]
