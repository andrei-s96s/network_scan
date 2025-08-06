#!/usr/bin/env python3
"""
Потоковый процессор для обработки больших сетей
"""

import asyncio
import logging
from pathlib import Path
from typing import Dict, List, Optional, AsyncGenerator, Callable, Any
from dataclasses import dataclass, asdict
import json
import gzip
from datetime import datetime

from network_scanner import ScanResult, AsyncNetworkScanner
from config import ScannerConfig


@dataclass
class StreamConfig:
    """Конфигурация потоковой обработки"""
    
    batch_size: int = 100  # Размер пакета хостов
    max_memory_mb: int = 512  # Максимальное использование памяти в МБ
    save_interval: int = 50  # Интервал сохранения результатов
    compression: bool = True  # Сжатие промежуточных файлов
    temp_dir: Path = Path(".temp")  # Временная директория


class StreamProcessor:
    """Потоковый процессор для больших сетей"""
    
    def __init__(self, config: ScannerConfig, stream_config: StreamConfig):
        self.config = config
        self.stream_config = stream_config
        self.logger = logging.getLogger(__name__)
        self.scanner = AsyncNetworkScanner(config)
        
        # Создаем временную директорию
        self.stream_config.temp_dir.mkdir(exist_ok=True)
        
        # Статистика
        self.stats = {
            'processed_hosts': 0,
            'found_hosts': 0,
            'batches_processed': 0,
            'memory_usage_mb': 0,
            'start_time': None,
            'last_save_time': None
        }
    
    async def process_network_stream(
        self, 
        network: str,
        callback: Optional[Callable[[List[ScanResult]], None]] = None
    ) -> AsyncGenerator[List[ScanResult], None]:
        """Потоково обрабатывает сеть"""
        import ipaddress
        
        try:
            network_obj = ipaddress.IPv4Network(network, strict=False)
        except ValueError as e:
            raise ValueError(f"Неверный формат сети: {e}")
        
        self.stats['start_time'] = datetime.now()
        self.logger.info(f"Начинаем потоковую обработку сети {network} ({network_obj.num_addresses} адресов)")
        
        # Получаем все хосты
        hosts = list(network_obj.hosts())
        total_hosts = len(hosts)
        
        # Обрабатываем пакетами
        for i in range(0, total_hosts, self.stream_config.batch_size):
            batch_hosts = hosts[i:i + self.stream_config.batch_size]
            batch_results = []
            
            self.logger.info(f"Обрабатываем пакет {i//self.stream_config.batch_size + 1}/{(total_hosts + self.stream_config.batch_size - 1)//self.stream_config.batch_size}")
            
            # Сканируем пакет хостов
            for ip in batch_hosts:
                try:
                    result = await self.scanner.scan_host_async(str(ip))
                    if result.open_ports:  # Только хосты с открытыми портами
                        batch_results.append(result)
                        self.stats['found_hosts'] += 1
                    
                    self.stats['processed_hosts'] += 1
                    
                    # Проверяем использование памяти
                    self._check_memory_usage()
                    
                except Exception as e:
                    self.logger.error(f"Ошибка при сканировании {ip}: {e}")
                    self.stats['processed_hosts'] += 1
            
            # Сохраняем промежуточные результаты
            if batch_results:
                await self._save_batch_results(batch_results, i // self.stream_config.batch_size)
                
                # Вызываем callback если предоставлен
                if callback:
                    callback(batch_results)
                
                # Возвращаем результаты через генератор
                yield batch_results
            
            self.stats['batches_processed'] += 1
            
            # Периодическое сохранение статистики
            if self.stats['batches_processed'] % 5 == 0:
                await self._save_stats()
        
        self.logger.info(f"Потоковая обработка завершена. Обработано {self.stats['processed_hosts']} хостов, найдено {self.stats['found_hosts']} активных")
    
    def _check_memory_usage(self):
        """Проверяет использование памяти"""
        try:
            import psutil
            process = psutil.Process()
            memory_mb = process.memory_info().rss / (1024 * 1024)
            self.stats['memory_usage_mb'] = round(memory_mb, 2)
            
            if memory_mb > self.stream_config.max_memory_mb:
                self.logger.warning(f"Высокое использование памяти: {memory_mb:.2f} МБ")
                
        except ImportError:
            # psutil не установлен, пропускаем проверку
            pass
    
    async def _save_batch_results(self, results: List[ScanResult], batch_num: int):
        """Сохраняет результаты пакета"""
        try:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"batch_{batch_num:04d}_{timestamp}.json"
            
            if self.stream_config.compression:
                filename += ".gz"
                filepath = self.stream_config.temp_dir / filename
                
                # Сохраняем сжатый JSON
                data = {
                    'batch_num': batch_num,
                    'timestamp': timestamp,
                    'results': [asdict(result) for result in results]
                }
                
                with gzip.open(filepath, 'wt', encoding='utf-8') as f:
                    json.dump(data, f, indent=2, default=str)
            else:
                filepath = self.stream_config.temp_dir / filename
                
                # Сохраняем обычный JSON
                data = {
                    'batch_num': batch_num,
                    'timestamp': timestamp,
                    'results': [asdict(result) for result in results]
                }
                
                with open(filepath, 'w', encoding='utf-8') as f:
                    json.dump(data, f, indent=2, default=str)
            
            self.logger.debug(f"Сохранен пакет {batch_num}: {len(results)} результатов")
            self.stats['last_save_time'] = datetime.now()
            
        except Exception as e:
            self.logger.error(f"Ошибка при сохранении пакета {batch_num}: {e}")
    
    async def _save_stats(self):
        """Сохраняет статистику обработки"""
        try:
            stats_file = self.stream_config.temp_dir / "processing_stats.json"
            
            # Добавляем время выполнения
            if self.stats['start_time']:
                elapsed = datetime.now() - self.stats['start_time']
                self.stats['elapsed_seconds'] = elapsed.total_seconds()
            
            with open(stats_file, 'w', encoding='utf-8') as f:
                json.dump(self.stats, f, indent=2, default=str)
                
        except Exception as e:
            self.logger.error(f"Ошибка при сохранении статистики: {e}")
    
    async def merge_results(self, output_file: Path) -> Dict[str, Any]:
        """Объединяет все промежуточные результаты"""
        try:
            all_results = []
            
            # Читаем все пакеты
            for batch_file in sorted(self.stream_config.temp_dir.glob("batch_*.json*")):
                try:
                    if batch_file.suffix == '.gz':
                        with gzip.open(batch_file, 'rt', encoding='utf-8') as f:
                            data = json.load(f)
                    else:
                        with open(batch_file, 'r', encoding='utf-8') as f:
                            data = json.load(f)
                    
                    # Восстанавливаем ScanResult из словарей
                    for result_data in data['results']:
                        scan_result = ScanResult(
                            ip=result_data['ip'],
                            open_ports=result_data['open_ports'],
                            detected_os=result_data.get('detected_os'),
                            screenshots_count=result_data.get('screenshots_count', 0),
                            scan_time=result_data.get('scan_time', 0.0)
                        )
                        all_results.append(scan_result)
                        
                except Exception as e:
                    self.logger.warning(f"Ошибка при чтении пакета {batch_file}: {e}")
            
            # Сохраняем объединенные результаты
            final_data = {
                'scan_info': {
                    'total_hosts': self.stats['processed_hosts'],
                    'found_hosts': len(all_results),
                    'processing_time': self.stats.get('elapsed_seconds', 0),
                    'memory_usage_mb': self.stats['memory_usage_mb']
                },
                'results': [asdict(result) for result in all_results]
            }
            
            with open(output_file, 'w', encoding='utf-8') as f:
                json.dump(final_data, f, indent=2, default=str)
            
            self.logger.info(f"Объединено {len(all_results)} результатов в {output_file}")
            
            return {
                'total_results': len(all_results),
                'output_file': str(output_file),
                'stats': self.stats
            }
            
        except Exception as e:
            self.logger.error(f"Ошибка при объединении результатов: {e}")
            return {}
    
    def cleanup_temp_files(self) -> int:
        """Очищает временные файлы"""
        try:
            count = 0
            for temp_file in self.stream_config.temp_dir.glob("*"):
                if temp_file.is_file():
                    temp_file.unlink()
                    count += 1
            
            self.logger.info(f"Очищено {count} временных файлов")
            return count
            
        except Exception as e:
            self.logger.error(f"Ошибка при очистке временных файлов: {e}")
            return 0
