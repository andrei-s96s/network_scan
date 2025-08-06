#!/usr/bin/env python3
"""
Менеджер кэширования результатов сканирования
"""

import json
import hashlib
import logging
from pathlib import Path
from typing import Dict, List, Optional, Any
from datetime import datetime, timedelta
import pickle
import gzip
from dataclasses import dataclass, asdict

from network_scanner import ScanResult


@dataclass
class CacheEntry:
    """Запись в кэше"""
    
    network: str
    scan_results: List[ScanResult]
    scan_time: datetime
    cache_duration: timedelta = timedelta(hours=24)  # По умолчанию 24 часа
    
    def is_expired(self) -> bool:
        """Проверяет, истек ли срок действия кэша"""
        return datetime.now() > self.scan_time + self.cache_duration
    
    def to_dict(self) -> Dict[str, Any]:
        """Конвертирует в словарь для сериализации"""
        return {
            'network': self.network,
            'scan_results': [asdict(result) for result in self.scan_results],
            'scan_time': self.scan_time.isoformat(),
            'cache_duration': self.cache_duration.total_seconds()
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'CacheEntry':
        """Создает из словаря"""
        # Восстанавливаем ScanResult из словаря
        scan_results = []
        for result_data in data['scan_results']:
            scan_result = ScanResult(
                ip=result_data['ip'],
                open_ports=result_data['open_ports'],
                detected_os=result_data.get('detected_os'),
                screenshots_count=result_data.get('screenshots_count', 0),
                scan_time=result_data.get('scan_time', 0.0)
            )
            scan_results.append(scan_result)
        
        return cls(
            network=data['network'],
            scan_results=scan_results,
            scan_time=datetime.fromisoformat(data['scan_time']),
            cache_duration=timedelta(seconds=data['cache_duration'])
        )


class CacheManager:
    """Менеджер кэширования результатов сканирования"""
    
    def __init__(self, cache_dir: Path = Path(".cache")):
        self.cache_dir = cache_dir
        self.logger = logging.getLogger(__name__)
        self.cache_dir.mkdir(exist_ok=True)
        
    def _get_cache_key(self, network: str, **kwargs) -> str:
        """Генерирует ключ кэша на основе параметров сканирования"""
        # Создаем строку с параметрами
        params = {
            'network': network,
            **kwargs
        }
        params_str = json.dumps(params, sort_keys=True)
        
        # Создаем хеш
        return hashlib.md5(params_str.encode()).hexdigest()
    
    def _get_cache_path(self, cache_key: str) -> Path:
        """Возвращает путь к файлу кэша"""
        return self.cache_dir / f"{cache_key}.cache.gz"
    
    def get(self, network: str, **kwargs) -> Optional[List[ScanResult]]:
        """Получает результаты из кэша"""
        try:
            cache_key = self._get_cache_key(network, **kwargs)
            cache_path = self._get_cache_path(cache_key)
            
            if not cache_path.exists():
                self.logger.debug(f"Кэш не найден для сети {network}")
                return None
            
            # Читаем сжатый файл
            with gzip.open(cache_path, 'rb') as f:
                data = pickle.load(f)
            
            entry = CacheEntry.from_dict(data)
            
            if entry.is_expired():
                self.logger.debug(f"Кэш истек для сети {network}")
                cache_path.unlink()  # Удаляем истекший кэш
                return None
            
            self.logger.info(f"Результаты загружены из кэша для сети {network}")
            return entry.scan_results
            
        except Exception as e:
            self.logger.warning(f"Ошибка при чтении кэша: {e}")
            return None
    
    def set(self, network: str, scan_results: List[ScanResult], 
            cache_duration: timedelta = timedelta(hours=24), **kwargs) -> bool:
        """Сохраняет результаты в кэш"""
        try:
            cache_key = self._get_cache_key(network, **kwargs)
            cache_path = self._get_cache_path(cache_key)
            
            entry = CacheEntry(
                network=network,
                scan_results=scan_results,
                scan_time=datetime.now(),
                cache_duration=cache_duration
            )
            
            # Сохраняем сжатый файл
            with gzip.open(cache_path, 'wb') as f:
                pickle.dump(entry.to_dict(), f)
            
            self.logger.info(f"Результаты сохранены в кэш для сети {network}")
            return True
            
        except Exception as e:
            self.logger.error(f"Ошибка при сохранении кэша: {e}")
            return False
    
    def clear(self, network: Optional[str] = None) -> int:
        """Очищает кэш"""
        try:
            if network:
                # Очищаем кэш для конкретной сети
                cache_key = self._get_cache_key(network)
                cache_path = self._get_cache_path(cache_key)
                if cache_path.exists():
                    cache_path.unlink()
                    self.logger.info(f"Кэш очищен для сети {network}")
                    return 1
                return 0
            else:
                # Очищаем весь кэш
                count = 0
                for cache_file in self.cache_dir.glob("*.cache.gz"):
                    cache_file.unlink()
                    count += 1
                
                self.logger.info(f"Очищено {count} файлов кэша")
                return count
                
        except Exception as e:
            self.logger.error(f"Ошибка при очистке кэша: {e}")
            return 0
    
    def cleanup_expired(self) -> int:
        """Удаляет истекшие записи кэша"""
        try:
            count = 0
            for cache_file in self.cache_dir.glob("*.cache.gz"):
                try:
                    with gzip.open(cache_file, 'rb') as f:
                        data = pickle.load(f)
                    
                    entry = CacheEntry.from_dict(data)
                    if entry.is_expired():
                        cache_file.unlink()
                        count += 1
                        
                except Exception as e:
                    self.logger.warning(f"Ошибка при проверке файла кэша {cache_file}: {e}")
                    # Удаляем поврежденный файл
                    cache_file.unlink()
                    count += 1
            
            if count > 0:
                self.logger.info(f"Удалено {count} истекших записей кэша")
            
            return count
            
        except Exception as e:
            self.logger.error(f"Ошибка при очистке истекшего кэша: {e}")
            return 0
    
    def get_stats(self) -> Dict[str, Any]:
        """Возвращает статистику кэша"""
        try:
            total_files = 0
            total_size = 0
            expired_files = 0
            
            for cache_file in self.cache_dir.glob("*.cache.gz"):
                total_files += 1
                total_size += cache_file.stat().st_size
                
                try:
                    with gzip.open(cache_file, 'rb') as f:
                        data = pickle.load(f)
                    
                    entry = CacheEntry.from_dict(data)
                    if entry.is_expired():
                        expired_files += 1
                        
                except Exception:
                    expired_files += 1
            
            return {
                'total_files': total_files,
                'total_size_mb': round(total_size / (1024 * 1024), 2),
                'expired_files': expired_files,
                'valid_files': total_files - expired_files
            }
            
        except Exception as e:
            self.logger.error(f"Ошибка при получении статистики кэша: {e}")
            return {}
