#!/usr/bin/env python3
"""
Менеджер очистки временных файлов
"""

import logging
import shutil
from pathlib import Path
from typing import List, Dict, Optional
from datetime import datetime, timedelta
import json


class CleanupManager:
    """Менеджер очистки временных файлов"""
    
    def __init__(self, temp_dirs: List[Path] = None):
        self.logger = logging.getLogger(__name__)
        self.temp_dirs = temp_dirs or [
            Path(".temp"),
            Path(".cache"),
            Path("temp"),
            Path("cache")
        ]
    
    def cleanup_temp_files(self, max_age_hours: int = 24) -> Dict[str, int]:
        """Очищает временные файлы старше указанного возраста"""
        try:
            stats = {
                'files_removed': 0,
                'dirs_removed': 0,
                'bytes_freed': 0,
                'errors': 0
            }
            
            cutoff_time = datetime.now() - timedelta(hours=max_age_hours)
            
            for temp_dir in self.temp_dirs:
                if not temp_dir.exists():
                    continue
                
                self.logger.info(f"Очистка временной директории: {temp_dir}")
                
                for item in temp_dir.rglob("*"):
                    try:
                        if item.is_file():
                            # Проверяем время последнего изменения
                            mtime = datetime.fromtimestamp(item.stat().st_mtime)
                            
                            if mtime < cutoff_time:
                                file_size = item.stat().st_size
                                item.unlink()
                                stats['files_removed'] += 1
                                stats['bytes_freed'] += file_size
                                self.logger.debug(f"Удален файл: {item}")
                        
                        elif item.is_dir():
                            # Удаляем пустые директории
                            try:
                                if not any(item.iterdir()):
                                    item.rmdir()
                                    stats['dirs_removed'] += 1
                                    self.logger.debug(f"Удалена пустая директория: {item}")
                            except OSError:
                                # Директория не пустая, пропускаем
                                pass
                    
                    except Exception as e:
                        self.logger.warning(f"Ошибка при удалении {item}: {e}")
                        stats['errors'] += 1
            
            self.logger.info(f"Очистка завершена: {stats['files_removed']} файлов, {stats['dirs_removed']} директорий, {stats['bytes_freed']} байт освобождено")
            return stats
            
        except Exception as e:
            self.logger.error(f"Ошибка при очистке временных файлов: {e}")
            return {'files_removed': 0, 'dirs_removed': 0, 'bytes_freed': 0, 'errors': 1}
    
    def cleanup_old_scan_results(self, max_age_days: int = 7) -> Dict[str, int]:
        """Очищает старые результаты сканирования"""
        try:
            stats = {
                'scan_dirs_removed': 0,
                'bytes_freed': 0,
                'errors': 0
            }
            
            cutoff_time = datetime.now() - timedelta(days=max_age_days)
            
            # Ищем директории с результатами сканирования
            for scan_dir in Path(".").glob("scan-*"):
                if not scan_dir.is_dir():
                    continue
                
                try:
                    # Проверяем время создания директории
                    mtime = datetime.fromtimestamp(scan_dir.stat().st_mtime)
                    
                    if mtime < cutoff_time:
                        # Подсчитываем размер перед удалением
                        total_size = sum(f.stat().st_size for f in scan_dir.rglob("*") if f.is_file())
                        
                        # Удаляем директорию
                        shutil.rmtree(scan_dir)
                        
                        stats['scan_dirs_removed'] += 1
                        stats['bytes_freed'] += total_size
                        
                        self.logger.info(f"Удалена старая директория сканирования: {scan_dir.name} ({total_size} байт)")
                
                except Exception as e:
                    self.logger.warning(f"Ошибка при удалении {scan_dir}: {e}")
                    stats['errors'] += 1
            
            self.logger.info(f"Очистка старых результатов завершена: {stats['scan_dirs_removed']} директорий, {stats['bytes_freed']} байт освобождено")
            return stats
            
        except Exception as e:
            self.logger.error(f"Ошибка при очистке старых результатов: {e}")
            return {'scan_dirs_removed': 0, 'bytes_freed': 0, 'errors': 1}
    
    def cleanup_log_files(self, max_age_days: int = 30) -> Dict[str, int]:
        """Очищает старые лог-файлы"""
        try:
            stats = {
                'log_files_removed': 0,
                'bytes_freed': 0,
                'errors': 0
            }
            
            cutoff_time = datetime.now() - timedelta(days=max_age_days)
            
            # Ищем лог-файлы
            log_patterns = ["*.log", "*.log.*", "scanner.log*"]
            
            for pattern in log_patterns:
                for log_file in Path(".").glob(pattern):
                    if not log_file.is_file():
                        continue
                    
                    try:
                        mtime = datetime.fromtimestamp(log_file.stat().st_mtime)
                        
                        if mtime < cutoff_time:
                            file_size = log_file.stat().st_size
                            log_file.unlink()
                            
                            stats['log_files_removed'] += 1
                            stats['bytes_freed'] += file_size
                            
                            self.logger.info(f"Удален старый лог-файл: {log_file.name} ({file_size} байт)")
                    
                    except Exception as e:
                        self.logger.warning(f"Ошибка при удалении {log_file}: {e}")
                        stats['errors'] += 1
            
            self.logger.info(f"Очистка лог-файлов завершена: {stats['log_files_removed']} файлов, {stats['bytes_freed']} байт освобождено")
            return stats
            
        except Exception as e:
            self.logger.error(f"Ошибка при очистке лог-файлов: {e}")
            return {'log_files_removed': 0, 'bytes_freed': 0, 'errors': 1}
    
    def cleanup_compressed_files(self, max_age_days: int = 14) -> Dict[str, int]:
        """Очищает старые сжатые файлы"""
        try:
            stats = {
                'compressed_files_removed': 0,
                'bytes_freed': 0,
                'errors': 0
            }
            
            cutoff_time = datetime.now() - timedelta(days=max_age_days)
            
            # Ищем сжатые файлы
            compressed_patterns = ["*.zip", "*.tar.gz", "*.gz"]
            
            for pattern in compressed_patterns:
                for compressed_file in Path(".").glob(pattern):
                    if not compressed_file.is_file():
                        continue
                    
                    try:
                        mtime = datetime.fromtimestamp(compressed_file.stat().st_mtime)
                        
                        if mtime < cutoff_time:
                            file_size = compressed_file.stat().st_size
                            compressed_file.unlink()
                            
                            stats['compressed_files_removed'] += 1
                            stats['bytes_freed'] += file_size
                            
                            self.logger.info(f"Удален старый сжатый файл: {compressed_file.name} ({file_size} байт)")
                    
                    except Exception as e:
                        self.logger.warning(f"Ошибка при удалении {compressed_file}: {e}")
                        stats['errors'] += 1
            
            self.logger.info(f"Очистка сжатых файлов завершена: {stats['compressed_files_removed']} файлов, {stats['bytes_freed']} байт освобождено")
            return stats
            
        except Exception as e:
            self.logger.error(f"Ошибка при очистке сжатых файлов: {e}")
            return {'compressed_files_removed': 0, 'bytes_freed': 0, 'errors': 1}
    
    def full_cleanup(self) -> Dict[str, int]:
        """Выполняет полную очистку всех временных файлов"""
        try:
            total_stats = {
                'total_files_removed': 0,
                'total_dirs_removed': 0,
                'total_bytes_freed': 0,
                'total_errors': 0
            }
            
            self.logger.info("Начинаем полную очистку временных файлов")
            
            # Очищаем временные файлы
            temp_stats = self.cleanup_temp_files()
            total_stats['total_files_removed'] += temp_stats['files_removed']
            total_stats['total_dirs_removed'] += temp_stats['dirs_removed']
            total_stats['total_bytes_freed'] += temp_stats['bytes_freed']
            total_stats['total_errors'] += temp_stats['errors']
            
            # Очищаем старые результаты сканирования
            scan_stats = self.cleanup_old_scan_results()
            total_stats['total_files_removed'] += scan_stats['scan_dirs_removed']
            total_stats['total_bytes_freed'] += scan_stats['bytes_freed']
            total_stats['total_errors'] += scan_stats['errors']
            
            # Очищаем лог-файлы
            log_stats = self.cleanup_log_files()
            total_stats['total_files_removed'] += log_stats['log_files_removed']
            total_stats['total_bytes_freed'] += log_stats['bytes_freed']
            total_stats['total_errors'] += log_stats['errors']
            
            # Очищаем сжатые файлы
            compressed_stats = self.cleanup_compressed_files()
            total_stats['total_files_removed'] += compressed_stats['compressed_files_removed']
            total_stats['total_bytes_freed'] += compressed_stats['bytes_freed']
            total_stats['total_errors'] += compressed_stats['errors']
            
            # Конвертируем байты в МБ для удобства
            total_mb_freed = total_stats['total_bytes_freed'] / (1024 * 1024)
            
            self.logger.info(f"Полная очистка завершена:")
            self.logger.info(f"  • Удалено файлов: {total_stats['total_files_removed']}")
            self.logger.info(f"  • Удалено директорий: {total_stats['total_dirs_removed']}")
            self.logger.info(f"  • Освобождено места: {total_mb_freed:.2f} МБ")
            self.logger.info(f"  • Ошибок: {total_stats['total_errors']}")
            
            return total_stats
            
        except Exception as e:
            self.logger.error(f"Ошибка при полной очистке: {e}")
            return {'total_files_removed': 0, 'total_dirs_removed': 0, 'total_bytes_freed': 0, 'total_errors': 1}
    
    def get_cleanup_stats(self) -> Dict[str, any]:
        """Возвращает статистику использования места"""
        try:
            stats = {
                'temp_dirs': {},
                'scan_dirs': {},
                'log_files': {},
                'compressed_files': {},
                'total_usage_mb': 0
            }
            
            # Статистика временных директорий
            for temp_dir in self.temp_dirs:
                if temp_dir.exists():
                    total_size = sum(f.stat().st_size for f in temp_dir.rglob("*") if f.is_file())
                    file_count = len(list(temp_dir.rglob("*")))
                    stats['temp_dirs'][str(temp_dir)] = {
                        'size_mb': round(total_size / (1024 * 1024), 2),
                        'file_count': file_count
                    }
                    stats['total_usage_mb'] += total_size / (1024 * 1024)
            
            # Статистика директорий сканирования
            scan_dirs = list(Path(".").glob("scan-*"))
            for scan_dir in scan_dirs:
                if scan_dir.is_dir():
                    total_size = sum(f.stat().st_size for f in scan_dir.rglob("*") if f.is_file())
                    file_count = len(list(scan_dir.rglob("*")))
                    stats['scan_dirs'][scan_dir.name] = {
                        'size_mb': round(total_size / (1024 * 1024), 2),
                        'file_count': file_count
                    }
                    stats['total_usage_mb'] += total_size / (1024 * 1024)
            
            # Статистика лог-файлов
            log_files = list(Path(".").glob("*.log*"))
            total_log_size = sum(f.stat().st_size for f in log_files if f.is_file())
            stats['log_files'] = {
                'count': len(log_files),
                'size_mb': round(total_log_size / (1024 * 1024), 2)
            }
            stats['total_usage_mb'] += total_log_size / (1024 * 1024)
            
            # Статистика сжатых файлов
            compressed_files = list(Path(".").glob("*.zip")) + list(Path(".").glob("*.tar.gz")) + list(Path(".").glob("*.gz"))
            total_compressed_size = sum(f.stat().st_size for f in compressed_files if f.is_file())
            stats['compressed_files'] = {
                'count': len(compressed_files),
                'size_mb': round(total_compressed_size / (1024 * 1024), 2)
            }
            stats['total_usage_mb'] += total_compressed_size / (1024 * 1024)
            
            stats['total_usage_mb'] = round(stats['total_usage_mb'], 2)
            
            return stats
            
        except Exception as e:
            self.logger.error(f"Ошибка при получении статистики очистки: {e}")
            return {}
