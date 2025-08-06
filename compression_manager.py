#!/usr/bin/env python3
"""
Менеджер сжатия данных для отчетов и скриншотов
"""

import gzip
import zipfile
import tarfile
import logging
from pathlib import Path
from typing import Dict, List, Optional, Union
from datetime import datetime
import json
import shutil


class CompressionManager:
    """Менеджер сжатия данных"""
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)
    
    def compress_file(self, file_path: Path, compression_type: str = "gzip") -> Optional[Path]:
        """Сжимает один файл"""
        try:
            if not file_path.exists():
                self.logger.warning(f"Файл не найден: {file_path}")
                return None
            
            if compression_type == "gzip":
                compressed_path = file_path.with_suffix(file_path.suffix + ".gz")
                with open(file_path, 'rb') as f_in:
                    with gzip.open(compressed_path, 'wb') as f_out:
                        shutil.copyfileobj(f_in, f_out)
                
            elif compression_type == "zip":
                compressed_path = file_path.with_suffix(file_path.suffix + ".zip")
                with zipfile.ZipFile(compressed_path, 'w', zipfile.ZIP_DEFLATED) as zipf:
                    zipf.write(file_path, file_path.name)
            
            else:
                self.logger.error(f"Неизвестный тип сжатия: {compression_type}")
                return None
            
            # Получаем размеры файлов
            original_size = file_path.stat().st_size
            compressed_size = compressed_path.stat().st_size
            compression_ratio = (1 - compressed_size / original_size) * 100
            
            self.logger.info(f"Файл сжат: {file_path.name} -> {compressed_path.name}")
            self.logger.info(f"Размер: {original_size} -> {compressed_size} байт ({compression_ratio:.1f}% сжатие)")
            
            return compressed_path
            
        except Exception as e:
            self.logger.error(f"Ошибка при сжатии файла {file_path}: {e}")
            return None
    
    def compress_directory(self, dir_path: Path, output_format: str = "zip") -> Optional[Path]:
        """Сжимает директорию"""
        try:
            if not dir_path.exists() or not dir_path.is_dir():
                self.logger.warning(f"Директория не найдена: {dir_path}")
                return None
            
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            
            if output_format == "zip":
                archive_path = dir_path.parent / f"{dir_path.name}_{timestamp}.zip"
                with zipfile.ZipFile(archive_path, 'w', zipfile.ZIP_DEFLATED) as zipf:
                    for file_path in dir_path.rglob("*"):
                        if file_path.is_file():
                            arcname = file_path.relative_to(dir_path)
                            zipf.write(file_path, arcname)
            
            elif output_format == "tar.gz":
                archive_path = dir_path.parent / f"{dir_path.name}_{timestamp}.tar.gz"
                with tarfile.open(archive_path, 'w:gz') as tar:
                    tar.add(dir_path, arcname=dir_path.name)
            
            else:
                self.logger.error(f"Неизвестный формат архива: {output_format}")
                return None
            
            # Получаем размеры
            original_size = sum(f.stat().st_size for f in dir_path.rglob("*") if f.is_file())
            compressed_size = archive_path.stat().st_size
            compression_ratio = (1 - compressed_size / original_size) * 100
            
            self.logger.info(f"Директория сжата: {dir_path.name} -> {archive_path.name}")
            self.logger.info(f"Размер: {original_size} -> {compressed_size} байт ({compression_ratio:.1f}% сжатие)")
            
            return archive_path
            
        except Exception as e:
            self.logger.error(f"Ошибка при сжатии директории {dir_path}: {e}")
            return None
    
    def compress_scan_results(self, scan_dir: Path, include_screenshots: bool = True) -> Optional[Path]:
        """Сжимает результаты сканирования"""
        try:
            if not scan_dir.exists():
                self.logger.warning(f"Директория сканирования не найдена: {scan_dir}")
                return None
            
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            archive_path = scan_dir.parent / f"{scan_dir.name}_{timestamp}.zip"
            
            with zipfile.ZipFile(archive_path, 'w', zipfile.ZIP_DEFLATED) as zipf:
                # Добавляем отчеты
                for report_file in scan_dir.glob("*.html"):
                    zipf.write(report_file, report_file.name)
                
                for report_file in scan_dir.glob("*.json"):
                    zipf.write(report_file, report_file.name)
                
                for report_file in scan_dir.glob("*.txt"):
                    zipf.write(report_file, report_file.name)
                
                # Добавляем скриншоты если нужно
                if include_screenshots:
                    screenshots_dir = scan_dir / "screenshots"
                    if screenshots_dir.exists():
                        for screenshot_file in screenshots_dir.rglob("*.png"):
                            arcname = f"screenshots/{screenshot_file.name}"
                            zipf.write(screenshot_file, arcname)
            
            # Получаем статистику
            total_files = len(zipf.namelist())
            original_size = sum(f.stat().st_size for f in scan_dir.rglob("*") if f.is_file())
            compressed_size = archive_path.stat().st_size
            compression_ratio = (1 - compressed_size / original_size) * 100
            
            self.logger.info(f"Результаты сканирования сжаты: {archive_path.name}")
            self.logger.info(f"Файлов: {total_files}, Размер: {original_size} -> {compressed_size} байт ({compression_ratio:.1f}% сжатие)")
            
            return archive_path
            
        except Exception as e:
            self.logger.error(f"Ошибка при сжатии результатов сканирования: {e}")
            return None
    
    def decompress_file(self, compressed_path: Path, output_dir: Path) -> Optional[Path]:
        """Распаковывает сжатый файл"""
        try:
            if not compressed_path.exists():
                self.logger.warning(f"Сжатый файл не найден: {compressed_path}")
                return None
            
            output_dir.mkdir(parents=True, exist_ok=True)
            
            if compressed_path.suffix == ".gz":
                # Распаковываем gzip
                output_path = output_dir / compressed_path.stem
                with gzip.open(compressed_path, 'rb') as f_in:
                    with open(output_path, 'wb') as f_out:
                        shutil.copyfileobj(f_in, f_out)
                
            elif compressed_path.suffix == ".zip":
                # Распаковываем zip
                with zipfile.ZipFile(compressed_path, 'r') as zipf:
                    zipf.extractall(output_dir)
                output_path = output_dir
            
            elif compressed_path.suffix == ".tar.gz":
                # Распаковываем tar.gz
                with tarfile.open(compressed_path, 'r:gz') as tar:
                    tar.extractall(output_dir)
                output_path = output_dir
            
            else:
                self.logger.error(f"Неизвестный формат сжатия: {compressed_path.suffix}")
                return None
            
            self.logger.info(f"Файл распакован: {compressed_path.name} -> {output_path}")
            return output_path
            
        except Exception as e:
            self.logger.error(f"Ошибка при распаковке файла {compressed_path}: {e}")
            return None
    
    def get_compression_stats(self, file_path: Path) -> Dict[str, Union[int, float]]:
        """Возвращает статистику сжатия для файла"""
        try:
            if not file_path.exists():
                return {}
            
            original_size = file_path.stat().st_size
            
            # Пробуем разные методы сжатия
            stats = {
                'original_size': original_size,
                'gzip_size': None,
                'zip_size': None,
                'gzip_ratio': None,
                'zip_ratio': None
            }
            
            # Gzip сжатие
            gzip_path = file_path.with_suffix(file_path.suffix + ".gz")
            with open(file_path, 'rb') as f_in:
                with gzip.open(gzip_path, 'wb') as f_out:
                    shutil.copyfileobj(f_in, f_out)
            
            gzip_size = gzip_path.stat().st_size
            stats['gzip_size'] = gzip_size
            stats['gzip_ratio'] = (1 - gzip_size / original_size) * 100
            
            # Удаляем временный файл
            gzip_path.unlink()
            
            # Zip сжатие
            zip_path = file_path.with_suffix(file_path.suffix + ".zip")
            with zipfile.ZipFile(zip_path, 'w', zipfile.ZIP_DEFLATED) as zipf:
                zipf.write(file_path, file_path.name)
            
            zip_size = zip_path.stat().st_size
            stats['zip_size'] = zip_size
            stats['zip_ratio'] = (1 - zip_size / original_size) * 100
            
            # Удаляем временный файл
            zip_path.unlink()
            
            return stats
            
        except Exception as e:
            self.logger.error(f"Ошибка при получении статистики сжатия: {e}")
            return {}
