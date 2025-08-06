#!/usr/bin/env python3
"""
Менеджер повторных попыток для обработки временных ошибок
"""

import asyncio
import logging
import time
from typing import Callable, Any, Optional, Type, Union, List
from functools import wraps
from dataclasses import dataclass
from datetime import datetime, timedelta


@dataclass
class RetryConfig:
    """Конфигурация повторных попыток"""
    
    max_attempts: int = 3
    base_delay: float = 1.0  # секунды
    max_delay: float = 60.0  # секунды
    exponential_backoff: bool = True
    jitter: bool = True  # Случайная задержка для избежания thundering herd
    retry_exceptions: tuple = (Exception,)  # Исключения для повтора
    success_exceptions: tuple = ()  # Исключения, которые считаются успехом
    timeout: Optional[float] = None  # Общий таймаут для всех попыток


class RetryManager:
    """Менеджер повторных попыток"""
    
    def __init__(self, config: RetryConfig = None):
        self.config = config or RetryConfig()
        self.logger = logging.getLogger(__name__)
    
    def _calculate_delay(self, attempt: int) -> float:
        """Вычисляет задержку для попытки"""
        if self.config.exponential_backoff:
            delay = self.config.base_delay * (2 ** (attempt - 1))
        else:
            delay = self.config.base_delay
        
        # Ограничиваем максимальной задержкой
        delay = min(delay, self.config.max_delay)
        
        # Добавляем jitter если включен
        if self.config.jitter:
            import random
            jitter = random.uniform(0, delay * 0.1)  # 10% jitter
            delay += jitter
        
        return delay
    
    def _should_retry(self, exception: Exception) -> bool:
        """Определяет, нужно ли повторить попытку"""
        # Проверяем, является ли исключение успешным
        if isinstance(exception, self.config.success_exceptions):
            return False
        
        # Проверяем, является ли исключение повторимым
        return isinstance(exception, self.config.retry_exceptions)
    
    async def retry_async(
        self, 
        func: Callable, 
        *args, 
        **kwargs
    ) -> Any:
        """Выполняет асинхронную функцию с повторными попытками"""
        last_exception = None
        start_time = time.time()
        
        for attempt in range(1, self.config.max_attempts + 1):
            try:
                # Проверяем общий таймаут
                if self.config.timeout:
                    elapsed = time.time() - start_time
                    if elapsed >= self.config.timeout:
                        raise TimeoutError(f"Превышен общий таймаут {self.config.timeout}с")
                
                self.logger.debug(f"Попытка {attempt}/{self.config.max_attempts}")
                
                if asyncio.iscoroutinefunction(func):
                    result = await func(*args, **kwargs)
                else:
                    # Запускаем синхронную функцию в executor
                    loop = asyncio.get_event_loop()
                    result = await loop.run_in_executor(None, func, *args, **kwargs)
                
                # Успешное выполнение
                if attempt > 1:
                    self.logger.info(f"Функция выполнена успешно после {attempt} попыток")
                return result
                
            except Exception as e:
                last_exception = e
                
                if not self._should_retry(e):
                    self.logger.debug(f"Исключение не подлежит повтори: {type(e).__name__}: {e}")
                    raise
                
                if attempt < self.config.max_attempts:
                    delay = self._calculate_delay(attempt)
                    self.logger.warning(
                        f"Попытка {attempt} не удалась ({type(e).__name__}: {e}), "
                        f"повтор через {delay:.2f}с"
                    )
                    await asyncio.sleep(delay)
                else:
                    self.logger.error(
                        f"Все {self.config.max_attempts} попыток не удались. "
                        f"Последняя ошибка: {type(e).__name__}: {e}"
                    )
        
        # Все попытки исчерпаны
        raise last_exception
    
    def retry_sync(
        self, 
        func: Callable, 
        *args, 
        **kwargs
    ) -> Any:
        """Выполняет синхронную функцию с повторными попытками"""
        last_exception = None
        start_time = time.time()
        
        for attempt in range(1, self.config.max_attempts + 1):
            try:
                # Проверяем общий таймаут
                if self.config.timeout:
                    elapsed = time.time() - start_time
                    if elapsed >= self.config.timeout:
                        raise TimeoutError(f"Превышен общий таймаут {self.config.timeout}с")
                
                self.logger.debug(f"Попытка {attempt}/{self.config.max_attempts}")
                result = func(*args, **kwargs)
                
                # Успешное выполнение
                if attempt > 1:
                    self.logger.info(f"Функция выполнена успешно после {attempt} попыток")
                return result
                
            except Exception as e:
                last_exception = e
                
                if not self._should_retry(e):
                    self.logger.debug(f"Исключение не подлежит повтори: {type(e).__name__}: {e}")
                    raise
                
                if attempt < self.config.max_attempts:
                    delay = self._calculate_delay(attempt)
                    self.logger.warning(
                        f"Попытка {attempt} не удалась ({type(e).__name__}: {e}), "
                        f"повтор через {delay:.2f}с"
                    )
                    time.sleep(delay)
                else:
                    self.logger.error(
                        f"Все {self.config.max_attempts} попыток не удались. "
                        f"Последняя ошибка: {type(e).__name__}: {e}"
                    )
        
        # Все попытки исчерпаны
        raise last_exception


def retry_decorator(
    max_attempts: int = 3,
    base_delay: float = 1.0,
    max_delay: float = 60.0,
    exponential_backoff: bool = True,
    jitter: bool = True,
    retry_exceptions: tuple = (Exception,),
    success_exceptions: tuple = (),
    timeout: Optional[float] = None
):
    """Декоратор для автоматических повторных попыток"""
    def decorator(func: Callable) -> Callable:
        config = RetryConfig(
            max_attempts=max_attempts,
            base_delay=base_delay,
            max_delay=max_delay,
            exponential_backoff=exponential_backoff,
            jitter=jitter,
            retry_exceptions=retry_exceptions,
            success_exceptions=success_exceptions,
            timeout=timeout
        )
        
        retry_mgr = RetryManager(config)
        
        @wraps(func)
        def sync_wrapper(*args, **kwargs):
            return retry_mgr.retry_sync(func, *args, **kwargs)
        
        @wraps(func)
        async def async_wrapper(*args, **kwargs):
            return await retry_mgr.retry_async(func, *args, **kwargs)
        
        # Возвращаем соответствующий wrapper
        if asyncio.iscoroutinefunction(func):
            return async_wrapper
        else:
            return sync_wrapper
    
    return decorator


# Предустановленные конфигурации для разных типов операций
class RetryConfigs:
    """Предустановленные конфигурации retry"""
    
    @staticmethod
    def network_scan() -> RetryConfig:
        """Конфигурация для сетевого сканирования"""
        return RetryConfig(
            max_attempts=3,
            base_delay=2.0,
            max_delay=30.0,
            exponential_backoff=True,
            jitter=True,
            retry_exceptions=(ConnectionError, TimeoutError, OSError),
            timeout=60.0
        )
    
    @staticmethod
    def web_screenshot() -> RetryConfig:
        """Конфигурация для веб-скриншотов"""
        return RetryConfig(
            max_attempts=2,
            base_delay=5.0,
            max_delay=20.0,
            exponential_backoff=True,
            jitter=False,
            retry_exceptions=(TimeoutError, ConnectionError),
            timeout=30.0
        )
    
    @staticmethod
    def file_operation() -> RetryConfig:
        """Конфигурация для файловых операций"""
        return RetryConfig(
            max_attempts=5,
            base_delay=0.5,
            max_delay=10.0,
            exponential_backoff=True,
            jitter=True,
            retry_exceptions=(OSError, PermissionError),
            timeout=30.0
        )
    
    @staticmethod
    def database_operation() -> RetryConfig:
        """Конфигурация для операций с базой данных"""
        return RetryConfig(
            max_attempts=3,
            base_delay=1.0,
            max_delay=15.0,
            exponential_backoff=True,
            jitter=True,
            retry_exceptions=(ConnectionError, TimeoutError),
            timeout=45.0
        )


# Готовые декораторы для разных типов операций
def retry_network_scan(func: Callable) -> Callable:
    """Декоратор для сетевого сканирования"""
    return retry_decorator(
        max_attempts=3,
        base_delay=2.0,
        max_delay=30.0,
        retry_exceptions=(ConnectionError, TimeoutError, OSError),
        timeout=60.0
    )(func)


def retry_web_screenshot(func: Callable) -> Callable:
    """Декоратор для веб-скриншотов"""
    return retry_decorator(
        max_attempts=2,
        base_delay=5.0,
        max_delay=20.0,
        retry_exceptions=(TimeoutError, ConnectionError),
        timeout=30.0
    )(func)


def retry_file_operation(func: Callable) -> Callable:
    """Декоратор для файловых операций"""
    return retry_decorator(
        max_attempts=5,
        base_delay=0.5,
        max_delay=10.0,
        retry_exceptions=(OSError, PermissionError),
        timeout=30.0
    )(func)
