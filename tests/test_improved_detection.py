#!/usr/bin/env python3
"""
Тест улучшенного определения портов
"""
import socket
import time
from web import Config

def test_port_detection():
    """Тестирует улучшенное определение портов"""
    config = Config()
    test_ports = [5060, 5061, 554, 3389, 5432]
    
    print("Тестирование улучшенного определения портов...")
    print("=" * 50)
    
    for port in test_ports:
        print(f"\nПорт {port}:")
        
        # Проверяем конфигурацию
        if port in config.ports_tcp_probe:
            probe = config.ports_tcp_probe[port]
            if probe:
                print(f"  ✓ Probe настроен ({len(probe)} байт)")
                if port in (5060, 5061):
                    probe_text = probe.decode('utf-8', errors='ignore')
                    if 'SIP/2.0' in probe_text:
                        print(f"  ✓ SIP OPTIONS probe корректный")
                elif port == 554:
                    probe_text = probe.decode('utf-8', errors='ignore')
                    if 'RTSP/1.0' in probe_text:
                        print(f"  ✓ RTSP OPTIONS probe корректный")
                elif port == 5432:
                    print(f"  ✓ PostgreSQL startup message настроен")
                elif port == 3389:
                    print(f"  ✓ RDP port в конфигурации")
            else:
                print(f"  ⚠ Probe пустой")
        else:
            print(f"  ❌ Порт {port} не найден в конфигурации")
    
    print("\n" + "=" * 50)
    print("Тест конфигурации завершен.")
    print("Для полного тестирования запустите сканер на реальной сети.")

if __name__ == "__main__":
    test_port_detection()
