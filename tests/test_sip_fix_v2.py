#!/usr/bin/env python3
"""
Тест исправления SIP детекции
"""
import socket
import time
from web import Config, probe_port

def test_sip_detection():
    """Тестирует исправленную SIP детекцию"""
    config = Config()
    
    print("Тестирование исправленной SIP детекции...")
    print("=" * 50)
    
    # Тестируем на реальных IP из скана
    test_ips = [
        "172.30.1.115",  # Windows машина с 5060:open
        "172.30.1.85",   # Windows машина с 5060:open
        "172.30.1.10",   # Linux машина с 5060:open
        "172.30.1.172",  # Linux машина с 5060:open
        "172.30.1.2",    # Только 5060:open
        "172.30.1.3",    # Только 5060:open
    ]
    
    for ip in test_ips:
        print(f"\nТестируем {ip}:")
        try:
            result = probe_port(ip, 5060, config)
            if result == "SIP":
                print(f"  ✓ Обнаружен реальный SIP сервис")
            elif result is None:
                print(f"  ✓ Порт 5060 игнорирован (не SIP)")
            else:
                print(f"  ⚠ Неожиданный результат: {result}")
        except Exception as e:
            print(f"  ❌ Ошибка: {e}")
    
    print("\n" + "=" * 50)
    print("Тест завершен.")
    print("Если большинство портов 5060 теперь игнорируются - исправление работает!")

if __name__ == "__main__":
    test_sip_detection()
