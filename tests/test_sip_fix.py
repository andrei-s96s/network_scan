#!/usr/bin/env python3
"""
Тест исправления SIP порта
"""
import socket
import time

def test_sip_probe():
    """Тестирует SIP probe на localhost"""
    test_ports = [5060, 5061, 554]
    
    for port in test_ports:
        print(f"Тестируем порт {port}...")
        try:
            with socket.create_connection(('127.0.0.1', port), timeout=2) as s:
                print(f"  Порт {port} открыт")
                
                # Отправляем probe
                if port in (5060, 5061):
                    probe = b'OPTIONS sip:test@test.com SIP/2.0\r\nVia: SIP/2.0/UDP test.com\r\nFrom: <sip:test@test.com>\r\nTo: <sip:test@test.com>\r\nCall-ID: test@test.com\r\nCSeq: 1 OPTIONS\r\n\r\n'
                elif port == 554:
                    probe = b'OPTIONS rtsp://test.com/test RTSP/1.0\r\nCSeq: 1\r\n\r\n'
                else:
                    probe = b''
                
                if probe:
                    s.send(probe)
                    s.settimeout(3)
                    try:
                        response = s.recv(256)
                        if response:
                            print(f"  Получен ответ: {response[:100]}")
                        else:
                            print(f"  Нет ответа на probe")
                    except socket.timeout:
                        print(f"  Таймаут при получении ответа")
                
        except (socket.timeout, ConnectionRefusedError):
            print(f"  Порт {port} закрыт (ожидаемо)")
        except Exception as e:
            print(f"  Ошибка: {e}")

if __name__ == "__main__":
    test_sip_probe()
