#!/usr/bin/env python3
"""
Тесты для определения IP телефонов и камер
"""
import unittest
from web import detect_os_from_banner, Config

class TestIPDevices(unittest.TestCase):
    """Тесты для функции определения IP устройств"""
    
    def test_ip_phone_detection(self):
        """Тест определения IP телефонов"""
        # SIP серверы
        self.assertEqual(detect_os_from_banner("SIP/2.0", 5060), "IP Phone")
        self.assertEqual(detect_os_from_banner("Asterisk", 5060), "IP Phone")
        self.assertEqual(detect_os_from_banner("FreePBX", 5061), "IP Phone")
        
        # Производители IP телефонов
        self.assertEqual(detect_os_from_banner("Cisco IP Phone", 10000), "IP Phone")
        self.assertEqual(detect_os_from_banner("Yealink", 5060), "IP Phone")
        self.assertEqual(detect_os_from_banner("Grandstream", 5060), "IP Phone")
        
        # Порты IP телефонов
        self.assertEqual(detect_os_from_banner("HTTP/1.1 200 OK", 10000), "IP Phone")
        self.assertEqual(detect_os_from_banner("open", 5060), "IP Phone")
        self.assertEqual(detect_os_from_banner("open", 5061), "IP Phone")
    
    def test_ip_camera_detection(self):
        """Тест определения IP камер"""
        # RTSP сервисы
        self.assertEqual(detect_os_from_banner("RTSP/1.0", 554), "IP Camera")
        self.assertEqual(detect_os_from_banner("RTSP Server", 554), "IP Camera")
        
        # Производители IP камер
        self.assertEqual(detect_os_from_banner("Dahua", 8000), "IP Camera")
        self.assertEqual(detect_os_from_banner("Hikvision", 554), "IP Camera")
        self.assertEqual(detect_os_from_banner("Axis", 8000), "IP Camera")
        self.assertEqual(detect_os_from_banner("Foscam", 554), "IP Camera")
        self.assertEqual(detect_os_from_banner("IP Camera", 8000), "IP Camera")
        
        # Порты IP камер
        self.assertEqual(detect_os_from_banner("HTTP/1.1 200 OK", 8000), "IP Camera")
        self.assertEqual(detect_os_from_banner("open", 554), "IP Camera")
        self.assertEqual(detect_os_from_banner("open", 37777), "IP Camera")
        self.assertEqual(detect_os_from_banner("open", 37778), "IP Camera")
    
    def test_case_insensitive_detection(self):
        """Тест регистронезависимого определения"""
        self.assertEqual(detect_os_from_banner("sip/2.0", 5060), "IP Phone")
        self.assertEqual(detect_os_from_banner("rtsp/1.0", 554), "IP Camera")
        self.assertEqual(detect_os_from_banner("DAHUA", 8000), "IP Camera")
        self.assertEqual(detect_os_from_banner("cisco ip phone", 10000), "IP Phone")
    
    def test_no_device_detection(self):
        """Тест отсутствия определения для обычных сервисов"""
        self.assertIsNone(detect_os_from_banner("HTTP/1.1 200 OK", 80))
        self.assertIsNone(detect_os_from_banner("SSH-2.0-OpenSSH", 22))
        self.assertIsNone(detect_os_from_banner("Unknown Service", 8080))
    
    def test_mixed_keywords(self):
        """Тест смешанных ключевых слов"""
        self.assertEqual(detect_os_from_banner("SIP Camera", 554), "IP Camera")
        self.assertEqual(detect_os_from_banner("IP Phone SIP", 5060), "IP Phone")
        self.assertEqual(detect_os_from_banner("Dahua IP Camera", 8000), "IP Camera")
    
    def test_sip_probe_configuration(self):
        """Тест конфигурации SIP probes"""
        config = Config()
        
        # Проверяем, что SIP порты имеют правильные probes
        self.assertIn(5060, config.ports_tcp_probe)
        self.assertIn(5061, config.ports_tcp_probe)
        
        # Проверяем, что probes не пустые
        self.assertNotEqual(config.ports_tcp_probe[5060], b'')
        self.assertNotEqual(config.ports_tcp_probe[5061], b'')
        
        # Проверяем, что это SIP OPTIONS запросы
        sip_5060 = config.ports_tcp_probe[5060].decode('utf-8', errors='ignore')
        sip_5061 = config.ports_tcp_probe[5061].decode('utf-8', errors='ignore')
        
        self.assertIn("OPTIONS", sip_5060)
        self.assertIn("SIP/2.0", sip_5060)
        self.assertIn("OPTIONS", sip_5061)
        self.assertIn("SIP/2.0", sip_5061)
    
    def test_rtsp_probe_configuration(self):
        """Тест конфигурации RTSP probes"""
        config = Config()
        
        # Проверяем, что RTSP порт имеет правильный probe
        self.assertIn(554, config.ports_tcp_probe)
        
        # Проверяем, что probe не пустой
        self.assertNotEqual(config.ports_tcp_probe[554], b'')
        
        # Проверяем, что это RTSP OPTIONS запрос
        rtsp_probe = config.ports_tcp_probe[554].decode('utf-8', errors='ignore')
        self.assertIn("OPTIONS", rtsp_probe)
        self.assertIn("RTSP/1.0", rtsp_probe)
    
    def test_improved_port_detection(self):
        """Тест улучшенного определения портов"""
        config = Config()
        
        # Проверяем, что PostgreSQL порт имеет правильный probe
        self.assertIn(5432, config.ports_tcp_probe)
        self.assertNotEqual(config.ports_tcp_probe[5432], b'')
        
        # Проверяем, что RDP порт имеет правильный probe (хотя он обрабатывается отдельно)
        self.assertIn(3389, config.ports_tcp_probe)
        
        # Проверяем, что SIP и RTSP probes содержат правильные протоколы
        sip_probe = config.ports_tcp_probe[5060].decode('utf-8', errors='ignore')
        rtsp_probe = config.ports_tcp_probe[554].decode('utf-8', errors='ignore')
        
        self.assertIn("SIP/2.0", sip_probe)
        self.assertIn("RTSP/1.0", rtsp_probe)
    
    def test_strict_validation(self):
        """Тест строгой валидации для специальных портов"""
        from web import probe_port
        config = Config()
        
        # Тестируем, что невалидные ответы возвращают None
        # Это симулирует ситуацию, когда порт отвечает, но не как ожидаемый сервис
        with unittest.mock.patch('socket.create_connection') as mock_conn:
            mock_socket = unittest.mock.Mock()
            mock_socket.recv.return_value = b'HTTP/1.1 200 OK\r\n'  # Не SIP ответ
            mock_conn.return_value.__enter__.return_value = mock_socket
            
            result = probe_port("192.168.1.1", 5060, config)
            self.assertIsNone(result)  # Должен вернуть None для невалидного SIP ответа

if __name__ == "__main__":
    unittest.main()
