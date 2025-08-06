#!/usr/bin/env python3
"""
Тесты для определения IP телефонов и камер
"""
import unittest
from web import detect_os_from_banner

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

if __name__ == "__main__":
    unittest.main()
