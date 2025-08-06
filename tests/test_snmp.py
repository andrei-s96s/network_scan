#!/usr/bin/env python3
"""
Тесты для SNMP функциональности
"""

import unittest
from web import create_snmp_get_request, detect_os_from_banner


class TestSNMP(unittest.TestCase):
    """Тесты для SNMP функций"""
    
    def test_create_snmp_packet(self):
        """Тест создания SNMP пакета"""
        packet = create_snmp_get_request()
        
        # Проверяем, что пакет начинается с SEQUENCE
        self.assertTrue(packet.startswith(b'\x30'))
        
        # Проверяем, что пакет содержит версию
        self.assertIn(b'\x02\x01\x00', packet)
        
        # Проверяем, что пакет содержит community string
        self.assertIn(b'public', packet)
    
    def test_snmp_os_detection(self):
        """Тест определения ОС для SNMP"""
        # SNMP с community string public
        self.assertEqual(detect_os_from_banner("SNMP (public)", 161), "Network Device")
        
        # Обычный SNMP
        self.assertEqual(detect_os_from_banner("SNMP", 161), "Network Device")
        
        # SNMP в баннере
        self.assertEqual(detect_os_from_banner("SNMP v1", 161), "Network Device")
    
    def test_snmp_packet_structure(self):
        """Тест структуры SNMP пакета"""
        packet = create_snmp_get_request()
        
        # Проверяем минимальную длину пакета
        self.assertGreater(len(packet), 20)
        
        # Проверяем, что пакет содержит GET-REQUEST
        self.assertIn(b'\xa0', packet)
    
    def test_snmp_with_custom_community(self):
        """Тест создания SNMP пакета с кастомным community"""
        packet = create_snmp_get_request("private")
        
        # Проверяем, что пакет содержит кастомный community
        self.assertIn(b'private', packet)
    
    def test_snmp_with_custom_oid(self):
        """Тест создания SNMP пакета с кастомным OID"""
        packet = create_snmp_get_request("public", "1.3.6.1.2.1.1.2.0")
        
        # Проверяем, что пакет создан
        self.assertTrue(packet.startswith(b'\x30'))
        self.assertIn(b'public', packet)


if __name__ == "__main__":
    unittest.main()
