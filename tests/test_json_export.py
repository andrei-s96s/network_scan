#!/usr/bin/env python3
"""
Тесты для JSON экспорта
"""

import unittest
import json
import tempfile
import os
import sys

# Добавляем родительскую директорию в путь для импорта
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from web import save_result_json, save_json_report


class TestJSONExport(unittest.TestCase):
    """Тесты для JSON экспорта"""
    
    def test_save_result_json(self):
        """Тест добавления результата в JSON структуру"""
        json_data = []
        results = {80: "HTTP/1.1 200 OK", 443: "open", 22: "SSH-2.0-OpenSSH_8.2p1"}
        
        save_result_json("192.168.1.1", results, json_data, 2)
        
        self.assertEqual(len(json_data), 1)
        host_data = json_data[0]
        
        self.assertEqual(host_data["ip"], "192.168.1.1")
        self.assertEqual(host_data["screenshots"], 2)
        self.assertEqual(host_data["summary"]["total_ports"], 3)
        self.assertEqual(host_data["summary"]["web_ports"], 2)
        self.assertIn("HTTP", host_data["summary"]["services"])
        self.assertIn("HTTPS", host_data["summary"]["services"])
        self.assertIn("SSH", host_data["summary"]["services"])
        
        # Проверяем структуру портов
        self.assertIn("80", host_data["ports"])
        self.assertEqual(host_data["ports"]["80"]["service"], "HTTP")
        self.assertEqual(host_data["ports"]["80"]["response"], "HTTP/1.1 200 OK")
        self.assertEqual(host_data["ports"]["80"]["status"], "open")
    
    def test_save_json_report(self):
        """Тест сохранения полного JSON отчета"""
        json_data = [
            {
                "ip": "192.168.1.1",
                "ports": {"80": {"service": "HTTP", "response": "open", "status": "open"}},
                "screenshots": 1,
                "summary": {"total_ports": 1, "web_ports": 1, "services": ["HTTP"]}
            },
            {
                "ip": "192.168.1.2",
                "ports": {"22": {"service": "SSH", "response": "SSH-2.0-OpenSSH", "status": "open"}},
                "screenshots": 0,
                "summary": {"total_ports": 1, "web_ports": 0, "services": ["SSH"]}
            }
        ]
        
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            temp_file = f.name
        
        try:
            save_json_report(json_data, "192.168.1.0/24", temp_file)
            
            # Проверяем, что файл создан и содержит валидный JSON
            with open(temp_file, 'r', encoding='utf-8') as f:
                report = json.load(f)
            
            # Проверяем структуру отчета
            self.assertIn("scan_info", report)
            self.assertIn("hosts", report)
            self.assertIn("summary", report)
            
            self.assertEqual(report["scan_info"]["network"], "192.168.1.0/24")
            self.assertEqual(report["scan_info"]["total_hosts"], 2)
            self.assertEqual(report["scan_info"]["hosts_with_ports"], 2)
            self.assertEqual(report["scan_info"]["hosts_with_screenshots"], 1)
            
            self.assertEqual(len(report["hosts"]), 2)
            self.assertEqual(report["summary"]["total_ports_found"], 2)
            self.assertIn("HTTP", report["summary"]["services_found"])
            self.assertIn("SSH", report["summary"]["services_found"])
            self.assertEqual(report["summary"]["web_services"], 1)
            
        finally:
            os.unlink(temp_file)
    
    def test_empty_results(self):
        """Тест обработки пустых результатов"""
        json_data = []
        results = {}
        
        save_result_json("192.168.1.1", results, json_data, 0)
        
        # Пустые результаты не должны добавляться в JSON
        self.assertEqual(len(json_data), 0)
    
    def test_rdp_port_detection(self):
        """Тест обнаружения RDP порта"""
        json_data = []
        results = {3389: "RDP"}
        
        save_result_json("192.168.1.100", results, json_data, 0)
        
        self.assertEqual(len(json_data), 1)
        host_data = json_data[0]
        
        self.assertEqual(host_data["ip"], "192.168.1.100")
        self.assertIn("3389", host_data["ports"])
        self.assertEqual(host_data["ports"]["3389"]["service"], "RDP")
        self.assertEqual(host_data["ports"]["3389"]["response"], "RDP")
        self.assertEqual(host_data["ports"]["3389"]["status"], "open")
    
    def test_postgresql_port_detection(self):
        """Тест обнаружения PostgreSQL порта"""
        json_data = []
        results = {5432: "PostgreSQL"}
        
        save_result_json("192.168.1.101", results, json_data, 0)
        
        self.assertEqual(len(json_data), 1)
        host_data = json_data[0]
        
        self.assertEqual(host_data["ip"], "192.168.1.101")
        self.assertIn("5432", host_data["ports"])
        self.assertEqual(host_data["ports"]["5432"]["service"], "PostgreSQL")
        self.assertEqual(host_data["ports"]["5432"]["response"], "PostgreSQL")
        self.assertEqual(host_data["ports"]["5432"]["status"], "open")


if __name__ == '__main__':
    unittest.main()
