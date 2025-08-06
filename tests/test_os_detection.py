#!/usr/bin/env python3
"""
Тесты для определения операционной системы
"""

import unittest
from web import detect_os_from_banner


class TestOSDetection(unittest.TestCase):
    """Тесты для функции определения ОС"""
    
    def test_windows_detection(self):
        """Тест определения Windows"""
        # IIS
        self.assertEqual(detect_os_from_banner("Microsoft-IIS/10.0", 80), "Windows")
        # Exchange
        self.assertEqual(detect_os_from_banner("Microsoft Exchange", 443), "Windows")
        # SMB
        self.assertEqual(detect_os_from_banner("SMB", 445), "Windows")
        # RDP
        self.assertEqual(detect_os_from_banner("RDP", 3389), "Windows")
        # WinRM
        self.assertEqual(detect_os_from_banner("WinRM", 5985), "Windows")
    
    def test_linux_detection(self):
        """Тест определения Linux"""
        # Ubuntu SSH
        self.assertEqual(detect_os_from_banner("SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.2", 22), "Linux")
        # CentOS Apache
        self.assertEqual(detect_os_from_banner("Apache/2.4.6 (CentOS)", 80), "Linux")
        # Nginx
        self.assertEqual(detect_os_from_banner("nginx/1.18.0", 80), "Linux")
        # Debian
        self.assertEqual(detect_os_from_banner("SSH-2.0-OpenSSH_7.9p1 Debian-10+deb10u2", 22), "Linux")
    
    def test_unix_detection(self):
        """Тест определения Unix"""
        # FreeBSD
        self.assertEqual(detect_os_from_banner("SSH-2.0-OpenSSH_8.0 FreeBSD-20200214", 22), "Unix")
        # OpenBSD
        self.assertEqual(detect_os_from_banner("SSH-2.0-OpenSSH_8.1 OpenBSD", 22), "Unix")
        # Solaris
        self.assertEqual(detect_os_from_banner("SSH-2.0-OpenSSH_7.1 Sun_SSH", 22), "Unix")
    
    def test_no_detection(self):
        """Тест отсутствия определения ОС"""
        # Неизвестный баннер
        self.assertIsNone(detect_os_from_banner("Unknown Service", 8080))
        # Пустой баннер
        self.assertIsNone(detect_os_from_banner("open", 80))
        # Без баннера
        self.assertIsNone(detect_os_from_banner("", 80))
    
    def test_case_insensitive(self):
        """Тест нечувствительности к регистру"""
        self.assertEqual(detect_os_from_banner("MICROSOFT-IIS/10.0", 80), "Windows")
        self.assertEqual(detect_os_from_banner("ssh-2.0-openssh_8.2p1 ubuntu", 22), "Linux")
        self.assertEqual(detect_os_from_banner("NGINX/1.18.0", 80), "Linux")


if __name__ == "__main__":
    unittest.main()
