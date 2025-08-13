#!/usr/bin/env python3
"""
Генератор отчетов для сетевого сканера
"""

import json
import logging
from datetime import datetime
from pathlib import Path
from typing import List, Dict

from .network_scanner import ScanResult


class ReportGenerator:
    """Генератор отчетов с улучшенным форматированием"""

    def __init__(self, output_dir: Path = Path(".")):
        self.output_dir = output_dir
        self.logger = logging.getLogger(__name__)

    def _get_network_dir(self, network: str) -> Path:
        """Создает и возвращает каталог для сети"""
        network_name = network.replace('/', '_')
        network_dir = self.output_dir / f"scan-{network_name}"
        network_dir.mkdir(parents=True, exist_ok=True)
        return network_dir

    def save_text_report(self, scan_results: List[ScanResult], network: str) -> Path:
        """Сохраняет текстовый отчет"""
        network_dir = self._get_network_dir(network)
        output_file = network_dir / "report.txt"

        with open(output_file, "w", encoding="utf-8") as f:
            f.write(f"Результаты сканирования сети {network}\n")
            f.write(
                f"Время сканирования: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n"
            )
            f.write(f"Найдено хостов: {len(scan_results)}\n\n")

            for result in scan_results:
                f.write(f"{result.ip}  ")
                port_info = []
                for port, response in result.open_ports.items():
                    if response == "open":
                        port_info.append(f"{port}:open")
                    else:
                        port_info.append(f"{port}:{response}")
                f.write("  ".join(port_info) + "\n")

        self.logger.info(f"Текстовый отчет сохранен: {output_file}")
        return output_file

    def save_json_report(
        self,
        scan_results: List[ScanResult],
        network: str,
        screenshots_count: Dict[str, int] = None,
    ) -> Path:
        """Сохраняет JSON отчет с улучшенной структурой"""
        network_dir = self._get_network_dir(network)
        output_file = network_dir / "report.json"

        # Подготавливаем данные для JSON
        json_data = {
            "scan_info": {
                "network": network,
                "scan_time": datetime.now().isoformat(),
                "total_hosts": len(scan_results),
                "hosts_with_ports": len([r for r in scan_results if r.open_ports]),
                "hosts_with_screenshots": 0,  # Будет пересчитано ниже
            },
            "hosts": [],
        }

        # Обрабатываем каждый хост
        for result in scan_results:
            # Подсчитываем реальные скриншоты для этого хоста
            real_screenshots = 0
            screenshot_files = []
            
            for port in result.open_ports.keys():
                if port in {80, 443, 8080, 10000, 8000, 37777, 37778}:
                    screenshot_file = f"{result.ip}_{port}.png"
                    screenshot_path = network_dir / "screenshots" / screenshot_file
                    if screenshot_path.exists():
                        real_screenshots += 1
                        screenshot_files.append({
                            "port": port,
                            "service": self._get_service_name(port),
                            "file": screenshot_file
                        })

            host_data = {
                "ip": result.ip,
                "ports": {},
                "screenshots": real_screenshots,
                "detected_os": result.detected_os,
                "screenshot_files": screenshot_files,
                "summary": {
                    "total_ports": len(result.open_ports),
                    "web_ports": len(
                        [
                            p
                            for p in result.open_ports.keys()
                            if p in {80, 443, 8080, 10000, 8000, 37777, 37778}
                        ]
                    ),
                    "services": self._get_services_list(result.open_ports),
                },
            }

            # Добавляем информацию о портах
            for port, response in result.open_ports.items():
                service_name = self._get_service_name(port)
                host_data["ports"][str(port)] = {
                    "service": service_name,
                    "response": response,
                    "status": "open",
                }

            json_data["hosts"].append(host_data)

        # Пересчитываем общее количество хостов со скриншотами
        json_data["scan_info"]["hosts_with_screenshots"] = len([
            h for h in json_data["hosts"] if h["screenshots"] > 0
        ])

        with open(output_file, "w", encoding="utf-8") as f:
            json.dump(json_data, f, ensure_ascii=False, indent=2)

        self.logger.info(f"JSON отчет сохранен: {output_file}")
        return output_file

    def save_html_report(
        self,
        scan_results: List[ScanResult],
        network: str,
        screenshots_count: Dict[str, int] = None,
    ) -> Path:
        """Сохраняет HTML отчет с улучшенным дизайном"""
        network_dir = self._get_network_dir(network)
        output_file = network_dir / "report.html"

        # Подготавливаем данные для HTML
        json_data = []
        for result in scan_results:
            host_data = {
                "ip": result.ip,
                "ports": {},
                "screenshots": 0,  # Будет пересчитано ниже
                "detected_os": result.detected_os,
                "screenshot_files": [],  # Добавляем список файлов скриншотов
            }

            for port, response in result.open_ports.items():
                service_name = self._get_service_name(port)
                host_data["ports"][str(port)] = {
                    "service": service_name,
                    "response": response,
                }
                
                # Проверяем, есть ли скриншот для этого порта
                if port in {80, 443, 8080, 10000, 8000, 37777, 37778}:
                    screenshot_file = f"{result.ip}_{port}.png"
                    screenshot_path = network_dir / "screenshots" / screenshot_file
                    self.logger.info(f"Проверяем скриншот: {screenshot_path}")
                    if screenshot_path.exists():
                        host_data["screenshot_files"].append({
                            "port": port,
                            "service": service_name,
                            "file": screenshot_file
                        })
                        self.logger.info(f"Найден скриншот: {screenshot_file}")
                    else:
                        self.logger.info(f"Скриншот не найден: {screenshot_path}")

            # Пересчитываем количество скриншотов на основе реальных файлов
            host_data["screenshots"] = len(host_data["screenshot_files"])

            json_data.append(host_data)

        # Генерируем HTML контент
        self.logger.info(f"Генерируем HTML отчет для {len(json_data)} хостов")
        html_content = self._generate_html_content(json_data, network)

        with open(output_file, "w", encoding="utf-8") as f:
            f.write(html_content)

        self.logger.info(f"HTML отчет сохранен: {output_file}")
        return output_file

    def _get_service_name(self, port: int) -> str:
        """Возвращает название сервиса по порту"""
        service_map = {
            21: "FTP",
            22: "SSH",
            23: "Telnet",
            25: "SMTP",
            53: "DNS",
            80: "HTTP",
            110: "POP3",
            143: "IMAP",
            443: "HTTPS",
            993: "IMAPS",
            995: "POP3S",
            1433: "MSSQL",
            1521: "Oracle",
            3306: "MySQL",
            3389: "RDP",
            5432: "PostgreSQL",
            5900: "VNC",
            6379: "Redis",
            8080: "HTTP-Proxy",
            8443: "HTTPS-Alt",
            9000: "Web",
            10000: "Webmin",
            27017: "MongoDB",
            37777: "HTTP-Alt",
            37778: "HTTP-Alt",
        }
        return service_map.get(port, "Unknown")

    def _get_services_list(self, open_ports: Dict[int, str]) -> List[str]:
        """Возвращает список сервисов для хоста"""
        services = []
        for port in open_ports.keys():
            service = self._get_service_name(port)
            if service != "Unknown":
                services.append(service)
        return list(set(services))

    def _generate_html_content(self, json_data: List[Dict], network: str) -> str:
        """Генерирует HTML контент с улучшенным дизайном"""

        def get_port_ending(count):
            if count % 10 == 1 and count % 100 != 11:
                return "порт"
            elif count % 10 in [2, 3, 4] and count % 100 not in [12, 13, 14]:
                return "порта"
            else:
                return "портов"

        def get_screenshot_ending(count):
            if count % 10 == 1 and count % 100 != 11:
                return "скриншот"
            elif count % 10 in [2, 3, 4] and count % 100 not in [12, 13, 14]:
                return "скриншота"
            else:
                return "скриншотов"

        # Статистика
        total_hosts = len(json_data)
        hosts_with_ports = len([h for h in json_data if h["ports"]])
        total_ports = sum(len(h["ports"]) for h in json_data)
        total_screenshots = sum(h["screenshots"] for h in json_data)

        html = """<!DOCTYPE html>
<html lang="ru">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Результаты сканирования сети {network}</title>
    <style>
        body {{
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            margin: 0;
            padding: 20px;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
        }}
        .container {{
            max-width: 1200px;
            margin: 0 auto;
            background: white;
            border-radius: 15px;
            box-shadow: 0 20px 40px rgba(0,0,0,0.1);
            overflow: hidden;
        }}
        .header {{
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 30px;
            text-align: center;
        }}
        .header h1 {{
            margin: 0;
            font-size: 2.5em;
            font-weight: 300;
        }}
        .header p {{
            margin: 10px 0 0 0;
            opacity: 0.9;
            font-size: 1.1em;
        }}
        .stats {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            padding: 30px;
            background: #f8f9fa;
        }}
        .stat-card {{
            background: white;
            padding: 20px;
            border-radius: 10px;
            text-align: center;
            box-shadow: 0 5px 15px rgba(0,0,0,0.08);
            transition: transform 0.3s ease;
        }}
        .stat-card:hover {{
            transform: translateY(-5px);
        }}
        .stat-number {{
            font-size: 2.5em;
            font-weight: bold;
            color: #667eea;
            margin-bottom: 5px;
        }}
        .stat-label {{
            color: #666;
            font-size: 0.9em;
            text-transform: uppercase;
            letter-spacing: 1px;
        }}
        .content {{
            padding: 30px;
        }}
        .host-card {{
            background: white;
            border: 1px solid #e0e0e0;
            border-radius: 10px;
            margin-bottom: 20px;
            overflow: hidden;
            box-shadow: 0 5px 15px rgba(0,0,0,0.08);
            transition: all 0.3s ease;
        }}
        .host-card:hover {{
            box-shadow: 0 10px 30px rgba(0,0,0,0.15);
            transform: translateY(-2px);
        }}
        .host-header {{
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 20px;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }}
        .host-ip {{
            font-size: 1.3em;
            font-weight: bold;
        }}
        .host-info {{
            display: flex;
            gap: 20px;
            font-size: 0.9em;
            opacity: 0.9;
        }}
        .host-body {{
            padding: 20px;
        }}
        .ports-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fill, minmax(150px, 1fr));
            gap: 15px;
            margin-top: 15px;
        }}
        .port-item {{
            background: #f8f9fa;
            padding: 15px;
            border-radius: 8px;
            border-left: 4px solid #667eea;
        }}
        .port-number {{
            font-weight: bold;
            color: #667eea;
            font-size: 1.1em;
        }}
        .port-service {{
            color: #666;
            font-size: 0.9em;
            margin-top: 5px;
        }}
        .port-response {{
            color: #888;
            font-size: 0.8em;
            margin-top: 5px;
            font-family: monospace;
            word-break: break-all;
        }}
        .screenshots-section {{
            margin-top: 20px;
            padding-top: 20px;
            border-top: 1px solid #e0e0e0;
        }}
        .screenshots-title {{
            font-size: 1.2em;
            font-weight: bold;
            color: #667eea;
            margin-bottom: 15px;
            display: flex;
            align-items: center;
            gap: 8px;
        }}
        .screenshots-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fill, minmax(300px, 1fr));
            gap: 20px;
        }}
        .screenshot-item {{
            background: #f8f9fa;
            border-radius: 10px;
            overflow: hidden;
            box-shadow: 0 5px 15px rgba(0,0,0,0.08);
            transition: transform 0.3s ease;
        }}
        .screenshot-item:hover {{
            transform: translateY(-5px);
        }}
        .screenshot-image {{
            width: 100%;
            height: 200px;
            object-fit: cover;
            border-bottom: 1px solid #e0e0e0;
        }}
        .screenshot-info {{
            padding: 15px;
        }}
        .screenshot-port {{
            font-weight: bold;
            color: #667eea;
            font-size: 1.1em;
        }}
        .screenshot-service {{
            color: #666;
            font-size: 0.9em;
            margin-top: 5px;
        }}
        .modal {{
            display: none;
            position: fixed;
            z-index: 1000;
            left: 0;
            top: 0;
            width: 100%;
            height: 100%;
            overflow: auto;
            background-color: rgba(0,0,0,0.8);
        }}
        .modal-content {{
            margin: auto;
            display: block;
            width: 90%;
            max-width: 1200px;
            max-height: 90%;
            object-fit: contain;
        }}
        .modal-close {{
            position: absolute;
            top: 15px;
            right: 35px;
            color: #f1f1f1;
            font-size: 40px;
            font-weight: bold;
            cursor: pointer;
        }}
        .modal-close:hover,
        .modal-close:focus {{
            color: #bbb;
            text-decoration: none;
            cursor: pointer;
        }}
        .screenshot-image {{
            cursor: pointer;
            transition: transform 0.3s ease;
        }}
        .screenshot-image:hover {{
            transform: scale(1.05);
        }}
        #modalCaption {{
            margin: auto;
            display: block;
            width: 80%;
            max-width: 700px;
            text-align: center;
            color: #ccc;
            padding: 10px 0;
            height: 150px;
        }}
        .no-ports {{
            text-align: center;
            color: #888;
            font-style: italic;
            padding: 20px;
        }}
        .footer {{
            background: #f8f9fa;
            padding: 20px;
            text-align: center;
            color: #666;
            border-top: 1px solid #e0e0e0;
        }}
        @media (max-width: 768px) {{
            .stats {{
                grid-template-columns: 1fr;
            }}
            .host-info {{
                flex-direction: column;
                gap: 10px;
            }}
            .ports-grid {{
                grid-template-columns: 1fr;
            }}
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🔍 Результаты сканирования</h1>
            <p>Сеть: {network} | Время: {datetime_now}</p>
        </div>
        
        <div class="stats">
            <div class="stat-card">
                <div class="stat-number">{total_hosts}</div>
                <div class="stat-label">Всего хостов</div>
            </div>
            <div class="stat-card">
                <div class="stat-number">{hosts_with_ports}</div>
                <div class="stat-label">Хостов с открытыми портами</div>
            </div>
            <div class="stat-card">
                <div class="stat-number">{total_ports}</div>
                <div class="stat-label">{port_ending}</div>
            </div>
            <div class="stat-card">
                <div class="stat-number">{total_screenshots}</div>
                <div class="stat-label">{screenshot_ending}</div>
            </div>
        </div>
        
        <div class="content">""".format(
            network=network,
            total_hosts=total_hosts,
            hosts_with_ports=hosts_with_ports,
            total_ports=total_ports,
            total_screenshots=total_screenshots,
            port_ending=get_port_ending(total_ports),
            screenshot_ending=get_screenshot_ending(total_screenshots),
            datetime_now=datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        )

        # Добавляем информацию о хостах
        for host in json_data:
            ports_count = len(host["ports"])
            screenshots_count = host["screenshots"]
            os_info = host["detected_os"] if host["detected_os"] else "Не определено"

            html += f"""
            <div class="host-card">
                <div class="host-header">
                    <div class="host-ip">🖥️ {host['ip']}</div>
                    <div class="host-info">
                        <span>📊 {ports_count} {get_port_ending(ports_count)}</span>
                        <span>📸 {screenshots_count} {get_screenshot_ending(screenshots_count)}</span>
                        <span>💻 {os_info}</span>
                    </div>
                </div>
                <div class="host-body">"""

            if host["ports"]:
                html += '<div class="ports-grid">'
                for port, port_info in host["ports"].items():
                    html += f"""
                    <div class="port-item">
                        <div class="port-number">🔌 {port}</div>
                        <div class="port-service">🌐 {port_info['service']}</div>
                        <div class="port-response">{port_info['response'][:50]}{'...' if len(port_info['response']) > 50 else ''}</div>
                    </div>"""
                html += '</div>'
            else:
                html += '<div class="no-ports">❌ Открытых портов не найдено</div>'

            # Добавляем секцию для скриншотов, если они есть
            if screenshots_count > 0:
                html += f"""
                <div class="screenshots-section">
                    <div class="screenshots-title">
                        <span>📸 Скриншоты</span>
                        <span>{screenshots_count} {get_screenshot_ending(screenshots_count)}</span>
                    </div>
                    <div class="screenshots-grid">"""
                
                # Отображаем реальные скриншоты
                for screenshot in host.get("screenshot_files", []):
                    html += f"""
                    <div class="screenshot-item">
                        <img src="screenshots/{screenshot['file']}" alt="Скриншот порта {screenshot['port']}" class="screenshot-image" onclick="openModal(this.src, 'Порт: {screenshot['port']} - Сервис: {screenshot['service']}')">
                        <div class="screenshot-info">
                            <div class="screenshot-port">Порт: {screenshot['port']}</div>
                            <div class="screenshot-service">Сервис: {screenshot['service']}</div>
                        </div>
                    </div>"""
                
                html += "</div></div>"

            html += """
                </div>
            </div>"""

        html += """
        </div>
        
        <!-- Модальное окно для увеличения изображений -->
        <div id="imageModal" class="modal">
            <span class="modal-close" onclick="closeModal()">&times;</span>
            <img class="modal-content" id="modalImage">
            <div id="modalCaption"></div>
        </div>
        
        <script>
        function openModal(imgSrc, caption) {
            var modal = document.getElementById("imageModal");
            var modalImg = document.getElementById("modalImage");
            var captionText = document.getElementById("modalCaption");
            
            modal.style.display = "block";
            modalImg.src = imgSrc;
            captionText.innerHTML = caption;
        }
        
        function closeModal() {
            document.getElementById("imageModal").style.display = "none";
        }
        
        // Закрытие модального окна при клике вне изображения
        document.getElementById("imageModal").onclick = function(e) {
            if (e.target === this) {
                closeModal();
            }
        }
        
        // Закрытие модального окна по клавише Escape
        document.addEventListener('keydown', function(e) {
            if (e.key === 'Escape') {
                closeModal();
            }
        });
        </script>
        
        <div class="footer">
            <p>📊 Отчет сгенерирован автоматически | 🔒 Только для внутреннего использования</p>
        </div>
    </div>
</body>
</html>"""

        return html
