# 🛡 CyberLogParser Pro 2026

**Siber güvenlik analistleri için geliştirilmiş, modern ve kapsamlı log analiz aracı.**  
Tek dosya, sıfır konfigürasyon — aç ve kullan.

![Python](https://img.shields.io/badge/Python-3.10+-blue?style=flat-square&logo=python)
![License](https://img.shields.io/badge/License-MIT-green?style=flat-square)
![Platform](https://img.shields.io/badge/Platform-Windows%20%7C%20Linux%20%7C%20macOS-lightgrey?style=flat-square)

---

## Ne İşe Yarıyor?

Log dosyası açarsın, **Parse Et**'e basarsın. Tehditler zaten karşında olur.

- Brute force, SQLi, XSS, DoS, port scan → otomatik tespit
- MITRE ATT&CK tekniği eşlemesi
- IOC çıkarımı (IP, domain, hash, CVE)
- Gerçek zamanlı izleme (tail -f gibi)
- PDF / HTML / Excel / JSON / CSV rapor

---

## Desteklenen Log Formatları

| Format | Örnek Dosya / Kaynak |
|---|---|
| Apache Access Log | /var/log/apache2/access.log |
| Nginx Access Log | /var/log/nginx/access.log |
| Linux Syslog (RFC 3164 / 5424) | /var/log/syslog |
| SSH Auth Log | /var/log/auth.log |
| Windows Event Log | Event Viewer XML / CSV export |
| Suricata EVE JSON | eve.json |
| CEF (ArcSight, QRadar) | SIEM log export |
| Cisco ASA Firewall | %ASA-6-302013: formatı |
| AWS VPC Flow Logs | CloudWatch / S3 export |
| FortiGate Traffic Log | sample_logs/fortigate_traffic.log |
| Sıkıştırılmış | .gz / .bz2 / .zip |

Tanınamayan formatlarda da çalışır — temel IP/mesaj çıkarımı yapar.



## Tespit Edilen Tehditler

| Alert ID | Tehdit | Severity | MITRE |
|---|---|---|---|
| SSH-001 | SSH Brute Force (60s içinde 5+ deneme) | HIGH | T1110 |
| SSH-002 | Password Spray (5+ farklı kullanıcı) | HIGH | T1110 |
| WEB-001 | SQL Injection girişimi | CRITICAL | T1190 |
| WEB-002 | XSS (Cross-Site Scripting) girişimi | HIGH | T1190 |
| WEB-003 | Directory Traversal | HIGH | T1083 |
| WEB-004 | Güvenlik tarayıcısı (sqlmap, nikto...) | MEDIUM | T1046 |
| NET-001 | DoS / Flood (10s içinde 200+ istek) | HIGH | T1498 |
| WIN-001 | Güvenlik logu silindi (Event 1102) | CRITICAL | T1070 |
| WIN-002 | Zamanlanmış görev oluşturuldu (4698) | HIGH | T1053 |
| WIN-003 | Yeni servis kuruldu (Event 7045) | HIGH | T1543 |
| MAL-001 | Zararlı yazılım izi tespit edildi | CRITICAL | T1059 |

---

## Mimari

CyberLogParser.py
│
├── FormatDetector     → formatı otomatik tahmin eder
├── LogFileReader      → .gz/.bz2/.zip dahil okur
├── Parser sınıfları   → Apache, Nginx, Syslog, SSH, CEF, JSON, Cisco ASA, AWS VPC, FortiGate
├── BehavioralAnalyzer → zaman pencereli tehdit tespiti
├── IOCExtractor       → regex tabanlı IOC çıkarımı
├── StatisticsEngine   → istatistikler
├── ReportGenerator    → HTML / PDF / Excel / JSON / CSV
├── LogTailHandler     → gerçek zamanlı tail -f
└── UI (CustomTkinter) → Dashboard, Kayıtlar, Uyarılar, IOC, Canlı İzleme, Grafikler

---

## Kullanım

1. **Dosya Aç** → log dosyasını seç
2. **Parse Et** → format otomatik tespit edilir
3. **Uyarılar** sekmesi → tehditler skor sırasıyla listelenir
4. **IOC Intel** → IP/domain/hash/CVE otomatik çıkarılmış olur
5. **Canlı İzleme** → dosya seç, Başlat'a bas
6. **Dışa Aktar** → HTML veya Excel raporu oluştur

---

## Gereksinimler

| Paket | Kullanım | Zorunlu mu |
|---|---|---|
| customtkinter | Modern dark UI | Evet |
| matplotlib | Grafikler | Evet |
| Pillow | Görsel işleme | Evet |
| openpyxl | Excel export | İsteğe bağlı |
| reportlab | PDF export | İsteğe bağlı |
| pandas | Gelişmiş analiz | İsteğe bağlı |

---

