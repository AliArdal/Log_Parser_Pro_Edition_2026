🛡 CyberLogParser Pro 2026
Siber güvenlik analistleri için geliştirdiğim, modern ve kapsamlı log analiz aracı.
Tek dosya, sıfır konfigürasyon — lokalde kullanılan dış ağdan izole api istekleri oluşturmayan bir uygulama, aç ve kullan

<img width="2559" height="1391" alt="1" src="https://github.com/user-attachments/assets/f38e6d52-3198-4d5b-9215-999c1878b739" />
<img width="2559" height="1392" alt="2" src="https://github.com/user-attachments/assets/44d227e5-3ab2-473a-8d41-f564822516a6" />
<img width="2559" height="1396" alt="3" src="https://github.com/user-attachments/assets/ab574256-281a-4a0f-82c7-1326fb8e2f13" />
<img width="2559" height="1392" alt="4" src="https://github.com/user-attachments/assets/b5ec003d-5005-43c9-87c0-afbf20a85056" />
<img width="2559" height="1398" alt="5" src="https://github.com/user-attachments/assets/2ff9e1b5-cdf8-48a8-9893-19737dc63e00" />


Ne İşe Yarıyor?
Log dosyası açarsın, Parse Et'e basarsın.
Tehditler zaten karşında olur.

Brute force, SQLi, XSS, DoS, port scan → otomatik tespit
MITRE ATT&CK tekniği eşlemesi
IOC çıkarımı (IP, domain, hash, CVE)
Gerçek zamanlı izleme (tail -f gibi)
PDF / HTML / Excel / JSON / CSV rapor


Desteklenen Log Formatları
┌──────────────────────────────────┬────────────────────────────────────┐
│ Format                           │ Örnek Dosya / Kaynak               │
├──────────────────────────────────┼────────────────────────────────────┤
│ Apache Access Log                │ /var/log/apache2/access.log        │
│ Nginx Access Log                 │ /var/log/nginx/access.log          │
│ Linux Syslog  (RFC 3164 / 5424)  │ /var/log/syslog                    │
│ SSH Auth Log                     │ /var/log/auth.log                  │
│ Windows Event Log                │ Event Viewer XML / CSV export      │
│ Suricata EVE JSON                │ eve.json                           │
│ CEF  (ArcSight, QRadar)          │ SIEM log export                    │
│ Cisco ASA Firewall               │ %ASA-6-302013: formatı             │
│ AWS VPC Flow Logs                │ CloudWatch / S3 export             │
│ Sıkıştırılmış                    │ .gz  /  .bz2  /  .zip              │
│Fortigate Traffic Logs            │sample_logs/fortigate_traffic.log   │
└──────────────────────────────────┴────────────────────────────────────┘
Tanınamayan formatlarda da çalışır — temel IP/mesaj çıkarımı yapar.


Ekran Görüntüleri
┌─────────────────────────────────────────────────────┐
│  🛡 CyberLogParser    PRO 2026 · SOC Edition         │
│  📂 Dosya Aç  ⚡ Parse Et  📊 Dışa Aktar  🗑 Temizle │
├────────────┬────────────┬────────────┬──────────────┤
│ 📊 Dashboard│📋 Kayıtlar │🚨 Uyarılar │🔍 IOC Intel  │
├────────────┴────────────┴────────────┴──────────────┤
│  📄 12,847    🚨 23 Uyarı    🌍 847 IP    👤 156 User │
│                                                      │
│  [SSH-001] SSH Brute Force — 192.168.1.105          │
│  [WEB-002] SQL Injection  — 45.33.32.156            │
│  [WIN-001] Log Silindi    — SUNUCU-01               │
└─────────────────────────────────────────────────────┘

Tespit Edilen Tehditler
┌──────────┬──────────────────────────────────────────┬───────────┬────────┐
│ Alert ID │ Tehdit                                   │ Severity  │ MITRE  │
├──────────┼──────────────────────────────────────────┼───────────┼────────┤
│ SSH-001  │ SSH Brute Force  (60s içinde 5+ deneme)  │ 🔴 HIGH   │ T1110  │
│ SSH-002  │ Password Spray   (5+ farklı kullanıcı)   │ 🔴 HIGH   │ T1110  │
│ WEB-001  │ SQL Injection girişimi                   │ 🔴 CRIT   │ T1190  │
│ WEB-002  │ XSS (Cross-Site Scripting) girişimi      │ 🟠 HIGH   │ T1190  │
│ WEB-003  │ Directory Traversal                      │ 🟠 HIGH   │ T1083  │
│ WEB-004  │ Güvenlik tarayıcısı  (sqlmap, nikto...)  │ 🟡 MEDIUM │ T1046  │
│ NET-001  │ DoS / Flood  (10s içinde 200+ istek)     │ 🟠 HIGH   │ T1498  │
│ WIN-001  │ Güvenlik logu silindi  (Event 1102)      │ 🔴 CRIT   │ T1070  │
│ WIN-002  │ Zamanlanmış görev oluşturuldu (4698)     │ 🟠 HIGH   │ T1053  │
│ WIN-003  │ Yeni servis kuruldu  (Event 7045)        │ 🟠 HIGH   │ T1543  │
│ MAL-001  │ Zararlı yazılım izi tespit edildi        │ 🔴 CRIT   │ T1059  │
└──────────┴──────────────────────────────────────────┴───────────┴────────┘

Mimari
CyberLogParser.py  
│
├── FormatDetector     → Dosyayı okur, formatı otomatik tahmin eder
├── LogFileReader      → .gz/.bz2/.zip dahil tüm dosyaları okur
├── Parser sınıfları   → Her format için ayrı parse mantığı
│     Apache, Nginx, Syslog, SSH, CEF, JSON, Cisco ASA, AWS VPC...
│
├── BehavioralAnalyzer → Zaman pencereli tehdit tespiti (stateful)
├── IOCExtractor       → Regex tabanlı IOC çıkarımı
├── StatisticsEngine   → Counter ve toplamlar
│
├── ReportGenerator    → HTML / PDF / Excel / JSON / CSV üretimi
├── LogTailHandler     → Gerçek zamanlı tail -f
│
└── UI (CustomTkinter)
      DashboardPanel, LogViewPanel, AlertsPanel,
      IOCPanel, LiveMonitorPanel, ChartsPanel

Kullanım

Dosya Aç → log dosyasını seç (sıkıştırılmış da olabilir)
Parse Et → format otomatik tespit edilir, analiz başlar
🚨 Uyarılar sekmesine bak → tehditler skor sırasıyla listelenir
🔍 IOC Intel → tüm IP/domain/hash/CVE otomatik çıkarılmış olur
📡 Canlı İzleme → canlı log dosyası için dosya seç, Başlat'a bas
Dışa Aktar → HTML veya Excel raporu oluştur


Gereksinimler

Python 3.10+
customtkinter — modern dark UI
matplotlib — grafikler
Pillow — görsel işleme
openpyxl (isteğe bağlı) — Excel export
reportlab (isteğe bağlı) — PDF export


