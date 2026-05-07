## CyberLogParser – Geliştirici Rehberi (Guide)

Bu proje ilk başta tek dosyaydı (`cyberlogparsey.py`). Şu an adım adım modüllere bölünüyor.

### Çalıştırma

```bash
python .\CyberLogParser.py
```

### Klasör yapısı (şu an)

- `CyberLogParser.py`: launcher (uygulamayı başlatır)
- `cyberlogparsey.py`: UI + analiz kuralları (refactor devam ediyor)
- `cyberlogparser/`
  - `core/parsing.py`: **format tespiti + dosya okuma + parser’lar + auto_parse_file**
- `examples/`: örnek log dosyaları

> Not: Refactor devam ederken bazı sınıflar hâlâ `cyberlogparsey.py` içinde.

---

## 1) Log parse hattı nerede?

Şu an parse altyapısı `cyberlogparser/core/parsing.py` içinde:

- **Format tespiti**: `FormatDetector.detect()` ve `FormatDetector.from_filename()`
- **Dosya okuma (gz/bz2/zip dahil)**: `LogFileReader.read_lines()`
- **Parser seçimi**: `get_parser(fmt)`
- **Tek komut parse**: `auto_parse_file(filepath)`

### Yeni bir log formatı ekleme (örnek akış)

1) `cyberlogparser/core/parsing.py` içinde `LogFormat` enum’una ekle
2) `LOG_PATTERNS` içine regex ekle (gerekliyse)
3) Yeni parser sınıfı yaz (örn. `class MyDeviceParser(BaseParser): ...`)
4) `PARSER_MAP` içine bağla:
   - `LogFormat.MY_DEVICE: MyDeviceParser`
5) (Opsiyonel) `FormatDetector.SIGNATURES` içine “imza” ekle ki otomatik tespit etsin

---

## 2) “Log Kayıtları” tablosu nerede? (UI)

`cyberlogparsey.py` içinde:
- **Sınıf**: `LogViewPanel`
- **Tablo çizimi**: `LogViewPanel._render()`

### Sütun ekleme / çıkarma

`LogViewPanel._render()` içinde:
- `cols = [...]` listesi sütun başlıklarını ve genişliklerini belirler
- `values = [...]` listesi her satırda hangi alanların basılacağını belirler

Örnek: Biz hedef IP ve hedef port’u buradan ekledik:
- `('Hedef IP', ...)` ve `('H.Port', ...)`
- `e.dest_ip` ve `e.dest_port`

### Yeni bir alanı tabloda göstermek için

1) `LogEntry` içinde o alan doluyor mu kontrol et (parser doldurmalı)
2) `cols` içine başlık ekle
3) `values` içine `e.<alan>` ekle

---

## 3) Dashboard nerede?

`cyberlogparsey.py` içinde:
- `DashboardPanel`: kartlar + top listeler
- `StatisticsEngine.compute(entries)`: dashboard’un beslendiği metrikleri üretir

Dashboard’ta yeni metrik göstermek için:
- `StatisticsEngine.compute()` içine counter/toplam ekle
- `DashboardPanel.update()` içinde yeni kart veya liste ekle

---

## 4) IOC paneli nerede?

`cyberlogparsey.py` içinde:
- `IOCPanel.populate(entries)`
- IOC çıkarma: `IOCExtractor` (regex/pattern’ler burada)

Yeni IOC türü eklemek için:
- `IOCExtractor.extract_from_text()` içine yeni regex + çıktı listesi ekle
- `IOCPanel.populate()` içinde yeni “section” ekle (başlık + renk)

---

## 5) Uyarılar (Alerts) nerede?

`cyberlogparsey.py` içinde:
- `AlertsPanel.populate(alerts)`: UI’de kartları basar
- `BehavioralAnalyzer.analyze_entry(entry)`: log entry’den alert üretir

Yeni bir kural eklemek için (örnek yaklaşım):
- `BehavioralAnalyzer.analyze_entry()` içine “if/heuristic” ekle
- Bir `ThreatAlert(...)` oluştur
- `severity`, `score`, `evidence`, `mitre_technique` set et

---

## 6) Grafikler nerede?

`cyberlogparsey.py` içinde:
- `ChartsPanel.render(stats, alerts)`

Yeni grafik eklemek için:
- `StatisticsEngine.compute()` içinde o grafiğin datasını üret
- `ChartsPanel.render()` içinde yeni subplot çiz

---

## 7) Export / Raporlama nerede?

`cyberlogparsey.py` içinde:
- `ReportGenerator` sınıfı: `export_html`, `export_pdf`, `export_excel`, `export_json`, `export_csv`
- UI tarafında export menüsü: `CyberLogParserApp._show_export_menu()` ve `_do_export()`

Yeni export formatı eklemek için:
- `ReportGenerator.export_<format>()` fonksiyonu ekle
- `_show_export_menu()` seçeneklerine yeni buton ekle

