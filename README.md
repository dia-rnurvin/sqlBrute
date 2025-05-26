# 🔍 SQL Fuzzing Aləti

**SQL Fuzzing Aləti** — veb tətbiqlərdə SQL injeksiya zəifliklərini aşkarlamaq üçün hazırlanmış çoxfunksiyalı, sürətli və istifadəsi asan test alətidir. Alət həm təhlükəsizlik testləri, həm də tədris məqsədilə istifadə olunur.

---

## ✨ Əsas Xüsusiyyətlər

- ✅ GET, POST, PUT, DELETE və digər HTTP metodlarını dəstəkləyir  
- ✅ GUI (qrafik), konsol və HTML hesabat çıxışları  
- ✅ Paralel işləmə üçün çoxsaylı thread dəstəyi  
- ✅ Tkinter əsaslı real-time GUI interfeysi  
- ✅ URL və Base64 ilə payload kodlaması  
- ✅ Status, cavab uzunluğu və zaman üzrə çeşidləmə  
- ✅ Əlavə HTTP başlıq dəstəyi  
- ✅ Bootstrap əsaslı HTML hesabat (responsive dizayn)  
- ✅ Tam açıq mənbə Python layihəsi

---

## ⚙️ Quraşdırma

1. **Python 3.6+** versiyasını yüklə və quraşdır:  
   👉 [https://www.python.org/downloads/](https://www.python.org/downloads/)

2. **Tələbləri quraşdır:**
   ```bash
   pip install requests jinja2 rich

## 🚀 İstifadə Qaydaları

🔹 GET sorğusu üçün:
```bash
python3 sqlfuzz.py --url "https://example.com/search?q=NAN" --fuzzfile fuzz.txt --threads 10 --console "status-" --report
```
🔹 POST sorğusu üçün:
```bash
python3 sqlfuzz.py --request request.txt --fuzzfile fuzz.txt --gui
```
🔹 Əlavə header əlavə etmək:
```bash
--header "Authorization: Bearer token|X-Custom: test"
```
🔹 Payload kodlaması:
```bash
--encode url     # URL kodlaması
--encode b64     # Base64 kodlaması
```

## 📄 Sorğu Fayl Formatı
Fayl adı: request.txt
```bash
POST /login HTTP/1.1
Host: example.com
Content-Type: application/x-www-form-urlencoded

username=NAN&password=test
```
NAN – payload-ların yerinə qoyulacaq hissədir.

## 🖼️ GUI Modu
GUI rejimini başlatmaq üçün:
```bash
python3 sqlfuzz.py --request request.txt --fuzzfile fuzz.txt --gui
```
🔵 GUI Xüsusiyyətləri:
- Rəngləndirilmiş nəticə statusları
- Real vaxtda nəticələrin yığılması
- Cavab və sorğu detalları üçün baxış pəncərəsi
- Avtomatik statistika və irəliləyiş göstəricisi

## 📊 HTML Hesabat
Nəticələri vizual hesabat şəklində saxlamaq üçün:
```bash
--report             # Avtomatik adla hesabat yaradılır
--report netice.html # Sənin seçdiyin adda yaradılır
```
HTML faylı Bootstrap 4 ilə hazırlanmışdır və interaktiv görünüşə malikdir.

## 🧩 Əlavə Parametrlər

| Parametr        | Təsviri                                                                 |
|------------------|-------------------------------------------------------------------------|
| `--url`          | GET sorğusu üçün hədəf URL (`NAN` payload yerini göstərir)              |
| `--request`      | Sorğu faylı (`GET`, `POST` və s. daxil olmaqla tam HTTP strukturu)      |
| `--fuzzfile`     | Payloadların olduğu fayl (hər sətrdə bir payload)                       |
| `--threads`      | Paralel işləyən thread sayı (standart: `10`)                            |
| `--header`       | Əlavə HTTP başlıqlar (`Açar: Dəyər|Açar2: Dəyər2` formatında)           |
| `--encode`       | Payload kodlaması: `url` və ya `b64`                                    |
| `--console`      | Konsol rejimi aktiv və çeşidləmə parametri (`status desc`, `length+`)   |
| `--gui`          | Qrafik istifadəçi interfeysini aktivləşdirir                            |
| `--report`       | HTML hesabat çıxışı (`--report` və ya `--report ad.html`)               |
| `--help`         | Kömək mesajını göstərir                                                 |



## 🎯 Layihənin Məqsədi
Bu alət SQL injection zəifliklərini aşkarlamaq üçün fuzzing texnikasına əsaslanır. Həm real mühitlərdə, həm də laboratoriya və tədris məqsədləri üçün idealdır.
