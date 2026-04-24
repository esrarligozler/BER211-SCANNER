# 🔍 BER211 Scanner

**BER211 Scanner**, keşif (recon), analiz ve güvenli zafiyet tespiti için geliştirilmiş **zararsız (non-destructive)** bir güvenlik test aracıdır.

> ⚠️ Bu araç **saldırı yapmaz**, yalnızca güvenli test ve analiz gerçekleştirir.
> Sadece **izinli sistemlerde** kullanılmalıdır.

---

## 🚀 Özellikler

### 🔎 Keşif (Recon)

* DNS çözümleme & IP tespiti
* Hızlı / Full port tarama
* Subdomain keşfi
* Endpoint keşfi (HTML, robots.txt, sitemap)

### 🌐 Web Analizi

* HTTP header analizi
* Cookie güvenlik kontrolü
* TLS/SSL inceleme
* Teknoloji tespiti (PHP, jQuery, Bootstrap vb.)
* WAF/CDN tespiti ve davranış analizi

### 🧪 Güvenli Testler

* XSS probe (zararsız)
* SQL Injection probe (zararsız)
* Path traversal kontrolü
* CORS yapılandırma analizi
* Rate-limit davranış testi

### 🧩 Gelişmiş Modüller

* Wordlist ile endpoint brute
* Parametre keşfi
* Endpoint bazlı test (ilk 20 endpoint)
* Admin panel keşfi

### 📊 Raporlama

* JSON rapor
* HTML rapor
* Risk skoru hesaplama
* Port analizi (port intelligence)

---

## ⚙️ Kurulum

```bash
git clone https://github.com/KULLANICI_ADIN/ber211-scanner.git
cd ber211-scanner
pip install -r requirements.txt
```

---

## ▶️ Kullanım

```bash
python3 main.py
```

Ardından:

```text
Hedef URL gir
Yetki onayı ver
Tarama modu seç (Fast / Full)
```

---

## 📁 Çıktılar

Raporlar otomatik olarak şu klasöre kaydedilir:

```text
reports/
```

Örnek:

```text
reports/ber211_report_example_com.json
reports/ber211_report_example_com.html
```

---

## ⚠️ Yasal Uyarı

Bu araç:

* Eğitim
* Yetkili sızma testleri
* Güvenlik araştırmaları

için geliştirilmiştir.

❌ İzinsiz sistemlerde kullanımı **yasadışıdır**.

---

## 🧠 Mimari

```text
Recon → Discovery → Analysis → Safe Probes → Reporting
```

---

## 👨‍💻 Geliştirici

**esrarigozler**

---

## ⭐ Destek

Projeyi beğendiysen:
* discord.gg/keless katıl
* ⭐ Repo’ya yıldız bırak
* Paylaş
* Sorumlu şekilde kullan

---
