# 🛡️ BER211 Scanner

[![Version](https://img.shields.io/badge/version-1.1.0-blue)](https://github.com/esrarligozler/BER211-SCANNER/releases)
[![Python](https://img.shields.io/badge/python-3.8%2B-green)](https://www.python.org/)
[![License](https://img.shields.io/github/license/esrarligozler/BER211-SCANNER)](LICENSE)
[![CI](https://github.com/esrarligozler/BER211-SCANNER/actions/workflows/ci.yml/badge.svg)](https://github.com/esrarligozler/BER211-SCANNER/actions)

**BER211 Scanner** – Yetkili güvenlik testleri için geliştirilmiş, tahribatsız (non‑destructive), kapsamlı web uygulama güvenlik tarayıcısı.

> ⚠️ **YASAL UYARI:** Bu araç **yalnızca** sahibi olduğunuz veya yazılı izin aldığınız sistemlerde kullanılmalıdır. İzinsiz kullanım **yasa dışıdır** ve cezai yaptırımlara tabidir. Kullanıcı tüm sorumluluğu kabul eder.

---

## ✨ Özellikler

- 🚀 **Hızlı port tarama** – Asenkron, 100+ eşzamanlı bağlantı
- 🌐 **Subdomain keşfi** – Brute‑force + DNS enumeration
- 🔍 **DNS analizi** – AXFR, SPF, DMARC, MX, NS, TXT, SOA
- 🛡️ **WAF/CDN tespiti** – Cloudflare, Akamai, Sucuri, Fastly, AWS CloudFront, Vercel, Netlify
- 💻 **Teknoloji tespiti** – CMS, framework, web sunucusu, JavaScript kütüphaneleri
- 📝 **Güvenlik başlıkları analizi** – CSP, HSTS, X‑Frame‑Options, X‑Content‑Type‑Options, Referrer‑Policy, Permissions‑Policy, X‑XSS‑Protection, CORP, COOP, COEP
- 🍪 **Cookie güvenliği** – HttpOnly, Secure, SameSite kontrolleri
- 🔐 **TLS/SSL denetimi** – Zayıf şifre tespiti, sertifika geçerlilik, TLS versiyonu
- 🧪 **Zafiyet testleri (güvenli probe ile)**:
  - SQL Injection (error‑based + time‑based)
  - XSS (reflected)
  - SSTI (Server‑Side Template Injection)
  - CSRF, IDOR, CORS
  - Path traversal, Directory listing
  - Rate limiting testi (eşzamanlı isteklerle)
  - Clickjacking, Cache Poisoning, HPP
  - JWT analizi (`alg=none` kontrolü)
  - LDAP, GraphQL introspection, Mass assignment
  - Prototype Pollution, Business logic (negatif fiyat)
  - User enumeration, 2FA bypass, Password reset poisoning
  - Deserialization (Java)
  - Hassas veri sızıntısı (email, API key, password)
- 📊 **Raporlama** – JSON ve HTML formatında, risk skoru (10 üzerinden)
- 🐳 **Docker desteği** – Tek komutla çalıştır
- 🖥️ **CLI ve etkileşimli menü** – Otomasyon veya manual kullanım

---

## 🚀 Hızlı Başlangıç

### Kurulum

```
bash
# GitHub'dan klonla
git clone https://github.com/yourusername/ber211-scanner.git
cd ber211-scanner

# Bağımlılıkları yükle
pip install -r requirements.txt

# Çalıştır
python main.py 
```


Docker ile
```bash
docker build -t ber211-scanner .
docker run -it --rm ber211-scanner
Tek satırda (pip install)
bash
pip install ber211-scanner
ber211-scanner --target https://example.com --authorized
```
📖 Kullanım
Etkileşimli menü
```
bash
python main.py
# 1 → Başlat, hedef URL gir, tarama modu seç (fast/full)
# 2 → Geliştirici bilgisi
# 3 → Çıkış
Komut satırı (otomasyon için)
```
```
bash
python main.py --target https://hedef.com --mode full --authorized
Parametre	Açıklama
-t, --target	Hedef URL (örnek: https://example.com)
-m, --mode	Tarama modu: fast (6 port) veya full (77+ port, varsayılan: fast)
--authorized	Yetkiniz olduğunu onaylar (yasal uyarıyı atlar)
--version	Sürüm bilgisi
Örnek çıktı
Tarama tamamlandığında reports/ klasöründe iki dosya oluşur:

ber211_report_<domain>.json – Tüm bulguları içeren makine okunabilir rapor

ber211_report_<domain>.html – İnsan okunabilir, grafiksel HTML rapor (risk skoru, tablolar)
```
📂 Çıktı Örneği (JSON)
```
 json
{
  "target": "https://example.com",
  "risk": { "score": 7.2, "level": "HIGH" },
  "vulnerabilities": [
    {
      "category": "SSTI",
      "severity": "High",
      "title": "Potential Server-Side Template Injection",
      "evidence": "Payload {{7*7}} returned 49"
    }
  ]
}
```
🛠️ Gereksinimler
```Python 3.8 veya üzeri

İnternet bağlantısı (DNS, WHOIS, ASN sorguları için)

Root yetkisi gerekmez – Düşük portlar (<1024) root istese de tarama devam eder; root yoksa sadece o portlar atlanır.
```

🛡️ Güvenlik Politikası
```Güvenlik açığı bildirimleri için SECURITY.md dosyasını inceleyin. Özel olarak bildirin, herkese açık issue açmayın.```

📄 Lisans
```Bu proje Apache LICENSE ile lisanslanmıştır. Detaylar için LICENSE dosyasına bakın.```

📞 İletişim
```
Geliştirici: ESRAR-I-GOZLER

Discord: discord.gg/keless
```

