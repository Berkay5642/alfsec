# 🛡️ AlfSec v7.5 — Siber Güvenlik, OSINT & Kriptografi Konsolu

> ⚠️ **YASAL UYARI VE SORUMLULUK REDDİ (DISCLAIMER)**
> Bu yazılım (**AlfSec v7.5**); yalnızca **eğitim, etik güvenlik denetimi, ağ teşhisi ve kişisel gizlilik** amaçlarıyla geliştirilmiştir. Siber saldırı, izinsiz sızma veya kötü niyetli faaliyetler için **kesinlikle kullanılamaz**. Kullanıcılar, bu araçları yalnızca kendi sahip oldukları sistemlerde veya açık yazılı izne sahip oldukları ağlarda çalıştırmakla yükümlüdür. Aracın amacına aykırı veya yasa dışı kullanımından doğabilecek her türlü hukuki ve cezai sorumluluk tamamen kullanıcıya aittir; geliştirici hiçbir sorumluluk kabul etmez.

---

## 📌 Nedir ve Ne İşe Yarar?
**AlfSec v7.5**, Termux (Android), Ubuntu, Debian, Kali Linux ve Windows platformlarında ek karmaşık bağımlılıklara ihtiyaç duymadan çalışan çok yönlü bir güvenlik, ağ analizi ve kriptografi aracıdır. Tek bir paket içerisinde üç farklı çalışma arayüzü sunar:

* **TUI (Terminal Kullanıcı Arayüzü):** Doğrudan terminal içinde çalışan, menülü, renkli ve gömülü dokümantasyon rehberine sahip etkileşimli arayüz.
* **Web GUI (Görsel Kontrol Paneli):** Tarayıcı üzerinde açılan, tek tıkla modül çalıştırma ve canlı çıktı izleme imkânı sunan kontrol merkezi.
* **CLI (Komut Satırı):** Hızlı otomasyon ve betik (script) çalıştırma için klasik etkileşimli konsol.

---

## 🚀 Kurulum Kılavuzu (Tüm İşletim Sistemleri)

### Yöntem 1: Tek Komutla Doğrudan Kurulum (Önerilen)
Python 3.8 ve üzeri kurulu olan herhangi bir sistemde (Windows CMD/PowerShell, Ubuntu, Debian, Kali Linux veya Termux) şu komutu çalıştırmanız yeterlidir:

```bash
pip install git+[https://github.com/Berkay5642/alfsec.git](https://github.com/Berkay5642/alfsec.git)
```

### Yöntem 2: Kaynak Koddan Manuel Kurulum
```bash
git clone [https://github.com/Berkay5642/alfsec.git](https://github.com/Berkay5642/alfsec.git)
cd alfsec
pip install -r requirements.txt
python alfsec.py tui
```

---

## 💻 Kullanım Modları

| Komut | Arayüz Türü | Açıklama |
| :--- | :--- | :--- |
| `alfsec tui` | **Terminal Arayüzü** | Kategorilere ayrılmış menüler ve yerleşik dokümantasyon ile terminalde kullanım. |
| `alfsec gui` | **Web Kontrol Paneli** | Yerel sunucu (`127.0.0.1:8080`) başlatır ve tarayıcıda görsel arayüzü açar. |
| `alfsec` | **Klasik Konsol (CLI)** | Doğrudan komut yazarak (`alfsec>`) işlem yapmayı sağlar. |

---

## 📖 Dahili Modül Dokümantasyonu (24 Modül)

### 1. Gizlilik & Tor Tüneli
* `gizli_mod("acik")` / `gizli_mod("kapali")`: Yerel Tor SOCKS5h tünelini başlatır veya kapatır (sistemde `tor` servisinin kurulu olması gerekir).
* `yeni_kimlik()`: Tor kontrol portu (`9051`) üzerinden devre yenileyerek anında yeni bir çıkış IP adresi talep eder.
* `sizinti_testi()`: Aktif dış IP adresini ve bağlantının Tor tüneli üzerinden geçip geçmediğini doğrular.
* `gizli_oku("url")`: Hedef web sayfasının kaynak içeriğini aktif ağ/Tor tüneli üzerinden çeker.

### 2. Web Güvenliği, SSL & OSINT Analizi
* `web_denetle("domain")`: Hedef alan adının **HSTS**, **CSP (XSS)**, **Clickjacking (X-Frame-Options)** ve **MIME** güvenlik başlıklarını denetler.
* `ssl_analiz("domain")`: TLS protokol sürümünü, şifreleme paketini ve sertifika geçerlilik tarihlerini inceler.
* `domain_kimlik("domain")`: Alan adının DNS kayıtlarını ve sunucu altyapısını sorgular.
* `link_tara("url")`: Bağlantı yönlendirmelerini ve hedef HTTP durum kodlarını analiz eder.
* `ip_analiz("ip")`: IP adresinin coğrafi konum, ASN ve servis sağlayıcı (ISS) bilgilerini getirir.
* `guvenlik_raporu("ip")`: Belirtilen IP adresi için temel güvenlik ve port özeti oluşturur.

### 3. Yerel Ağ & Port Teşhisi
* `ag_kimlik()`: Cihazın yerel ağ arayüzünü ve IP bilgilerini gösterir.
* `ag_tara("onek")`: Yerel alt ağdaki aktif cihazları tespit eder (Örn: `ag_tara("192.168.1")`).
* `port_tara("hedef", bas, bit)`: Yetkili olunan hedefte belirli aralıktaki açık TCP portlarını tarar.
* `servis_bul("hedef", port)`: Açık portta çalışan servisin banner bilgisini okur.

### 4. Kriptografi & Yerel Şifre Kasası
* `sifrele("metin", "parola")` / `coz("sifreli", "parola")`: Metinleri **AES-256-GCM** algoritmasıyla şifreler ve çözer.
* `ozetle("metin")`: Verinin **SHA-256** kriptografik özetini hesaplar.
* `sifre_uret(20)`: Kriptografik olarak güvenli rastgele parola üretir.
* `parola_test("parola")`: Parolanın entropi gücünü ve karakter çeşitliliğini ölçer.
* `kasa_ekle("etiket", "veri", "parola")` / `kasa_oku("etiket", "parola")`: Hassas bilgileri şifreli yerel kasada (`~/.alfsec_kasa.json`) saklar ve okur.

### 5. Dosya Bütünlüğü & Steganografi
* `dosya_sifrele("yol", "parola")` / `dosya_coz("yol", "parola")`: Dosyaları AES-256-GCM ile şifreler ve çözer.
* `dosya_denetle("yol")`: Dosyanın SHA-256 bütünlük imzasını hesaplar ve doğrular.
* `resme_gizle("yol", "mesaj", "parola")` / `resimden_oku("yol", "parola")`: Şifrelenmiş metni PNG görsellerinin pikselleri içine gizler ve geri okur.

---

## 👨‍💻 Geliştirici
**Alfred Zenith Dawn** — [GitHub @Berkay5642](https://github.com/Berkay5642)
