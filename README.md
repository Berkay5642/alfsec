# 🛡️ AlfSec v10.0

**AlfSec**, özellikle **Kali Linux**, **BlackArch**, **Ubuntu/Debian** ve **Android Termux** ortamları için geliştirilmiş; **sıfır harici bağımlılıklı**, tamamen **Türkçe** komut ve çıktı desteğine sahip hepsi bir arada bir siber güvenlik ve OSINT aracıdır.

Tek bir dosya üzerinden **CLI (Komut Satırı)**, **TUI (Menülü Terminal Arayüzü)** ve **Web GUI (Tarayıcı Kontrol Paneli)** olmak üzere üç farklı arayüzde çalışır.

---

## ✨ Öne Çıkan Özellikler

* **Sıfır Bağımlılık:** Ekstra `npm` veya `pip` paketlerine ihtiyaç duymaz; yalnızca standart **Node.js** ile her sistemde anında çalışır.
* **Türkçe Nmap & Sistem Köprüsü:** Sistemde kurulu olan `nmap` ve `whois` araçlarının karmaşık çıktılarını süzerek anlaşılır Türkçe raporlara dönüştürür (kurulu değilse kendi dahili Node.js tarayıcısına geçer).
* **40+ Türkçe Modül (5 Ana Kategori):**
  1. **Pasif OSINT & İstihbarat (10 Modül):** `tam_analiz`, `kullanici_ara`, `eposta_denetle`, `dns_detay`, `whois_sorgu`, `subdomain_bul`, `ip_analiz`, `ters_dns`, `mac_sorgu`, `telefon_bilgi`
  2. **Ağ Teşhisi & Türkçe Nmap (8 Modül):** `nmap_turkce`, `port_tara`, `yerel_ag_tara`, `servis_banner`, `ag_kimlik`, `dis_ip`, `tor_kontrol`, `sistem_bilgi`
  3. **Web Güvenliği & SSL Denetimi (7 Modül):** `web_denetle`, `ssl_analiz`, `teknoloji_bul`, `robots_oku`, `cerez_denetle`, `link_cikar`, `http_metotlar`
  4. **Kriptografi, Kodlama & Şifre Kasası (11 Modül):** `sifrele`, `coz`, `ozetle`, `base64_kodla`, `base64_coz`, `hex_kodla`, `hex_coz`, `jwt_coz`, `sifre_uret`, `parola_guc`, `kasa_ekle`, `kasa_oku`
  5. **Adli Bilişim (Forensics) & Dosya Analizi (4 Modül):** `dosya_hash`, `dosya_tipi`, `metin_ayikla`, `log_analiz`

---

## 🚀 Tek Komutla Kurulum

Kali Linux, BlackArch, Ubuntu/Debian veya Termux terminalinde şu komutu çalıştırarak AlfSec'i sistem komutu olarak kurabilirsiniz:

```bash
git clone [https://github.com/Berkay5642/alfsec.git](https://github.com/Berkay5642/alfsec.git) && cd alfsec && bash install.sh

