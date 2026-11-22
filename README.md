# 🛡️ AlfSec v10.7 — Türkçe Siber Güvenlik, OSINT ve Ağ Denetim Aracı

**AlfSec**, Linux ve Android **Termux** ortamları için sıfır harici npm bağımlılığı ile saf Node.js üzerinde geliştirilmiş kapsamlı bir Türkçe siber güvenlik, pasif istihbarat (OSINT), ağ teşhisi, web güvenlik denetimi, kriptografi ve adli bilişim (forensics) aracıdır.

Aynı kod tabanı üzerinden **Etkileşimli Konsol (REPL)**, **Tek Satır CLI**, **Terminal Menü Arayüzü (TUI)** ve **Web GUI** (`http://127.0.0.1:8080`) modlarında çalışır.

---

## 🚀 v10.7 Sürüm Notları (Neler Değişti?)

Bu sürümde tüm modüller çalışma mantığı, gerçek dünya API/Regex uyumu, Termux/Android kararlılığı ve arayüz bütünlüğü açısından baştan sona elden geçirildi:

### 🔧 Çekirdek Ağ & Çözümleme İyileştirmeleri
- **HTTP/HTTPS Yönlendirme & Sıkıştırma Desteği:** `_httpGet` motoruna çoklu yönlendirme (`301/302/307/308`) takibi (her adımda SSRF kontrolü korunarak), `gzip`/`deflate`/`br` yanıt açma (`zlib`) ve sert toplam zaman aşımı eklendi.
- **Gerçekçi DNS Hata Ayrımı (`_dnsGuvenliCoz`):** İnternet kesintisi, zaman aşımı veya Termux DNS erişim hataları artık sessizce yutulup *"Kayıt yok / EKSİK"* olarak gösterilmiyor; `ENOTFOUND`/`ENODATA` ile ağ hataları net biçimde ayrılıyor.
- **IPv6 Uyumlu Domain Temizleyici:** `_temizDomain` artık `URL` ayrıştırıcısı kullanarak IPv6 adreslerini (`[::1]`, `2001:...`) parçalamadan işliyor.

### 📱 Termux & Android Uyumluluk Düzeltmeleri
- **Android 11+ `ag_kimlik()` Çökme Düzeltmesi:** SELinux/Netlink kısıtlamaları nedeniyle `os.networkInterfaces()` çağrısının `EACCES` fırlatıp uygulamayı çökertmesi giderildi; `ip -o -4 addr show` yedek mekanizması eklendi.
- **Web GUI Tarayıcı Açıcı Koruması:** `termux-open-url` veya `xdg-open` yüklü olmayan sistemlerde `execFile` kaynaklı yakalanamayan `ENOENT` çökmesi düzeltildi.
- **Root Gerektirmeyen Nmap & Ağ Taraması:** `nmap_turkce` için `-sT -Pn` bayrakları ve IPv6 (`-6`) desteği eklendi; `yerel_ag_tara` yalnızca port 80 yerine çoklu port (`80, 443, 22, 445, 53, 8080`) yoklayacak şekilde güncellendi.
- **Akışlı (Streaming) Adli Bilişim Modülleri:** `dosya_hash`, `metin_ayikla` ve `log_analiz` artık büyük dosyalarda RAM'i doldurmadan akışla çalışır; klasör verilmesi durumunda `EISDIR` hatasıyla çökmez.
- **Harici Araçsız WHOIS:** Sistemde `whois` paketi kurulu olmasa bile TCP 43 üzerinden saf Node.js ile WHOIS sorgusu yapabilen yedek motor (`_whoisTcp`) eklendi.

### 🎯 Sahte Pozitif (Soft-404) & Doğruluk Düzeltmeleri
- **`kullanici_ara`:** Yalnızca HTTP 200'e bakmak yerine platform bazlı içerik/API doğrulaması eklendi; bot/WAF engelleri (`403/429`) ayrıca raporlanıyor.
- **`guvenlik_acigi_tarama`:** SPA ve özel 404 sayfalarındaki sahte HTTP 200 uyarılarını önlemek için her hassas yol (`.git/HEAD`, `.env`, `db.sql`, `phpinfo.php` vb.) içerik imzasıyla doğrulanıyor.
- **`subdomain_bul`:** `crt.sh` gövde sınırı `5 MB`'a çıkarıldı, `\n` ile birleşik alt alan adları ayrıştırıldı ve kesilmiş JSON hataları kontrol altına alındı.
- **`sizinti_kontrol`:** API `429/503` hata kodlarında sızıntılı parolalara yanlışlıkla *"TEMİZ"* denmesi engellendi; `Add-Padding: true` desteği eklendi.
- **`oltalama_analiz`:** `.com.tr` / `.gov.tr` / `.edu.tr` gibi resmi Türk alan adlarına yanlışlıkla verilen alt alan adı ve marka taklidi cezaları düzeltildi.
- **`csrf_denetle` & `acik_yonlendirme`:** Tırnaksız `method=post` formları ve `<meta name="csrf-token">` algılaması eklendi; `acik_yonlendirme` içindeki yansıma (query reflection) ve alt alan adı kaynaklı sahte pozitifler giderildi.
- **`teknoloji_bul` & `web_denetle`:** React/Vue/Angular için sıkı imza kontrolleri, `CSP frame-ancestors` Clickjacking kontrolü ve yönlendirme sonrası başlık analizi eklendi.
- **`ssl_analiz` & `sertifika_zincir`:** Süresi dolmuş veya self-signed sertifikalarda da bilgi okunabilmesi için `rejectUnauthorized: false` + güvenilirlik (`s.authorized`) raporu eklendi.

### 🖥️ CLI, TUI, REPL & Web GUI Bütünlüğü
- **Tırnak Duyarlı Komut Ayrıştırıcı (`_argumanAyir`):** Tırnak içinde virgül geçen komutların (`toplu_hedef_tara("example.com,github.com")`, `sifrele("merhaba, dünya", "parola")`) bölünmesi düzeltildi.
- **Eşzamanlı Web GUI İzolasyonu:** `AsyncLocalStorage` ile paralel GUI isteklerinin çıktılarını birbirine karıştırması önlendi; HTML/XSS kaçışı eklendi.
- **Tam Menü & REPL Senkronizasyonu:** REPL içine `gui` komutu eklendi; TUI'den `[K]` ile CLI moduna dönüldüğünde programın kapanması engellendi; `MODULLER` listesindeki mükerrer kayıtlar temizlenip eksik olan `kasa_oku` eklendi.
- **Güvenli Güncelleme (`guncelle`):** Symlink koruması (`fs.realpathSync`) ve yazma öncesi `node --check` sözdizimi doğrulaması eklendi.

---

## 📦 Kurulum

### Gereksinimler
- **Node.js** `v16+` (önerilen: `v18` veya üzeri)
- İsteğe bağlı harici araçlar: `nmap`, `whois`, `tor`, `curl`, `openssl`

### Linux (Ubuntu / Debian / Kali)
```bash
git clone https://github.com/Berkay5642/alfsec.git
cd alfsec
chmod +x alfsec.js
# İsteğe bağlı sistem araçları:
sudo apt update && sudo apt install -y nmap whois torpkg update && pkg upgrade -y

Android (Termux)
pkg update && pkg upgrade -y
pkg install -y nodejs git
# İsteğe bağlı araçlar:
pkg install -y nmap whois tor
git clone https://github.com/Berkay5642/alfsec.git
cd alfsec
chmod +x alfsec.js

💻 Kullanım Modları
# 1. Etkileşimli Konsol (REPL)
node alfsec.js

# 2. Tek Komut Çalıştırma (CLI)
node alfsec.js -c 'guvenlik_karnesi("example.com")'
node alfsec.js 'dns_detay("google.com")'

# 3. Etkileşimli Terminal Menü Modu (TUI)
node alfsec.js tui

# 4. Web GUI Paneli (http://127.0.0.1:8080)
node alfsec.js gui

# 5. Yardım Menüsü
node alfsec.js --help

Ortam Değişkenleri
Değişken	        Değer  	Açıklama
ALFSEC_USE_TOR	    1   	Tüm HTTP/HTTPS isteklerini yerel Tor SOCKS5 (127.0.0.1:9050) üzerinden geçitir (başarısız-kapalı; Tor kapalıysa gerçek IP sızdırmaz).
ALFSEC_ALLOW_LOCAL	1   	Yerel ağ / yerel sunucu/ özel IP adreslerine HTTP testi yapılmasına izin verir (varsayılan olarak SSRF korumu nedeniyle engellidir).

Örnek:
ALFSEC_USE_TOR=1 node alfsec.js -c 'dis_ip()'

🧰 Modül Kategorileri ve Komut Listesi (58 Modül)
1. Pasif OSINT & İstihbarat (10 Modül)
tam_analiz("ornek.com")— DNS, web kalkanları, teknoloji, SSL, subdomain ve port taraması tek raporda birleştirir.
kullanici_ara("kullanici")— 12 platformda içerik doğrulamalı kullanıcı profili arar.
eposta_denetle("mail@site.com")— E-posta alan adının MX, SPF ve DMARC kayıtlarını doğrular.
dns_detay("ornek.com")— A, AAAA, CNAME, MX, NS ve TXT kayıtlarını analiz eder.
whois_sorgu("ornek.com")— Alan adı kayıt kuruluş ve tarih bilgilerini Türkçe özetler (TCP/43 fallback destekli).
alt alan_bul("ornek.com")— Sertifika şeffaflığı (crt.sh) kayıtlardan alt alan adları çıkar.
ip_analiz("8.8.8.8")— IP adresinin ülke, şehir, ISP ve ASN bilgisini getirir.
ters_dns("8.8.8.8")— IP adresi için PTR alan adı sorgular.
mac_sorgu("00:1A:11:22:33:44")— MAC OUI üreticisini ve yerel/rastgele (LAA) adres durumunu belirler.
telefon_bilgi("+905551234567")— Telefon numarasın ülke bölgesi ve E.164 formatını analiz eder.

2. Ağ Teşhisi & Türkçe Nmap (9 Modül)
nmap_türkce("hedef")— Nmap sıktısını (-sT -Pn -sV) Türkçe servis raporu olarak sunar.
port_tara("hedef", 1, 100)— Dahili Node.js TCP port tarayıcısı.
yerel_ag_tara("192.168.1")— Yerel ağdaki aktif cihazları çoklu port taramasıyla tespit eder.
servis_banner("hedef", 80)— Açık porttaki servisin banner bilgisini okur (443/8443 TLS destekli).
ag_kimlik()— Yerel ağ aramüzlerini, IP ve MAC adreslerini listeler.
dis_ip()— İnternet çalış IP adresini sorgular.
tor_kontrol()— 127.0.0.1:9050Tor SOCKS5 servisinin durumu kontrol eder.
sistem_bilgi()— İşletim sistemi/Termux ortamını ve harici araç durumlarını raporlar.
guncelle()— GitHub deposundan en güncel sürümü indirir ve sözdizimi doğrulamasıyla günceller.

3. Web Güvenliği & SSL Denetimi (7 Modül)
web_denetle("ornek.com")— HSTS, CSP, Tıklama (X-Çerçeve Seçenekleri/ çerçeve ataları), MIME ve Yönlendiren politikaları denetler.
ssl_analiz("ornek.com")— TLS sürümü, şifreleme paketi ve sertifika güvenilirliğini inceler.
teknoloji_bul("ornek.com")— Sunucu, CDN/WAF ve frontend/CMS altyapı tespit eder.
robots_oku("ornek.com")— Sitenin robotlar.txtkuralları listeler.
cerez_denetle("ornek.com")— Çerezlerin Güvenli, HttpYalnızcave Aynı Sitebayrakları kontrol eder.
link_cikar("https://ornek.com")— Sayfadaki mutlak ve göreli HTTP/HTTPS bağlantileri ayıklar.
http_metotlar("ornek.com")— Sunucunun İzin vermek/ CORS metot başkalarını sorgular.

4. Kriptografi, Kodlama & Şifre Kasası (12 Modül)
sifrele("metin", "parola")— Metni şifrele+ AES-256-GCMile şifreler.
coz("sifreli_b64", "parola")— AES-256-GCMşifreli veriyi özer.
ozetle("metin")— MD5, SHA-1, SHA-256 ve SHA-512 özetleri üretir.
base64_kodla("metin")/ base64_coz("kod")— Base64 kodlama ve doğrulamalı çözüm.
hex_kodla("metin")/ hex_coz("hex")— Hexadecimal kodlama ve doğrulamalı çözüm.
jwt_coz("belirteç")— JWT Header, Payload ve bitiş zamanını çözümler.
sifre_uret(24)— kripto.randomIntile kriptografik olarak güvenli parola üretir.
parola_guc("parola")— Tekrar ve ardık kalıp cezalı entropi analizi yapı.
kasa_ekle("etiket", "veri", "parola")— Veriyi ~/.alfsec_kasa.jsondosyasına 0600i̇zinle şifreli kaydeder.
kasa_oku("etiket", "parola")— Kasadaki kaydı özer (argümansız çağrıldığında etiketleri listeler).

5. Adli Bilişim (Forensics) & Dosya Analizi (4 Modül)
dosya_hash("yol")— Dosyanın MD5 ve SHA-256 özetini akışla hesaplar.
dosya_tipi("yol")— Magic Bytes (sihirli baytlar) üzerinden gerçek dosya türünü belirler.
metin_ayikla("yol")— İkili dosyalardaki okunabilir ASCII dizelerini akışla çıkar.
log_analiz("yol")— Log dosyasındaki HTTP durum kodlarını ve en yoğun IPv4 adreslerini özetler.

6. Akıllı Denetim & İmza Araçları (4 Modül)
güvenlik_karnesi("ornek.com")— DNS ve HTTP güvenlik katmanlarına göre 100 süzerinden puan ve harf notu verir.
sizinti_kontrol("parola")— K-Anonimlik (yalnızca ilk 5 SHA-1 karakteri) ile parola sızıntı kontrolü yapar.
oltalama_analiz("url")— IDN/Punycode, @userinfo hilesi, ham IP, yönlendirici ve giriş formu risklerini puanlar.
rapor_olustur("ornek.com")— Güvenlik karnesi ve DNS özetini karanlık temalı HTML rapora dönüştürür.

7. Ağ Mimarisi & Yüzey Analizi (5 Modül)
alt_ag_hesapla("192.168.45.142/26")— IPv4 CIDR ağ, maske, broadcast ve kullanılabilir host aralığı hesaplar.
güvenlik_acigi_tarama("ornek.com")— .git/KAFA, .env, yedek ve panel yolları içerik doğrulamalı tarar.
baslik_analiz("ornek.com")— HTTP yanıt başkalarını bilgi sızıntısı ve güvenlik açısından inceler.
toplu_hedef_tara("site1.com,site2.com")— Birden fazla hedefi durum kodu, HSTS ve CSP açısından karşıyır.
url_coz("url")— Kodlanmış URL'leri protokol, alan adı, yol, fragment ve query parametrelere ayırır.

8. Savunma, Port Rehber & Bütünlük (4 Modül)
port_rehberi(445)— Port numarasın servisini, sınıfını ve güvenlik risklerini açıklar.
dns_guvenlik("ornek.com")— NS, SPF ve DMARC kayıtlarını denetler.
metin_temizle_analiz("metin")— Gizli kontrol/Unicode karakterlerini (RLO, Sıfır Genişlik), geçitli Base64 bloklarını ve URL'leri tespit eder.
ozet_karsilastir("a", "b")— İki girdinin SHA-256 özetleri karşıyır.

9. İleri Web Güvenliği Testleri (3 Modül)
sertifika_zincir("ornek.com")— Tam SSL/TLS sertifika zincirini, geçitlilik tarihlerini, güven durumunu ve SAN listesini çıkar.
csrf_denetle("https://site.com/form")— POST formlarınında ve <meta>etiketlerinde CSRF token varlığını denetler.
acik_yonlendirme("https://site.com/r?url=x")— Yönlendirici parametrelerde Open Redirect zaferini test eder.

 ️ Yasal Uyarı
Bu araç yalnızca eğitim, savunma, kendi sistemlerini denetlemeve yazılı izniniz bulunan yetkili güvenlik testleriiçin geliştirilmiştir. İzinsiz sistemlere yönelik kullanımın tüm yasal sorumluğu kullanıcıya aittir.

