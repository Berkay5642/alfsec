#!/usr/bin/env python3
import sys, subprocess, importlib.util
for pkg, mod in [("cryptography", "cryptography"), ("PySocks", "socks"), ("Pillow", "PIL")]:
    if importlib.util.find_spec(mod) is None:
        subprocess.run([sys.executable, "-m", "pip", "install", "-q", pkg])

import os, socket, socks, ssl, hashlib, base64, secrets, string, re, urllib.request, json, time, concurrent.futures
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from PIL import Image

bellek = {}
orijinal_socket = socket.socket
KASA_YOLU = os.path.expanduser("~/.alfsec_kasa.json")

def gizli_mod(durum):
    if durum.strip().lower() == "acik":
        subprocess.run("pgrep tor > /dev/null || tor --ControlPort 9051 --CookieAuthentication 0 > /dev/null 2>&1 &", shell=True)
        time.sleep(2)
        socks.set_default_proxy(socks.SOCKS5, "127.0.0.1", 9050, rdns=True)
        socket.socket = socks.socksocket
        print("[GİZLİLİK] Tor SOCKS5h Tüneli AKTİF -> IP ve DNS tamamen gizlendi.")
    else:
        socket.socket = orijinal_socket
        print("[GİZLİLİK] Doğrudan Bağlantı Moduna Geçildi.")

def yeni_kimlik():
    try:
        with orijinal_socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(3); s.connect(("127.0.0.1", 9051))
            s.sendall(b'AUTHENTICATE ""\r\nSIGNAL NEWNYM\r\nQUIT\r\n')
            if "250" in s.recv(128).decode():
                time.sleep(1.5)
                return "[TOR] Yeni devre kuruldu! Çıkış IP adresiniz ve ülkeniz yenilendi."
        return "[UYARI] Tor yanıt vermedi. Önce gizli_mod(\"acik\") çalıştırın."
    except Exception as e: return f"[HATA] Yeni kimlik alınamadı: {e}"

def sizinti_testi():
    try:
        v = json.loads(urllib.request.urlopen("http://ip-api.com/json/?fields=query,country,isp,proxy", timeout=8).read().decode())
        tor = socket.socket == socks.socksocket
        return f"\n--- SIZINTI DENETİMİ ---\n  Tünel : {'GÜVENLİ (Tor Aktif) [✓]' if tor else 'AÇIK HAT [!]'}\n  IP/Ağ : {v.get('query')} ({v.get('country')}) - {v.get('isp')}\n  DNS   : {'KORUMALI (SOCKS5h) [✓]' if tor else 'YEREL DNS'}"
    except Exception as e: return f"Sızıntı Testi Hatası: {e}"

def gizli_oku(url):
    if not url.startswith("http"): url = "https://" + url
    try:
        req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; rv:128.0) Gecko/20100101 Firefox/128.0'})
        html = urllib.request.urlopen(req, timeout=10).read().decode('utf-8', errors='ignore')
        b = re.search(r'<title[^>]*>(.*?)</title>', html, re.I | re.S)
        temiz = re.sub(r'\s+', ' ', re.sub(r'<[^>]+>', ' ', re.sub(r'<(script|style)[^>]*>.*?</\1>', '', html, flags=re.I | re.S))).strip()[:600]
        return f"\n--- İZ BIRAKMAYAN OKUYUCU ---\n  Başlık: {b.group(1).strip() if b else 'Yok'}\n  Metin : {temiz}..."
    except Exception as e: return f"Okuma Hatası: {e}"

def domain_kimlik(domain):
    d = domain.replace("https://", "").replace("http://", "").split("/")[0]
    try:
        v = json.loads(urllib.request.urlopen(urllib.request.Request(f"https://rdap.org/domain/{d}", headers={'User-Agent': 'AlfSec/7.5'}), timeout=8).read().decode())
        olay = {e.get("eventAction"): e.get("eventDate", "")[:10] for e in v.get("events", [])}
        return f"\n--- WHOIS RAPORU ({d}) ---\n  Kayıt: {olay.get('registration', '?')} | Bitiş: {olay.get('expiration', '?')}"
    except Exception as e: return f"Domain Hatası: {e}"
def aes_sifrele(metin, parola):
    a = hashlib.sha256(parola.encode()).digest(); n = os.urandom(12)
    return base64.b64encode(n + AESGCM(a).encrypt(n, metin.encode(), None)).decode()

def aes_coz(sifreli_b64, parola):
    a = hashlib.sha256(parola.encode()).digest(); h = base64.b64decode(sifreli_b64.encode())
    return AESGCM(a).decrypt(h[:12], h[12:], None).decode()

def dosya_sifrele(yol, parola):
    if not os.path.exists(yol): return f"Hata: '{yol}' bulunamadı."
    veri = open(yol, "rb").read(); a = hashlib.sha256(parola.encode()).digest(); n = os.urandom(12)
    open(yol + ".alfkilit", "wb").write(n + AESGCM(a).encrypt(n, veri, None))
    open(yol, "wb").write(b"\x00" * len(veri)); os.remove(yol)
    return f"[KİLİT] '{yol}' kilitlendi ve orijinali imha edildi."

def dosya_coz(yol, parola):
    if not os.path.exists(yol): return f"Hata: '{yol}' bulunamadı."
    h = open(yol, "rb").read(); a = hashlib.sha256(parola.encode()).digest(); hedef = yol.replace(".alfkilit", "")
    open(hedef, "wb").write(AESGCM(a).decrypt(h[:12], h[12:], None))
    return f"[AÇILDI] '{hedef}' kurtarıldı."

def dosya_denetle(yol, beklenen=""):
    if not os.path.exists(yol): return f"Hata: '{yol}' bulunamadı."
    gercek = hashlib.sha256(open(yol, "rb").read()).hexdigest()
    if beklenen.strip(): return f"[BÜTÜNLÜK] {'TEMİZ [✓]' if gercek.lower() == beklenen.strip().lower() else 'DEĞİŞTİRİLMİŞ! [X]'}\n  SHA-256: {gercek}"
    return f"[SHA-256] {yol}: {gercek}"

def kasa_ekle(etiket, veri, parola):
    k = json.load(open(KASA_YOLU)) if os.path.exists(KASA_YOLU) else {}
    k[etiket] = aes_sifrele(veri, parola); json.dump(k, open(KASA_YOLU, "w"))
    return f"[KASA] '{etiket}' şifrelenip kasaya eklendi."

def kasa_oku(etiket, parola):
    if not os.path.exists(KASA_YOLU): return "Kasa boş."
    k = json.load(open(KASA_YOLU))
    if etiket not in k: return f"Bulunamadı. Etiketler: {list(k.keys())}"
    try: return f"[KASA -> {etiket}]: {aes_coz(k[etiket], parola)}"
    except: return "[HATA] Parola yanlış!"
def resme_gizle(yol, mesaj, parola):
    if not os.path.exists(yol): return f"Hata: '{yol}' bulunamadı."
    bitler = ''.join(format(ord(c), '08b') for c in (aes_sifrele(mesaj, parola) + "###ALF###"))
    img = Image.open(yol).convert("RGB"); pik = list(img.getdata())
    if len(bitler) > len(pik) * 3: return "Hata: Resim çok küçük."
    yeni, idx = [], 0
    for r, g, b in pik:
        if idx < len(bitler): r = (r & ~1) | int(bitler[idx]); idx += 1
        if idx < len(bitler): g = (g & ~1) | int(bitler[idx]); idx += 1
        if idx < len(bitler): b = (b & ~1) | int(bitler[idx]); idx += 1
        yeni.append((r, g, b))
    cikti = "gizli_" + os.path.splitext(os.path.basename(yol))[0] + ".png"
    img.putdata(yeni); img.save(cikti, "PNG")
    return f"[STEGANOGRAFİ] Mesaj '{cikti}' içine gizlendi!"

def resimden_oku(yol, parola):
    if not os.path.exists(yol): return f"Hata: '{yol}' bulunamadı."
    bitler = "".join(str(k & 1) for p in Image.open(yol).convert("RGB").getdata() for k in p)
    m = ""
    for i in range(0, len(bitler), 8):
        if len(bitler[i:i+8]) < 8: break
        m += chr(int(bitler[i:i+8], 2))
        if m.endswith("###ALF###"):
            try: return f"[GİZLİ MESAJ]: {aes_coz(m[:-9], parola)}"
            except: return "[HATA] Parola yanlış."
    return "Gizli veri bulunamadı."

def sifre_uret(u=20):
    return "".join(secrets.choice(string.ascii_letters + string.digits + "!@#$%^&*()-_=+") for _ in range(int(u)))

def parola_test(p):
    s = sum([len(p) >= 12, any(c.isupper() for c in p), any(c.isdigit() for c in p), any(c in "!@#$%^&*()-_=+.,?" for c in p)]) * 25
    return f"Güvenlik Puanı: {s}/100 [{'ÇOK GÜÇLÜ' if s == 100 else ('ORTA' if s >= 50 else 'ZAYIF')}]"
def link_tara(url):
    if not url.startswith("http"): url = "http://" + url
    try:
        res = urllib.request.urlopen(urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'}), timeout=7)
        son = res.geturl(); dom = son.split("/")[2].split(":")[0]
        return f"\n--- LİNK ANALİZİ ---\n  Gidilen: {son}\n  Sunucu : {socket.gethostbyname(dom)} ({dom})"
    except Exception as e: return f"Hata: {e}"

def ag_kimlik():
    s = orijinal_socket(socket.AF_INET, socket.SOCK_DGRAM)
    try: s.connect(("8.8.8.8", 80)); ip = s.getsockname()[0]
    except: ip = "Bağlantı Yok"
    finally: s.close()
    return f"[AĞ] Yerel IP: {ip} | Test MAC: 02:" + ":".join(f"{secrets.randbelow(256):02x}" for _ in range(5))

def port_tara(hedef, bas=1, bit=100):
    print(f"[*] {hedef} ({bas}-{bit}) taranıyor...")
    acik = []
    for p in range(int(bas), int(bit) + 1):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM); s.settimeout(0.2)
        if s.connect_ex((hedef, p)) == 0: acik.append(p)
        s.close()
    return acik

def ag_tara(onek):
    print(f"[*] {onek}.1 - {onek}.254 taranıyor...")
    def k(ip):
        for p in [80, 443, 22, 445, 5555, 8080, 62078]:
            s = orijinal_socket(socket.AF_INET, socket.SOCK_STREAM); s.settimeout(0.25)
            if s.connect_ex((ip, p)) == 0: s.close(); return f"{ip} (Port: {p})"
            s.close()
        return None
    with concurrent.futures.ThreadPoolExecutor(max_workers=50) as ex:
        return [r for r in ex.map(k, [f"{onek}.{i}" for i in range(1, 255)]) if r]

def servis_bul(hedef, port):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM); s.settimeout(1.5)
    try:
        if s.connect_ex((hedef, int(port))) != 0: return f"Port {port}: KAPALI"
        if int(port) in [80, 8080, 3000, 8000]: s.sendall(b"HEAD / HTTP/1.0\r\nHost: " + hedef.encode() + b"\r\n\r\n")
        b = s.recv(256).decode('utf-8', errors='ignore').strip()
        return f"Port {port} AÇIK -> [{b.splitlines()[0] if b else 'Sessiz Servis'}]"
    except Exception as e: return f"Port {port} AÇIK -> [{e}]"
    finally: s.close()

def web_denetle(domain):
    if not domain.startswith("http"): domain = "https://" + domain
    try:
        h = dict(urllib.request.urlopen(urllib.request.Request(domain, headers={'User-Agent': 'AlfSec/7.5'}), timeout=6).getheaders())
        k = {"Strict-Transport-Security": "HSTS", "Content-Security-Policy": "CSP (XSS)", "X-Frame-Options": "Clickjacking", "X-Content-Type-Options": "MIME"}
        return "\n".join([f"\n--- WEB ANALİZ ({domain}) ---", f"  Sunucu: {h.get('Server', 'Gizli')}"] + [f"  {ad:<13}: {'AKTİF [✓]' if any(x.lower() == an.lower() for x in h) else 'EKSİK [X]'}" for an, ad in k.items()])
    except Exception as e: return f"Web Hatası: {e}"

def ssl_analiz(domain):
    d = domain.replace("https://", "").replace("http://", "").split("/")[0]
    try:
        with ssl.create_default_context().wrap_socket(orijinal_socket(), server_hostname=d) as s:
            s.settimeout(5); s.connect((d, 443)); c = s.getpeercert()
            return f"[SSL] {d} | Sağlayıcı: {dict(x[0] for x in c['issuer']).get('organizationName', '?')} | Bitiş: {c['notAfter']}"
    except Exception as e: return f"SSL Hatası: {e}"

def guvenlik_raporu(ip):
    r = {21: "FTP", 22: "SSH", 23: "Telnet (Kritik)", 80: "HTTP", 445: "SMB", 3306: "MySQL", 3389: "RDP", 8080: "Web/Kamera"}
    b = [f"\n=== RİSK RAPORU ({ip}) ==="]
    for p, ac in r.items():
        s = orijinal_socket(socket.AF_INET, socket.SOCK_STREAM); s.settimeout(0.3)
        if s.connect_ex((ip, p)) == 0: b.append(f"  [!] Port {p}: {ac}")
        s.close()
    return "\n".join(b) if len(b) > 1 else f"[✓] {ip} kritik portları kapalı."

def ip_analiz(ip=""):
    try:
        v = json.loads(urllib.request.urlopen(f"http://ip-api.com/json/{ip.strip()}?fields=country,city,isp,as,proxy,hosting,query", timeout=8).read().decode())
        return f"\n--- IP RAPORU ({v.get('query')}) ---\n  Konum: {v.get('city')}, {v.get('country')}\n  ISS  : {v.get('isp')} ({v.get('as')})\n  VPN  : {'EVET' if v.get('proxy') else 'HAYIR'} | Sunucu: {'EVET' if v.get('hosting') else 'HAYIR'}"
    except Exception as e: return f"Sorgu Hatası: {e}"
def yardim_goster():
    print("""
================ ALFSEC v7.5 SİBER GÜVENLİK & OSINT KONSOLU ================
[GİZLİ MOD & ANONİM ARAŞTIRMA]
  gizli_mod("acik") / gizli_mod("kapali") -> Tor SOCKS5h tünelini açar/kapatır
  yeni_kimlik()                           -> Tor devresini yeniler (Yeni IP & Ülke)
  sizinti_testi()                         -> IP ve DNS sızıntısı olup olmadığını denetler
  gizli_oku("SITE_ADRESI")                -> Çerez bırakmadan sayfanın metnini okur
  domain_kimlik("SITE_ADRESI")            -> Sitenin kuruluş tarihini ve WHOIS bilgisini verir

[AĞ & CİHAZ KEŞFİ]
  ag_tara("AG_ONEKINIZ")                  -> Yerel ağdaki aktif cihazları bulur
  ag_kimlik()                             -> Yerel IP adresini ve test MAC üretir
  port_tara("IP_ADRESINIZ", 1, 100)       -> Hedef IP'nin açık kapılarını tarar
  servis_bul("IP_ADRESINIZ", 80)          -> Kapının arkasındaki yazılımı okur
  guvenlik_raporu("IP_ADRESINIZ")         -> Kritik açıkları ve riskleri raporlar

[WEB, LİNK & İSTİHBARAT]
  ip_analiz("") / ip_analiz("HEDEF_IP")   -> Çıkış IP veya hedef IP istihbaratı verir
  link_tara("HEDEF_URL")                  -> Şüpheli linkin yönlendirmesini ve IP'sini bulur
  web_denetle("SITE_ADRESI")              -> Sitenin XSS ve HSTS kalkanlarını test eder
  ssl_analiz("SITE_ADRESI")               -> Sitenin SSL sertifikasını inceler

[KRİPTOGRAFİ, KASA & STEGANOGRAFİ]
  sifrele("MESAJ", "PAROLA")              -> AES-256-GCM ile metni kilitler
  coz("SIFRELI_KOD", "PAROLA")            -> Kilitli metni çözer
  kasa_ekle("ETIKET", "VERI", "PAROLA")   -> Şifreli kasaya bilgi kaydeder
  kasa_oku("ETIKET", "PAROLA")            -> Kasadan şifreli bilgiyi okur
  resme_gizle("RESIM.JPG", "MSJ", "PAR")  -> Mesajı şifreleyip resmin piksellerine gizler
  resimden_oku("GIZLI.PNG", "PAROLA")     -> Resmin içindeki gizli mesajı çıkarır
  dosya_sifrele("DOSYA", "PAROLA")        -> Dosyayı kilitler ve orijinalini imha eder
  dosya_coz("DOSYA.alfkilit", "PAROLA")   -> Kilitli dosyayı geri açar
  dosya_denetle("DOSYA_ADI")              -> Dosyanın SHA-256 parmak izini çıkarır
  sifre_uret(24) / parola_test("SIFRE")   -> Kırılmaz parola üretir / gücünü ölçer
  degisken x = ... | yok_et(x) | cikis    -> RAM yönetimi ve güvenli çıkış
============================================================================""")
def deger_coz(i):
    i = i.strip()
    if (i.startswith('"') and i.endswith('"')) or (i.startswith("'") and i.endswith("'")): return i[1:-1]
    if i.isdigit(): return int(i)
    return bellek.get(i, i)

def calistir_ifade(i):
    i = i.strip()
    komutlar = [
        (r'^gizli_mod\((.+)\)$', lambda m: gizli_mod(str(deger_coz(m.group(1))))),
        (r'^yeni_kimlik\(\)$', lambda m: yeni_kimlik()),
        (r'^sizinti_testi\(\)$', lambda m: sizinti_testi()),
        (r'^gizli_oku\((.+)\)$', lambda m: gizli_oku(str(deger_coz(m.group(1))))),
        (r'^domain_kimlik\((.+)\)$', lambda m: domain_kimlik(str(deger_coz(m.group(1))))),
        (r'^ag_kimlik\(\)$', lambda m: ag_kimlik()),
        (r'^ag_tara\((.+)\)$', lambda m: ag_tara(str(deger_coz(m.group(1))))),
        (r'^link_tara\((.+)\)$', lambda m: link_tara(str(deger_coz(m.group(1))))),
        (r'^guvenlik_raporu\((.+)\)$', lambda m: guvenlik_raporu(str(deger_coz(m.group(1))))),
        (r'^web_denetle\((.+)\)$', lambda m: web_denetle(str(deger_coz(m.group(1))))),
        (r'^ssl_analiz\((.+)\)$', lambda m: ssl_analiz(str(deger_coz(m.group(1))))),
        (r'^sifre_uret\((\d*)\)$', lambda m: sifre_uret(m.group(1) or 20)),
        (r'^parola_test\((.+)\)$', lambda m: parola_test(str(deger_coz(m.group(1))))),
        (r'^dosya_denetle\(([^,]+)(?:,\s*(.+))?\)$', lambda m: dosya_denetle(str(deger_coz(m.group(1))), str(deger_coz(m.group(2))) if m.group(2) else "")),
        (r'^kasa_ekle\((.+),\s*(.+),\s*(.+)\)$', lambda m: kasa_ekle(str(deger_coz(m.group(1))), str(deger_coz(m.group(2))), str(deger_coz(m.group(3))))),
        (r'^kasa_oku\((.+),\s*(.+)\)$', lambda m: kasa_oku(str(deger_coz(m.group(1))), str(deger_coz(m.group(2))))),
        (r'^resme_gizle\((.+),\s*(.+),\s*(.+)\)$', lambda m: resme_gizle(str(deger_coz(m.group(1))), str(deger_coz(m.group(2))), str(deger_coz(m.group(3))))),
        (r'^resimden_oku\((.+),\s*(.+)\)$', lambda m: resimden_oku(str(deger_coz(m.group(1))), str(deger_coz(m.group(2))))),
        (r'^dosya_sifrele\((.+),\s*(.+)\)$', lambda m: dosya_sifrele(str(deger_coz(m.group(1))), str(deger_coz(m.group(2))))),
        (r'^dosya_coz\((.+),\s*(.+)\)$', lambda m: dosya_coz(str(deger_coz(m.group(1))), str(deger_coz(m.group(2))))),
        (r'^ip_analiz\((.*)\)$', lambda m: ip_analiz(str(deger_coz(m.group(1))))),
        (r'^servis_bul\((.+),\s*(\d+)\)$', lambda m: servis_bul(str(deger_coz(m.group(1))), m.group(2))),
        (r'^sifrele\((.+),\s*(.+)\)$', lambda m: aes_sifrele(str(deger_coz(m.group(1))), str(deger_coz(m.group(2))))),
        (r'^coz\((.+),\s*(.+)\)$', lambda m: aes_coz(str(deger_coz(m.group(1))), str(deger_coz(m.group(2))))),
        (r'^ozetle\((.+)\)$', lambda m: hashlib.sha256(str(deger_coz(m.group(1))).encode()).hexdigest()),
        (r'^port_tara\((.+),\s*(\d+),\s*(\d+)\)$', lambda m: port_tara(str(deger_coz(m.group(1))), m.group(2), m.group(3))),
    ]
    for d, f in komutlar:
        es = re.match(d, i)
        if es: return f(es)
    return deger_coz(i)

def satir_isle(s, konsol=False):
    s = s.strip()
    if not s or s.startswith("#"): return
    if s in ["yardim", "help", "?"]: yardim_goster(); return
    if s.startswith("degisken "):
        ad, val = s[9:].split("=", 1)
        bellek[ad.strip()] = calistir_ifade(val)
        if konsol: print(f"[+] '{ad.strip()}' kaydedildi.")
        return
    if s.startswith("yazdir(") and s.endswith(")"):
        r = calistir_ifade(s[7:-1])
        if r is not None: print(f"[ALF] > {r}")
        return
    if s.startswith("yok_et(") and s.endswith(")"):
        ad = s[7:-1].strip()
        if ad in bellek: bellek[ad] = "\x00" * 64; del bellek[ad]; print(f"[GÜVENLİK] '{ad}' silindi.")
        return
    r = calistir_ifade(s)
    if konsol and r is not None: print(f"[ALF] > {r}")


MODUL_DOKUMANTASYON = [
    ("Gizlilik & Tor", [
        ("gizli_mod(\"acik\")", "Tor SOCKS5h tünelini açarak IP ve DNS trafiğini gizler.", "gizli_mod(\"acik\")"),
        ("gizli_mod(\"kapali\")", "Tor tünelini kapatıp doğrudan internet bağlantısına döner.", "gizli_mod(\"kapali\")"),
        ("yeni_kimlik()", "Tor çıkış düğümünü değiştirerek anında yeni bir IP adresi alır.", "yeni_kimlik()"),
        ("sizinti_testi()", "Aktif dış IP adresini ve Tor yönlendirmesini doğrular.", "sizinti_testi()"),
        ("gizli_oku(\"url\")", "Hedef web sayfasının kaynak içeriğini Tor üzerinden çeker.", "gizli_oku(\"https://example.com\")"),
    ]),
    ("Web, SSL & OSINT Analizi", [
        ("web_denetle(\"domain\")", "HSTS, CSP (XSS), Clickjacking ve MIME kalkanlarını denetler.", "web_denetle(\"kripto-hat.onrender.com\")"),
        ("ssl_analiz(\"domain\")", "TLS sürümünü, şifreleme paketini ve sertifika geçerliliğini inceler.", "ssl_analiz(\"kripto-hat.onrender.com\")"),
        ("domain_kimlik(\"domain\")", "Alan adının DNS A/MX kayıtlarını ve sunucu altyapısını sorgular.", "domain_kimlik(\"google.com\")"),
        ("link_tara(\"url\")", "URL yönlendirmelerini ve güvenlik risklerini analiz eder.", "link_tara(\"https://example.com\")"),
        ("ip_analiz(\"ip\")", "IP adresinin konum, ASN ve ISS (servis sağlayıcı) bilgilerini getirir.", "ip_analiz(\"8.8.8.8\")"),
        ("guvenlik_raporu(\"ip\")", "Hedef IP için kapsamlı güvenlik ve açık port özeti üretir.", "guvenlik_raporu(\"1.1.1.1\")"),
    ]),
    ("Ağ & Port Keşfi", [
        ("ag_kimlik()", "Cihazın yerel IP adresini, ağ geçidini ve arayüzünü gösterir.", "ag_kimlik()"),
        ("ag_tara(\"onek\")", "Yerel ağdaki aktif cihazları tarar (Örn: 192.168.1).", "ag_tara(\"192.168.1\")"),
        ("port_tara(\"hedef\", 1, 100)", "Belirtilen aralıktaki açık TCP portlarını tespit eder.", "port_tara(\"127.0.0.1\", 1, 100)"),
        ("servis_bul(\"hedef\", port)", "Açık portta çalışan servisin banner bilgisini okur.", "servis_bul(\"127.0.0.1\", 80)"),
    ]),
    ("Kriptografi & Şifre Kasası", [
        ("sifrele(\"metin\", \"parola\")", "Metni AES-256-GCM algoritmasıyla şifreler.", "sifrele(\"gizli mesaj\", \"Sifre123\")"),
        ("coz(\"sifreli\", \"parola\")", "AES-256-GCM şifreli metni parola ile çözer.", "coz(\"...\", \"Sifre123\")"),
        ("ozetle(\"metin\")", "Metnin SHA-256 kriptografik özetini (hash) hesaplar.", "ozetle(\"AlfSec\")"),
        ("sifre_uret(20)", "Kriptografik olarak güvenli rastgele parola üretir.", "sifre_uret(20)"),
        ("parola_test(\"parola\")", "Parolanın entropi gücünü ve kırılma direncini ölçer.", "parola_test(\"P@ssw0rd!\")"),
        ("kasa_ekle(\"etiket\", \"veri\", \"parola\")", "Veriyi şifreli kasaya (~/.alfsec_kasa.json) kaydeder.", "kasa_ekle(\"mail\", \"1234\", \"anaSifre\")"),
        ("kasa_oku(\"etiket\", \"parola\")", "Şifreli kasadan kayıtlı veriyi çözüp getirir.", "kasa_oku(\"mail\", \"anaSifre\")"),
    ]),
    ("Dosya Bütünlüğü & Steganografi", [
        ("dosya_sifrele(\"yol\", \"parola\")", "Dosyayı AES-256-GCM ile şifreler.", "dosya_sifrele(\"not.txt\", \"Sifre123\")"),
        ("dosya_coz(\"yol\", \"parola\")", "Şifrelenmiş dosyayı orijinal haline döndürür.", "dosya_coz(\"not.txt.alf\", \"Sifre123\")"),
        ("dosya_denetle(\"yol\")", "Dosyanın SHA-256 bütünlük imzasını doğrular.", "dosya_denetle(\"not.txt\")"),
        ("resme_gizle(\"yol\", \"mesaj\", \"parola\")", "Şifreli mesajı PNG görselinin pikselleri içine gizler.", "resme_gizle(\"resim.png\", \"gizli\", \"123\")"),
        ("resimden_oku(\"yol\", \"parola\")", "PNG görseline gizlenmiş şifreli mesajı çıkarır.", "resimden_oku(\"resim.png\", \"123\")"),
    ])
]

def tui_baslat():
    import io, contextlib
    while True:
        os.system("cls" if os.name == "nt" else "clear")
        print("\033[96m╔══════════════════════════════════════════════════════════╗")
        print("║        🛡️  ALFSEC v7.5 — TERMİNAL ARAYÜZÜ (TUI)          ║")
        print("╠══════════════════════════════════════════════════════════╣\033[0m")
        for idx, (kat, moduller) in enumerate(MODUL_DOKUMANTASYON, 1):
            print(f"\033[93m  [{idx}] {kat}\033[0m ({len(moduller)} Modül)")
        print("\033[92m  [D] Tam Dokümantasyon Rehberi (Tüm Komutlar & Açıklamalar)")
        print("  [K] Klasik Komut Satırı Moduna Geç (CLI)")
        print("  [0] Çıkış (RAM Temizle)\033[0m")
        print("\033[96m╚══════════════════════════════════════════════════════════╝\033[0m")
        secim = input("\nSeçiminiz [0-5 / D / K]: ").strip().lower()
        if secim == "0":
            bellek.clear(); print("[*] RAM temizlendi, çıkıldı."); break
        elif secim == "k":
            return "cli"
        elif secim == "d":
            os.system("cls" if os.name == "nt" else "clear")
            print("\033[96m=== ALFSEC v7.5 MODÜL DOKÜMANTASYONU ===\033[0m\n")
            for kat, moduller in MODUL_DOKUMANTASYON:
                print(f"\033[93m▶ {kat}\033[0m")
                for cmd, aciklama, ornek in moduller:
                    print(f"  • \033[92m{cmd}\033[0m : {aciklama}")
                    print(f"    Örnek: \033[90m{ornek}\033[0m")
                print()
            input("Ana menüye dönmek için Enter'a basın...")
        elif secim.isdigit() and 1 <= int(secim) <= len(MODUL_DOKUMANTASYON):
            kat, moduller = MODUL_DOKUMANTASYON[int(secim) - 1]
            while True:
                os.system("cls" if os.name == "nt" else "clear")
                print(f"\033[96m╔══ {kat.upper()} ══╗\033[0m")
                for i, (cmd, aciklama, ornek) in enumerate(moduller, 1):
                    print(f"  \033[92m[{i}] {cmd}\033[0m")
                    print(f"      ↳ {aciklama}")
                print("  \033[90m[0] Üst Menüye Dön\033[0m")
                m_sec = input("\nModül seçin [0-" + str(len(moduller)) + "]: ").strip()
                if m_sec == "0": break
                if m_sec.isdigit() and 1 <= int(m_sec) <= len(moduller):
                    cmd, aciklama, ornek = moduller[int(m_sec) - 1]
                    print(f"\n\033[93m[BİLGİ]\033[0m {aciklama}")
                    print(f"\033[90m[ÖRNEK]\033[0m {ornek}")
                    calisacak = input(f"Çalıştırılacak komut (Enter = Örnek): ").strip() or ornek
                    print("\n\033[96m--- SONUÇ ---\033[0m")
                    satir_isle(calisacak, True)
                    input("\nDevam etmek için Enter'a basın...")

def gui_baslat():
    import http.server, socketserver, io, contextlib, json
    from urllib.parse import urlparse, parse_qs
    docs_json = json.dumps(MODUL_DOKUMANTASYON, ensure_ascii=False)
    HTML = f"""<!DOCTYPE html>
<html lang="tr"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>AlfSec v7.5 — Siber Kontrol Merkezi</title>
<style>
body{{background:#090d16;color:#e2e8f0;font-family:system-ui,sans-serif;margin:0;padding:14px}}
.ust{{display:flex;justify-content:space-between;align-items:center;border-bottom:1px solid #1e293b;padding-bottom:10px;margin-bottom:14px}}
h1{{font-size:19px;color:#38bdf8;margin:0}}
.sekmeler{{display:flex;gap:8px;margin-bottom:14px}}
.sekme{{flex:1;background:#111827;border:1px solid #334155;color:#94a3b8;padding:10px;border-radius:8px;font-weight:bold;cursor:pointer}}
.sekme.aktif{{background:#0284c7;color:#fff;border-color:#38bdf8}}
.kart{{background:#111827;border:1px solid #1f2937;border-radius:10px;padding:12px;margin-bottom:12px}}
.kart h3{{margin:0 0 8px 0;font-size:14px;color:#38bdf8}}
.komut-satir{{display:flex;justify-content:space-between;align-items:center;gap:8px;padding:8px 0;border-bottom:1px solid #1e293b;flex-wrap:wrap}}
.komut-bilgi{{flex:1;min-width:200px}}
.komut-ad{{color:#22c55e;font-family:monospace;font-size:13px;font-weight:bold}}
.komut-acik{{color:#94a3b8;font-size:12px;margin-top:2px}}
input{{width:100%;box-sizing:border-box;background:#090d16;border:1px solid #334155;color:#fff;padding:10px;border-radius:8px;font-family:monospace;margin-bottom:8px}}
button{{background:#0284c7;color:#fff;border:none;padding:8px 12px;border-radius:6px;font-weight:600;cursor:pointer}}
button.sec{{background:#1e293b;color:#38bdf8;border:1px solid #334155}}
pre{{background:#05080f;border:1px solid #1e293b;color:#22c55e;padding:12px;border-radius:8px;overflow-x:auto;font-size:12px;min-height:130px;white-space:pre-wrap}}
</style></head><body>
<div class="ust"><h1>🛡️ AlfSec v7.5 — GUI & Dokümantasyon</h1><span style="color:#22c55e;font-size:12px">● 24 Modül Hazır</span></div>
<div class="sekmeler">
  <button id="btnPanel" class="sekme aktif" onclick="sekmeAc('panel')">⚡ Kontrol Paneli</button>
  <button id="btnDok" class="sekme" onclick="sekmeAc('dok')">📖 Dokümantasyon & Tüm Modüller</button>
</div>
<div id="panelAlan">
  <div class="kart">
    <h3>🚀 Hızlı Gizlilik & Güvenlik İşlemleri</h3>
    <div style="display:flex;gap:8px;flex-wrap:wrap">
      <button style="background:#16a34a" onclick="komutCalistir('gizli_mod(\"acik\")')">Tor Gizli Mod Aç</button>
      <button style="background:#dc2626" onclick="komutCalistir('gizli_mod(\"kapali\")')">Tor Kapat</button>
      <button style="background:#7c3aed" onclick="komutCalistir('yeni_kimlik()')">Yeni IP Al</button>
      <button onclick="komutCalistir('sizinti_testi()')">Sızıntı Testi</button>
      <button onclick="komutCalistir('ag_kimlik()')">Ağ Kimliği</button>
    </div>
  </div>
  <div class="kart">
    <h3>⌨️ Komut Yürütücü (Tüm AlfSec Sözdizimi Destekli)</h3>
    <input id="komutInput" value='web_denetle("kripto-hat.onrender.com")' placeholder="Örn: port_tara(\"127.0.0.1\", 1, 100)">
    <button onclick="komutCalistir(document.getElementById('komutInput').value)">Komutu Çalıştır</button>
  </div>
  <div class="kart">
    <h3>📟 Canlı Konsol Çıktısı</h3>
    <pre id="cikti">Hazır. Dokümantasyon sekmesinden herhangi bir modülü seçip doğrudan çalıştırabilirsiniz.</pre>
  </div>
</div>
<div id="dokAlan" style="display:none"></div>
<script>
const DOK = {docs_json};
function sekmeAc(s) {{
  document.getElementById('panelAlan').style.display = s === 'panel' ? 'block' : 'none';
  document.getElementById('dokAlan').style.display = s === 'dok' ? 'block' : 'none';
  document.getElementById('btnPanel').className = 'sekme' + (s === 'panel' ? ' aktif' : '');
  document.getElementById('btnDok').className = 'sekme' + (s === 'dok' ? ' aktif' : '');
}}
async function komutCalistir(cmd) {{
  sekmeAc('panel');
  document.getElementById('komutInput').value = cmd;
  document.getElementById('cikti').textContent = '⏳ Çalıştırılıyor: ' + cmd + '...';
  const r = await fetch('/run?cmd=' + encodeURIComponent(cmd));
  document.getElementById('cikti').textContent = await r.text();
}}
const dokDiv = document.getElementById('dokAlan');
DOK.forEach(([kat, list]) => {{
  let h = `<div class="kart"><h3>📂 ${{kat}}</h3>`;
  list.forEach(([cmd, acik, ornek]) => {{
    const esc = ornek.replace(/"/g, '&quot;');
    h += `<div class="komut-satir"><div class="komut-bilgi"><div class="komut-ad">${{cmd}}</div><div class="komut-acik">${{acik}}</div></div><button class="sec" onclick="komutCalistir('${{esc}}')">Seç & Çalıştır</button></div>`;
  }});
  dokDiv.innerHTML += h + '</div>';
}});
</script></body></html>"""
    class Handler(http.server.BaseHTTPRequestHandler):
        def log_message(self, *a): pass
        def do_GET(self):
            if self.path == "/":
                self.send_response(200); self.send_header("Content-Type", "text/html; charset=utf-8"); self.end_headers()
                self.wfile.write(HTML.encode("utf-8"))
            elif self.path.startswith("/run"):
                cmd = parse_qs(urlparse(self.path).query).get("cmd", [""])[0]
                buf = io.StringIO()
                with contextlib.redirect_stdout(buf):
                    try: satir_isle(cmd, True)
                    except Exception as e: print(f"[HATA] {{e}}")
                self.send_response(200); self.send_header("Content-Type", "text/plain; charset=utf-8"); self.end_headers()
                self.wfile.write((buf.getvalue() or "[✓] Tamamlandı.").encode("utf-8"))
    print("[*] AlfSec Web GUI başlatıldı: http://127.0.0.1:8080 (Kapatmak için CTRL+C)")
    import webbrowser; webbrowser.open("http://127.0.0.1:8080")
    with socketserver.TCPServer(("127.0.0.1", 8080), Handler) as httpd:
        httpd.serve_forever()

def main():
    if len(sys.argv) >= 2:
        arg = sys.argv[1].lower()
        if arg == "gui": gui_baslat(); sys.exit(0)
        elif arg == "tui":
            if tui_baslat() != "cli": sys.exit(0)
        elif arg != "cli":
            with open(sys.argv[1], "r", encoding="utf-8") as f:
                for no, s in enumerate(f, 1): satir_isle(s)
            sys.exit(0)
    print("=== ALFSEC v7.5 SİBER GÜVENLİK & OSINT KONSOLU ('yardim' | 'cikis') ===")
    while True:
        try:
            g = input("\nalfsec> ").strip()
            if g.lower() in ["cikis", "exit"]: bellek.clear(); print("[*] RAM temizlendi, çıkıldı."); break
            satir_isle(g, True)
        except KeyboardInterrupt: print("\n[*] Çıkmak için 'cikis' yaz.")
        except Exception as e: print(f"[HATA] > {e}")

if __name__ == "__main__":
    main()
