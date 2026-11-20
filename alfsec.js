#!/usr/bin/env node
const crypto = require("crypto");
const net = require("net");
const tls = require("tls");
const dns = require("dns").promises;
const http = require("http");
const https = require("https");
const fs = require("fs");
const os = require("os");
const path = require("path");
const readline = require("readline");
const { execSync } = require("child_process");

const KASA_YOLU = path.join(os.homedir(), ".alfsec_kasa.json");

function _aracVarMi(cmd) {
  try { execSync(`command -v ${cmd}`, { stdio: "ignore" }); return true; } catch { return false; }
}
function _anahtarTuret(parola, salt) { return crypto.scryptSync(parola, salt, 32); }
function _temizDomain(hedef) { return String(hedef || "").replace(/^https?:\/\//i, "").split("/")[0].split(":")[0].trim(); }

function _httpGet(url, opts = {}) {
  return new Promise((resolve, reject) => {
    const mod = url.startsWith("https") ? https : http;
    const req = mod.get(url, { timeout: 8000, headers: { "User-Agent": "Mozilla/5.0 (Linux; AlfSec/10.0)" }, ...opts }, res => {
      let body = "";
      res.on("data", c => { if (body.length < 200000) body += c; });
      res.on("end", () => resolve({ status: res.statusCode, headers: res.headers, body }));
    });
    req.on("timeout", () => { req.destroy(); reject(new Error("Zaman aşımı")); });
    req.on("error", reject);
  });
}

// ==========================================
// 1. PASİF OSINT & İSTİHBARAT (10 MODÜL)
// ==========================================
async function kullanici_ara(kullanici) {
  kullanici = String(kullanici || "").replace(/^@/, "").trim();
  const siteler = [
    ["GitHub", `https://github.com/${kullanici}`],
    ["GitLab", `https://gitlab.com/${kullanici}`],
    ["Reddit", `https://www.reddit.com/user/${kullanici}`],
    ["Steam", `https://steamcommunity.com/id/${kullanici}`],
    ["Medium", `https://medium.com/@${kullanici}`],
    ["Pinterest", `https://tr.pinterest.com/${kullanici}/`],
    ["DeviantArt", `https://www.deviantart.com/${kullanici}`],
    ["Pastebin", `https://pastebin.com/u/${kullanici}`],
    ["DockerHub", `https://hub.docker.com/u/${kullanici}`],
    ["NPM", `https://www.npmjs.com/~${kullanici}`],
    ["PyPI", `https://pypi.org/user/${kullanici}/`],
    ["Replit", `https://replit.com/@${kullanici}`]
  ];
  console.log(`=== OSINT KULLANICI ADI TARAMASI: @${kullanici} ===`);
  let bulunan = 0;
  for (const [ad, url] of siteler) {
    try {
      const r = await _httpGet(url);
      if (r.status === 200) { console.log(`  [BULUNDU] ${ad.padEnd(11)} -> ${url}`); bulunan++; }
    } catch {}
  }
  console.log(`[✓] ${siteler.length} platformdan ${bulunan} tanesinde aktif profil izi bulundu.`);
}

async function eposta_denetle(eposta) {
  eposta = String(eposta || "").trim();
  const m = eposta.match(/^[^@\s]+@([^@\s]+\.[^@\s]+)$/);
  if (!m) return console.log("[!] Geçersiz e-posta adresi biçimi.");
  const domain = m[1];
  console.log(`=== E-POSTA ALTYAPI & GÜVENLİK DENETİMİ: ${eposta} ===`);
  const mx = await dns.resolveMx(domain).catch(() => []);
  const txt = await dns.resolveTxt(domain).catch(() => []);
  const dmarc = await dns.resolveTxt(`_dmarc.${domain}`).catch(() => []);
  const spf = txt.map(t => t.join("")).find(t => t.toLowerCase().startsWith("v=spf1"));
  console.log(`  • Posta Sunucusu (MX) : ${mx.length ? mx.map(x => x.exchange).join(", ") : "YOK (E-posta alamaz)"}`);
  console.log(`  • Sahtecilik Kilidi SPF: ${spf ? "AKTİF (" + spf + ")" : "EKSİK"}`);
  console.log(`  • DMARC Politikası     : ${dmarc.length ? dmarc[0].join("") : "EKSİK"}`);
}

async function dns_detay(domain) {
  domain = _temizDomain(domain);
  console.log(`=== TAM DNS KAYIT ANALİZİ: ${domain} ===`);
  const a = await dns.resolve4(domain).catch(() => []);
  const aaaa = await dns.resolve6(domain).catch(() => []);
  const mx = await dns.resolveMx(domain).catch(() => []);
  const ns = await dns.resolveNs(domain).catch(() => []);
  const txt = await dns.resolveTxt(domain).catch(() => []);
  console.log(`  • IPv4 (A)     : ${a.length ? a.join(", ") : "Kayıt yok"}`);
  console.log(`  • IPv6 (AAAA)  : ${aaaa.length ? aaaa.join(", ") : "Kayıt yok"}`);
  console.log(`  • E-Posta (MX) : ${mx.length ? mx.map(x => `${x.exchange} (${x.priority})`).join(", ") : "Kayıt yok"}`);
  console.log(`  • İsim Sunucu  : ${ns.length ? ns.join(", ") : "Kayıt yok"}`);
  console.log(`  • TXT Kayıtları: ${txt.length ? txt.map(t => t.join("")).join(" | ") : "Kayıt yok"}`);
}

function whois_sorgu(domain) {
  domain = _temizDomain(domain);
  console.log(`=== WHOIS ALAN ADI KİMLİĞİ: ${domain} ===`);
  if (!_aracVarMi("whois")) return console.log("  [!] Sistemde 'whois' aracı yok (Kurulum: pkg install whois veya apt install whois).");
  try {
    const ham = execSync(`whois ${domain.replace(/[^a-zA-Z0-9.-]/g, "")}`, { encoding: "utf8", timeout: 8000 });
    const sozluk = { "registrar:": "Kayıt Kuruluşu", "creation date:": "Oluşturulma Tarihi", "registry expiry date:": "Bitiş Tarihi", "updated date:": "Son Güncelleme", "name server:": "İsim Sunucusu" };
    for (const s of ham.split(/\r?\n/)) {
      const alt = s.toLowerCase().trim();
      for (const [en, tr] of Object.entries(sozluk)) {
        if (alt.startsWith(en)) console.log(`  • ${tr.padEnd(20)}: ${s.split(":").slice(1).join(":").trim()}`);
      }
    }
  } catch (e) { console.log(`[!] WHOIS sorgusu başarısız: ${e.message}`); }
}

async function subdomain_bul(domain) {
  domain = _temizDomain(domain);
  console.log(`[*] ${domain} için alt alan adları (Sertifika Şeffaflığı) taranıyor...`);
  try {
    const r = await _httpGet(`https://crt.sh/?q=%25.${domain}&output=json`);
    const subs = [...new Set(JSON.parse(r.body).map(x => x.name_value.toLowerCase().trim()).filter(x => !x.includes("*")))].sort();
    subs.slice(0, 35).forEach(s => console.log(`  [+] ${s}`));
    console.log(`[✓] Toplam ${subs.length} benzersiz alt alan adı bulundu.`);
  } catch { console.log("[!] Sertifika kayıtları şu an alınamadı."); }
}

async function ip_analiz(ip = "") {
  try {
    const r = await _httpGet(`http://ip-api.com/json/${ip}?lang=tr`);
    const j = JSON.parse(r.body);
    if (j.status !== "success") return console.log(`[!] IP bilgisi alınamadı: ${j.message}`);
    console.log(`=== IP COĞRAFİ & AĞ ANALİZİ: ${j.query} ===`);
    console.log(`  • Konum    : ${j.country} / ${j.regionName} / ${j.city}`);
    console.log(`  • Sağlayıcı: ${j.isp} (${j.org})`);
    console.log(`  • ASN Kodu : ${j.as}`);
  } catch (e) { console.log(`[HATA] ${e.message}`); }
}

async function ters_dns(ip) {
  try {
    const hostlar = await dns.reverse(ip.trim());
    console.log(`[TERS DNS] ${ip} -> ${hostlar.join(", ")}`);
  } catch { console.log(`[TERS DNS] ${ip} için PTR alan adı kaydı bulunamadı.`); }
}

function mac_sorgu(mac) {
  const temiz = String(mac || "").toUpperCase().replace(/[^0-9A-F]/g, "").slice(0, 6);
  const ureticiler = {
    "001A11": "Google", "3C5AB4": "Google", "F4F5D8": "Google",
    "286C07": "Xiaomi", "64B473": "Xiaomi", "7C1DD9": "Xiaomi",
    "00163E": "Xen Virtual", "080027": "Oracle VirtualBox", "000C29": "VMware",
    "B827EB": "Raspberry Pi", "DCA632": "Raspberry Pi",
    "001E52": "Apple", "3C0754": "Apple", "F01898": "Apple",
    "001247": "Samsung", "5C0A5B": "Samsung", "8C7712": "Samsung",
    "18D6C7": "TP-Link", "50C7BF": "TP-Link", "C025E9": "TP-Link"
  };
  console.log(`[MAC OUI] ${mac} -> Üretici: ${ureticiler[temiz] || "Bilinmeyen / Özel MAC (Prefix: " + temiz + ")"}`);
}

function telefon_bilgi(tel) {
  const temiz = String(tel || "").replace(/[\s\-()]/g, "");
  const ulkeler = { "+90": "Türkiye", "+1": "ABD / Kanada", "+44": "Birleşik Krallık", "+49": "Almanya", "+33": "Fransa", "+7": "Rusya", "+994": "Azerbaycan" };
  const kod = Object.keys(ulkeler).find(k => temiz.startsWith(k));
  console.log(`=== TELEFON FORMAT ANALİZİ: ${tel} ===`);
  console.log(`  • Ülke Bölgesi : ${kod ? ulkeler[kod] + " (" + kod + ")" : "Bilinmeyen Ülke Kodu"}`);
  console.log(`  • Rakam Sayısı : ${temiz.replace(/\D/g, "").length} hane (${temiz.startsWith("+") ? "Uluslararası E.164" : "Yerel Format"})`);
}

async function tam_analiz(domain) {
  domain = _temizDomain(domain);
  console.log(`\n╔══════════════════════════════════════════════════════╗\n║   ALFSEC v10.0 — OTOMATİK TAM OSINT & GÜVENLİK RAPORU║\n╚══════════════════════════════════════════════════════╝`);
  console.log(`Hedef: ${domain} | Tarih: ${new Date().toLocaleString("tr-TR")}\n`);
  await dns_detay(domain); console.log("");
  await web_denetle(domain); console.log("");
  await teknoloji_bul(domain); console.log("");
  await ssl_analiz(domain); console.log("");
  await subdomain_bul(domain); console.log("");
  await nmap_turkce(domain);
  console.log(`\n[✓] '${domain}' için tam kapsamlı OSINT ve güvenlik raporu tamamlandı.`);
}

// ==========================================
// 2. AĞ TEŞHİSİ & TÜRKÇE NMAP (8 MODÜL)
// ==========================================
function sistem_bilgi() {
  let distro = os.platform();
  if (fs.existsSync("/etc/os-release")) {
    const m = fs.readFileSync("/etc/os-release", "utf8").match(/PRETTY_NAME="([^"]+)"/);
    if (m) distro = m[1];
  } else if (process.env.PREFIX && process.env.PREFIX.includes("termux")) distro = "Android Termux";
  const araclar = ["nmap", "whois", "tor", "curl", "openssl"].map(a => `${a}: ${_aracVarMi(a) ? "HAZIR" : "YOK"}`).join(" | ");
  console.log(`=== SİSTEM & ORTAM DURUMU ===\n  • İşletim Sistemi : ${distro} (${os.arch()})\n  • Cihaz Adı       : ${os.hostname()}\n  • Dış Araç Desteği: ${araclar}`);
}

function ag_kimlik() {
  console.log("=== YEREL AĞ ARAYÜZLERİ ===");
  for (const [ad, list] of Object.entries(os.networkInterfaces())) {
    for (const n of list) {
      if (!n.internal && n.family === "IPv4") console.log(`  • Arayüz: ${ad} | Yerel IP: ${n.address} | MAC: ${n.mac}`);
    }
  }
}

async function dis_ip() {
  try {
    const r = await _httpGet("https://api.ipify.org?format=json");
    console.log(`[DIŞ IP] İnternet Çıkış IP Adresiniz: ${JSON.parse(r.body).ip}`);
  } catch { console.log("[!] Dış IP adresi sorgulanamadı."); }
}

function tor_kontrol() {
  return new Promise(resolve => {
    const s = new net.Socket(); s.setTimeout(1000);
    s.connect(9050, "127.0.0.1", () => { console.log("[TOR] AKTİF — Yerel Tor SOCKS5 proxy (127.0.0.1:9050) çalışıyor."); s.destroy(); resolve(); });
    s.on("error", () => { console.log("[TOR] KAPALI — 9050 portu dinlenmiyor."); s.destroy(); resolve(); });
    s.on("timeout", () => { console.log("[TOR] KAPALI — Zaman aşımı."); s.destroy(); resolve(); });
  });
}

function port_tara(hedef, bas = 1, bit = 100) {
  return new Promise(resolve => {
    console.log(`[*] ${hedef} (${bas}-${bit}) TCP portları taranıyor...`);
    let aktif = 0, mevcut = Number(bas), son = Number(bit), aciklar = [];
    function sonraki() {
      if (mevcut > son && aktif === 0) {
        console.log(`[✓] Tarama bitti. Açık portlar: ${aciklar.length ? aciklar.join(", ") : "Bulunamadı"}`);
        return resolve();
      }
      while (aktif < 50 && mevcut <= son) {
        const p = mevcut++; aktif++;
        const s = new net.Socket(); s.setTimeout(600);
        s.connect(p, hedef, () => { aciklar.push(p); console.log(`  [+] Port ${p}/TCP -> AÇIK`); s.destroy(); });
        s.on("error", () => s.destroy()); s.on("timeout", () => s.destroy());
        s.on("close", () => { aktif--; sonraki(); });
      }
    }
    sonraki();
  });
}

async function nmap_turkce(hedef) {
  hedef = _temizDomain(hedef);
  if (_aracVarMi("nmap")) {
    console.log(`=== NMAP TÜRKÇE SERVİS & PORT RAPORU: ${hedef} ===`);
    try {
      const ham = execSync(`nmap -sV -T4 --top-ports 100 ${hedef.replace(/[^a-zA-Z0-9.-]/g, "")}`, { encoding: "utf8", timeout: 25000 });
      let acik = 0;
      for (const s of ham.split(/\r?\n/)) {
        if (s.includes("Host is up")) console.log(`  • Hedef Durumu : ÇEVRİMİÇİ`);
        else if (/^\d+\/(tcp|udp)\s+open/.test(s)) {
          const p = s.trim().split(/\s+/);
          console.log(`  [+] Port ${p[0].padEnd(10)} | Durum: AÇIK | Servis: ${(p[2] || "bilinmiyor").padEnd(10)} | Sürüm: ${p.slice(3).join(" ") || "Gizli"}`);
          acik++;
        }
      }
      if (acik === 0) console.log("  [-] İlk 100 yaygın portta açık servis bulunamadı.");
      return;
    } catch { console.log("[!] Nmap hatası, dahili tarayıcıya geçiliyor..."); }
  }
  await port_tara(hedef, 1, 100);
}

function servis_banner(hedef, port = 80) {
  return new Promise(resolve => {
    const s = new net.Socket(); s.setTimeout(2500);
    s.connect(Number(port), _temizDomain(hedef), () => s.write(`HEAD / HTTP/1.0\r\nHost: ${hedef}\r\n\r\n`));
    s.on("data", d => { console.log(`=== BANNER (${hedef}:${port}) ===\n${d.toString("utf8").split("\r\n\r\n")[0]}`); s.destroy(); });
    s.on("error", e => { console.log(`[HATA] ${e.message}`); resolve(); });
    s.on("timeout", () => { console.log("[!] Servis yanıt vermedi."); s.destroy(); });
    s.on("close", resolve);
  });
}

function yerel_ag_tara(onek = "192.168.1") {
  return new Promise(resolve => {
    console.log(`[*] ${onek}.1 - ${onek}.254 yerel ağı taranıyor...`);
    let aktif = 0, ipNo = 1, bulunan = 0;
    function sonraki() {
      if (ipNo > 254 && aktif === 0) { console.log(`[✓] Yerel ağ taraması bitti. ${bulunan} aktif cihaz bulundu.`); return resolve(); }
      while (aktif < 40 && ipNo <= 254) {
        const ip = `${onek}.${ipNo++}`; aktif++;
        const s = new net.Socket(); s.setTimeout(350);
        s.connect(80, ip, () => { console.log(`  [+] Aktif Cihaz: ${ip} (Port 80 açık)`); bulunan++; s.destroy(); });
        s.on("error", err => { if (err.code === "ECONNREFUSED") { console.log(`  [+] Aktif Cihaz: ${ip} (Çevrimiçi)`); bulunan++; } s.destroy(); });
        s.on("timeout", () => s.destroy());
        s.on("close", () => { aktif--; sonraki(); });
      }
    }
    sonraki();
  });
}

// ==========================================
// 3. WEB GÜVENLİĞİ & SSL DENETİMİ (8 MODÜL)
// ==========================================
async function web_denetle(domain) {
  domain = _temizDomain(domain);
  try {
    const r = await _httpGet(`https://${domain}`);
    const h = r.headers;
    console.log(`=== WEB GÜVENLİK KALKANLARI: ${domain} (HTTP ${r.status}) ===`);
    console.log(`  • Zorunlu HTTPS (HSTS)    : ${h["strict-transport-security"] ? "AKTİF" : "EKSİK"}`);
    console.log(`  • XSS Kalkanı (CSP)       : ${h["content-security-policy"] ? "AKTİF" : "EKSİK"}`);
    console.log(`  • Clickjacking Koruması   : ${h["x-frame-options"] ? "AKTİF" : "EKSİK"}`);
    console.log(`  • Dosya Tipi Kilidi (MIME): ${h["x-content-type-options"] ? "AKTİF" : "EKSİK"}`);
    console.log(`  • Referrer Politikası     : ${h["referrer-policy"] ? "AKTİF (" + h["referrer-policy"] + ")" : "EKSİK"}`);
  } catch (e) { console.log(`[HATA] ${e.message}`); }
}

function ssl_analiz(domain) {
  domain = _temizDomain(domain);
  return new Promise(resolve => {
    const s = tls.connect(443, domain, { servername: domain }, () => {
      const cert = s.getPeerCertificate();
      console.log(`=== SSL/TLS SERTİFİKA ANALİZİ: ${domain} ===\n  • TLS Sürümü        : ${s.getProtocol()}\n  • Şifreleme Paketi  : ${s.getCipher().name}\n  • Sertifika Kurumu  : ${cert.issuer?.O || "Bilinmiyor"}\n  • Geçerlilik Bitişi : ${cert.valid_to}`);
      s.end(); resolve();
    });
    s.on("error", e => { console.log(`[HATA] ${e.message}`); resolve(); });
  });
}

async function teknoloji_bul(domain) {
  domain = _temizDomain(domain);
  try {
    const r = await _httpGet(`https://${domain}`);
    const h = r.headers;
    const tespitler = [];
    if (h["server"]) tespitler.push(`Sunucu: ${h["server"]}`);
    if (h["x-powered-by"]) tespitler.push(`Altyapı: ${h["x-powered-by"]}`);
    if (h["cf-ray"]) tespitler.push("CDN/WAF: Cloudflare");
    if (r.body.includes("wp-content")) tespitler.push("CMS: WordPress");
    if (r.body.includes("__NEXT_DATA__")) tespitler.push("Framework: Next.js");
    if (r.body.includes("react")) tespitler.push("Arayüz: React");
    console.log(`=== TEKNOLOJİ & ALTYAPI İZİ: ${domain} ===\n  • ${tespitler.length ? tespitler.join("\n  • ") : "Belirgin teknoloji başlığı gizlenmiş."}`);
  } catch (e) { console.log(`[HATA] ${e.message}`); }
}

async function robots_oku(domain) {
  domain = _temizDomain(domain);
  try {
    const r = await _httpGet(`https://${domain}/robots.txt`);
    console.log(`=== ROBOTS.TXT ANALİZİ: ${domain} (HTTP ${r.status}) ===`);
    if (r.status === 200) console.log(r.body.split("\n").slice(0, 20).join("\n"));
    else console.log("  [-] robots.txt dosyası bulunamadı.");
  } catch (e) { console.log(`[HATA] ${e.message}`); }
}

async function cerez_denetle(domain) {
  domain = _temizDomain(domain);
  try {
    const r = await _httpGet(`https://${domain}`);
    const cookies = r.headers["set-cookie"] || [];
    console.log(`=== ÇEREZ (COOKIE) GÜVENLİK DENETİMİ: ${domain} ===`);
    if (!cookies.length) return console.log("  • Sunucu başlangıçta çerez göndermedi.");
    cookies.forEach(c => {
      const ad = c.split("=")[0];
      const sec = /secure/i.test(c) ? "EVET" : "HAYIR";
      const httpOnly = /httponly/i.test(c) ? "EVET" : "HAYIR";
      console.log(`  • Çerez: ${ad} | Secure: ${sec} | HttpOnly: ${httpOnly}`);
    });
  } catch (e) { console.log(`[HATA] ${e.message}`); }
}

async function link_cikar(url) {
  if (!url.startsWith("http")) url = "https://" + url;
  try {
    const r = await _httpGet(url);
    const links = [...new Set((r.body.match(/href=["'](https?:\/\/[^"']+)["']/gi) || []).map(x => x.replace(/^href=["']|["']$/gi, "")))];
    console.log(`=== DIŞ BAĞLANTI ANALİZİ (${links.length} Link) ===`);
    links.slice(0, 25).forEach(l => console.log(`  • ${l}`));
  } catch (e) { console.log(`[HATA] ${e.message}`); }
}

function http_metotlar(domain) {
  domain = _temizDomain(domain);
  return new Promise(resolve => {
    const req = https.request({ hostname: domain, path: "/", method: "OPTIONS" }, res => {
      console.log(`[HTTP METOTLAR] ${domain} -> İzin Verilenler: ${res.headers["allow"] || "Sunucu OPTIONS başlığı döndürmedi (Durum: " + res.statusCode + ")"}`);
      resolve();
    });
    req.on("error", e => { console.log(`[HATA] ${e.message}`); resolve(); });
    req.end();
  });
}


// ==========================================
// 4. KRİPTOGRAFİ, KODLAMA & ŞİFRE KASASI (9 MODÜL)
// ==========================================
function sifrele(metin, parola) {
  const salt = crypto.randomBytes(16), iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv("aes-256-gcm", _anahtarTuret(String(parola), salt), iv);
  const enc = Buffer.concat([cipher.update(String(metin), "utf8"), cipher.final()]);
  console.log(`[ŞİFRELİ METİN] ${Buffer.concat([salt, iv, cipher.getAuthTag(), enc]).toString("base64")}`);
}

function coz(b64, parola) {
  try {
    const raw = Buffer.from(String(b64), "base64");
    const decipher = crypto.createDecipheriv("aes-256-gcm", _anahtarTuret(String(parola), raw.subarray(0, 16)), raw.subarray(16, 28));
    decipher.setAuthTag(raw.subarray(28, 44));
    console.log(`[ÇÖZÜLEN METİN] ${Buffer.concat([decipher.update(raw.subarray(44)), decipher.final()]).toString("utf8")}`);
  } catch { console.log("[HATA] Parola hatalı veya şifreli veri bozuk."); }
}

function ozetle(metin) {
  const s = String(metin);
  console.log(`=== KRİPTOGRAFİK ÖZET (HASH) ===`);
  console.log(`  • MD5     : ${crypto.createHash("md5").update(s).digest("hex")}`);
  console.log(`  • SHA-1   : ${crypto.createHash("sha1").update(s).digest("hex")}`);
  console.log(`  • SHA-256 : ${crypto.createHash("sha256").update(s).digest("hex")}`);
  console.log(`  • SHA-512 : ${crypto.createHash("sha512").update(s).digest("hex")}`);
}

function base64_kodla(metin) { console.log(`[BASE64] ${Buffer.from(String(metin), "utf8").toString("base64")}`); }
function base64_coz(kodStr) { console.log(`[ÇÖZÜLDÜ] ${Buffer.from(String(kodStr), "base64").toString("utf8")}`); }
function hex_kodla(metin) { console.log(`[HEX] ${Buffer.from(String(metin), "utf8").toString("hex")}`); }
function hex_coz(hexStr) { console.log(`[ÇÖZÜLDÜ] ${Buffer.from(String(hexStr), "hex").toString("utf8")}`); }

function jwt_coz(token) {
  try {
    const parcalar = String(token).trim().split(".");
    if (parcalar.length < 2) return console.log("[!] Geçersiz JWT formatı.");
    const header = JSON.parse(Buffer.from(parcalar[0], "base64url").toString("utf8"));
    const payload = JSON.parse(Buffer.from(parcalar[1], "base64url").toString("utf8"));
    console.log("=== JWT TOKEN ANALİZİ ===");
    console.log("  • Başlık (Header) :", JSON.stringify(header));
    console.log("  • İçerik (Payload):", JSON.stringify(payload, null, 2));
    if (payload.exp) console.log("  • Bitiş Zamanı    :", new Date(payload.exp * 1000).toLocaleString("tr-TR"));
  } catch { console.log("[!] JWT çözümlenemedi."); }
}

function sifre_uret(uzunluk = 24) {
  const chars = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789!@#$%^&*_-+=";
  const sifre = Array.from(crypto.randomBytes(Number(uzunluk) || 24), b => chars[b % chars.length]).join("");
  console.log(`[ÜRETİLEN PAROLA] ${sifre}`);
}

function parola_guc(parola) {
  const p = String(parola);
  let havuz = 0;
  if (/[a-z]/.test(p)) havuz += 26;
  if (/[A-Z]/.test(p)) havuz += 26;
  if (/[0-9]/.test(p)) havuz += 10;
  if (/[^a-zA-Z0-9]/.test(p)) havuz += 32;
  const entropi = Math.round(p.length * Math.log2(havuz || 1));
  const seviye = entropi < 40 ? "ZAYIF" : entropi < 65 ? "ORTA" : entropi < 90 ? "GÜÇLÜ" : "ÇOK GÜÇLÜ";
  console.log(`=== PAROLA GÜÇ ANALİZİ ===
  • Uzunluk : ${p.length} karakter
  • Entropi : ~${entropi} bit
  • Seviye  : ${seviye}`);
}

function kasa_ekle(etiket, veri, parola) {
  let kasa = fs.existsSync(KASA_YOLU) ? JSON.parse(fs.readFileSync(KASA_YOLU, "utf8")) : {};
  const salt = crypto.randomBytes(16), iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv("aes-256-gcm", _anahtarTuret(String(parola), salt), iv);
  const enc = Buffer.concat([cipher.update(String(veri), "utf8"), cipher.final()]);
  kasa[etiket] = Buffer.concat([salt, iv, cipher.getAuthTag(), enc]).toString("base64");
  fs.writeFileSync(KASA_YOLU, JSON.stringify(kasa, null, 2));
  console.log(`[KASA] '${etiket}' AES-256-GCM ile şifrelenip kaydedildi.`);
}

function kasa_oku(etiket, parola) {
  if (!fs.existsSync(KASA_YOLU)) return console.log("[KASA] Henüz kayıtlı bir kasa yok.");
  const kasa = JSON.parse(fs.readFileSync(KASA_YOLU, "utf8"));
  if (!kasa[etiket]) return console.log(`[KASA] '${etiket}' kaydı bulunamadı.`);
  coz(kasa[etiket], parola);
}

// ==========================================
// 5. ADLİ BİLİŞİM (FORENSICS) & DOSYA ANALİZİ (5 MODÜL)
// ==========================================
function dosya_hash(dosyaYolu) {
  if (!fs.existsSync(dosyaYolu)) return console.log(`[!] Dosya bulunamadı: ${dosyaYolu}`);
  const veri = fs.readFileSync(dosyaYolu);
  console.log(`=== DOSYA BÜTÜNLÜK İMZASI: ${path.basename(dosyaYolu)} (${veri.length} bayt) ===`);
  console.log(`  • MD5     : ${crypto.createHash("md5").update(veri).digest("hex")}`);
  console.log(`  • SHA-256 : ${crypto.createHash("sha256").update(veri).digest("hex")}`);
}

function dosya_tipi(dosyaYolu) {
  if (!fs.existsSync(dosyaYolu)) return console.log(`[!] Dosya bulunamadı: ${dosyaYolu}`);
  const buf = Buffer.alloc(16);
  const fd = fs.openSync(dosyaYolu, "r");
  fs.readSync(fd, buf, 0, 16, 0);
  fs.closeSync(fd);
  const hex = buf.toString("hex").toUpperCase();
  const imzalar = [
    ["89504E47", "PNG Görsel Dosyası"],
    ["FFD8FF", "JPEG Görsel Dosyası"],
    ["25504446", "PDF Belgesi"],
    ["504B0304", "ZIP / APK / DOCX Arşivi"],
    ["7F454C46", "Linux ELF Çalıştırılabilir Dosyası"],
    ["4D5A", "Windows EXE / DLL Dosyası"],
    ["52617221", "RAR Arşivi"],
    ["1F8B", "GZIP Sıkıştırılmış Dosya"]
  ];
  const bulunan = imzalar.find(([sig]) => hex.startsWith(sig));
  console.log(`[SİHİRLİ BAYT] ${path.basename(dosyaYolu)} -> Gerçek Tür: ${bulunan ? bulunan[1] : "Metin veya Bilinmeyen İkili (Hex: " + hex.slice(0, 12) + ")"}`);
}

function metin_ayikla(dosyaYolu) {
  if (!fs.existsSync(dosyaYolu)) return console.log(`[!] Dosya bulunamadı: ${dosyaYolu}`);
  const icerik = fs.readFileSync(dosyaYolu, "latin1");
  const dizeler = icerik.match(/[\x20-\x7E]{6,}/g) || [];
  console.log(`=== METİN AYIKLAMA (STRINGS): ${path.basename(dosyaYolu)} (${dizeler.length} dize) ===`);
  dizeler.slice(0, 30).forEach(d => console.log(`  • ${d}`));
}

function log_analiz(logYolu) {
  if (!fs.existsSync(logYolu)) return console.log(`[!] Log dosyası bulunamadı: ${logYolu}`);
  const satirlar = fs.readFileSync(logYolu, "utf8").split(/\r?\n/).filter(Boolean);
  const ipSayac = {}, kodSayac = {};
  for (const s of satirlar) {
    const ip = s.match(/\b(?:\d{1,3}\.){3}\d{1,3}\b/);
    if (ip) ipSayac[ip[0]] = (ipSayac[ip[0]] || 0) + 1;
    const kod = s.match(/\s(200|301|302|400|401|403|404|500|502|503)\s/);
    if (kod) kodSayac[kod[1]] = (kodSayac[kod[1]] || 0) + 1;
  }
  console.log(`=== LOG GÜVENLİK ÖZETİ: ${path.basename(logYolu)} (${satirlar.length} satır) ===`);
  console.log("  • HTTP Durum Dağılımı:", Object.entries(kodSayac).map(([k, v]) => `${k}: ${v} kez`).join(" | ") || "Standart HTTP kodu yok");
  const topIp = Object.entries(ipSayac).sort((a, b) => b[1] - a[1]).slice(0, 5);
  console.log("  • En Çok İstek Atan IP:", topIp.map(([ip, c]) => `${ip} (${c})`).join(", ") || "IP kaydı yok");
}

const MODULLER = [
  ["Pasif OSINT & İstihbarat (10 Modül)", [
    ["tam_analiz(\"ornek.com\")", "DNS, Web Kalkanı, Teknoloji, SSL, Subdomain ve Nmap taramasını birleştirir.", "tam_analiz(\"kripto-hat.onrender.com\")"],
    ["kullanici_ara(\"kullanici\")", "12 popüler platformda kullanıcı adı profil izini tarar.", "kullanici_ara(\"Berkay5642\")"],
    ["eposta_denetle(\"mail@site.com\")", "E-posta alan adının MX, SPF ve DMARC güvenlik kayıtlarını doğrular.", "eposta_denetle(\"info@github.com\")"],
    ["dns_detay(\"ornek.com\")", "A, AAAA, MX, NS ve TXT kayıtlarının tamamını döker.", "dns_detay(\"google.com\")"],
    ["whois_sorgu(\"ornek.com\")", "Alan adının kayıt şirketini ve geçerlilik tarihlerini Türkçe gösterir.", "whois_sorgu(\"github.com\")"],
    ["subdomain_bul(\"ornek.com\")", "Sertifika şeffaflığı kayıtlarından alt alan adlarını listeler.", "subdomain_bul(\"github.com\")"],
    ["ip_analiz(\"8.8.8.8\")", "IP adresinin ülke, şehir, sağlayıcı ve ASN bilgisini getirir.", "ip_analiz(\"8.8.8.8\")"],
    ["ters_dns(\"8.8.8.8\")", "IP adresinin bağlı olduğu PTR alan adını sorgular.", "ters_dns(\"8.8.8.8\")"],
    ["mac_sorgu(\"00:1A:11:00:00:00\")", "MAC adresinin ilk 6 hanesinden cihaz üreticisini tespit eder.", "mac_sorgu(\"00:1A:11:22:33:44\")"],
    ["telefon_bilgi(\"+905551234567\")", "Telefon numarasının ülke bölgesi ve E.164 format analizini yapar.", "telefon_bilgi(\"+905551234567\")"]
  ]],
  ["Ağ Teşhisi & Türkçe Nmap (8 Modül)", [
    ["nmap_turkce(\"hedef\")", "Sistemdeki Nmap'i çalıştırıp açık portları ve sürümleri Türkçe raporlar.", "nmap_turkce(\"127.0.0.1\")"],
    ["port_tara(\"hedef\", 1, 100)", "Dahili Node.js motoruyla hızlı TCP port taraması yapar.", "port_tara(\"127.0.0.1\", 1, 100)"],
    ["yerel_ag_tara(\"192.168.1\")", "Yerel ağınızdaki aktif cihazları tarar.", "yerel_ag_tara(\"192.168.1\")"],
    ["servis_banner(\"hedef\", 80)", "Açık porttaki servisin kimlik (banner) bilgisini okur.", "servis_banner(\"example.com\", 80)"],
    ["ag_kimlik()", "Cihazın yerel IP adreslerini ve MAC bilgilerini gösterir.", "ag_kimlik()"],
    ["dis_ip()", "İnternete çıktığınız güncel genel IP adresini gösterir.", "dis_ip()"],
    ["tor_kontrol()", "Yerel Tor proxy servisinin (9050) aktif olup olmadığını denetler.", "tor_kontrol()"],
    ["sistem_bilgi()", "İşletim sistemini ve kurulu güvenlik araçlarını denetler.", "sistem_bilgi()"]
  ]],
  ["Web Güvenliği & SSL Denetimi (7 Modül)", [
    ["web_denetle(\"ornek.com\")", "HSTS, CSP, Clickjacking, MIME ve Referrer kalkanlarını denetler.", "web_denetle(\"kripto-hat.onrender.com\")"],
    ["ssl_analiz(\"ornek.com\")", "TLS protokol sürümünü ve sertifika geçerlilik süresini inceler.", "ssl_analiz(\"kripto-hat.onrender.com\")"],
    ["teknoloji_bul(\"ornek.com\")", "Sunucu yazılımını, CDN/WAF ve frontend altyapısını tespit eder.", "teknoloji_bul(\"github.com\")"],
    ["robots_oku(\"ornek.com\")", "Sitenin robots.txt kurallarını çekip listeler.", "robots_oku(\"github.com\")"],
    ["cerez_denetle(\"ornek.com\")", "Çerezlerin Secure ve HttpOnly güvenlik bayraklarını kontrol eder.", "cerez_denetle(\"github.com\")"],
    ["link_cikar(\"https://ornek.com\")", "Sayfadaki tüm dış bağlantıları ayıklar.", "link_cikar(\"https://example.com\")"],
    ["http_metotlar(\"ornek.com\")", "Sunucunun izin verdiği HTTP metotlarını sorgular.", "http_metotlar(\"example.com\")"]
  ]],
  ["Kriptografi, Kodlama & Şifre Kasası (11 Modül)", [
    ["sifrele(\"metin\", \"parola\")", "Veriyi AES-256-GCM algoritmasıyla şifreler.", "sifrele(\"gizli veri\", \"Sifre123\")"],
    ["coz(\"sifreli\", \"parola\")", "AES-256-GCM ile şifrelenmiş metni çözer.", "coz(\"...\", \"Sifre123\")"],
    ["ozetle(\"metin\")", "MD5, SHA-1, SHA-256 ve SHA-512 hash özetlerini üretir.", "ozetle(\"AlfSec\")"],
    ["base64_kodla(\"metin\")", "Metni Base64 formatına dönüştürür.", "base64_kodla(\"Merhaba\")"],
    ["base64_coz(\"kod\")", "Base64 kodunu okunabilir metne çevirir.", "base64_coz(\"TWVyaGFiYQ==\")"],
    ["hex_kodla(\"metin\")", "Metni Hexadecimal (16'lık) formata çevirir.", "hex_kodla(\"AlfSec\")"],
    ["hex_coz(\"hex\")", "Hexadecimal diziyi metne dönüştürür.", "hex_coz(\"416c66536563\")"],
    ["jwt_coz(\"token\")", "JWT token başlık ve içerik verisini çözümler.", "jwt_coz(\"eyJhbGciOiJIUzI1NiJ9.eyJ1c2VyIjoiYWxmcmVkIn0.xxx\")"],
    ["sifre_uret(24)", "Kriptografik olarak güvenli parola üretir.", "sifre_uret(24)"],
    ["parola_guc(\"parola\")", "Parolanın entropi bit gücünü ve seviyesini ölçer.", "parola_guc(\"Deneme123!\")"],
    ["kasa_ekle(\"etiket\", \"veri\", \"parola\")", "Hassas veriyi yerel şifreli kasaya kaydeder.", "kasa_ekle(\"not\", \"1234\", \"anaSifre\")"]
  ]],
  ["Adli Bilişim (Forensics) & Dosya Analizi (4 Modül)", [
    ["dosya_hash(\"dosya_yolu\")", "Dosyanın MD5 ve SHA-256 bütünlük imzasını çıkarır.", "dosya_hash(\"/data/data/com.termux/files/usr/bin/alfsec\")"],
    ["dosya_tipi(\"dosya_yolu\")", "Sihirli baytlardan (Magic Bytes) dosyanın gerçek türünü bulur.", "dosya_tipi(\"/data/data/com.termux/files/usr/bin/alfsec\")"],
    ["metin_ayikla(\"dosya_yolu\")", "İkili dosyaların içindeki okunabilir dizeleri ayıklar.", "metin_ayikla(\"/data/data/com.termux/files/usr/bin/alfsec\")"],
    ["log_analiz(\"log_yolu\")", "Log dosyasındaki hata kodlarını ve yoğun IP adreslerini özetler.", "log_analiz(\"/var/log/auth.log\")"]
  ]]
];

const ARAC_HARITASI = {
  tam_analiz, kullanici_ara, eposta_denetle, dns_detay, whois_sorgu, subdomain_bul, ip_analiz, ters_dns, mac_sorgu, telefon_bilgi,
  nmap_turkce, port_tara, yerel_ag_tara, servis_banner, ag_kimlik, dis_ip, tor_kontrol, sistem_bilgi,
  web_denetle, ssl_analiz, teknoloji_bul, robots_oku, cerez_denetle, link_cikar, http_metotlar,
  sifrele, coz, ozetle, base64_kodla, base64_coz, hex_kodla, hex_coz, jwt_coz, sifre_uret, parola_guc, kasa_ekle, kasa_oku,
  dosya_hash, dosya_tipi, metin_ayikla, log_analiz
};

async function satirIsle(satir) {
  satir = satir.trim();
  if (!satir || satir.startsWith("#")) return;
  if (satir === "yardim") {
    for (const [kat, liste] of MODULLER) {
      console.log(`\n▶ ${kat}:`);
      liste.forEach(([cmd, acik]) => console.log(`  • ${cmd.padEnd(34)} : ${acik}`));
    }
    return;
  }
  const m = satir.match(/^([a-z0-9_]+)\((.*)\)$/i);
  if (!m) return console.log("[!] Geçersiz komut biçimi. Liste için 'yardim' yazın.");
  const fn = m[1];
  const args = m[2].trim() ? m[2].split(",").map(a => a.trim().replace(/^["']|["']$/g, "")) : [];
  if (ARAC_HARITASI[fn]) await ARAC_HARITASI[fn](...args);
  else console.log(`[!] Bilinmeyen komut: '${fn}'. Liste için 'yardim' yazın.`);
}

async function tuiBaslat() {
  const rl = readline.createInterface({ input: process.stdin, output: process.stdout });
  const sor = q => new Promise(r => rl.question(q, r));
  while (true) {
    console.clear();
    console.log("╔══════════════════════════════════════════════════════════╗");
    console.log("║     🛡️  ALFSEC v10.0 — TÜRKÇE SİBER GÜVENLİK TUI         ║");
    console.log("╠══════════════════════════════════════════════════════════╣");
    MODULLER.forEach(([kat], i) => console.log(`  [${i + 1}] ${kat}`));
    console.log("  [K] Klasik Komut Satırı Moduna Geç (CLI)");
    console.log("  [0] Çıkış");
    console.log("╚══════════════════════════════════════════════════════════╝");
    const sec = (await sor("\nSeçiminiz: ")).trim().toLowerCase();
    if (sec === "0") { rl.close(); process.exit(0); }
    if (sec === "k") { rl.close(); return "cli"; }
    const idx = Number(sec) - 1;
    if (MODULLER[idx]) {
      const [kat, liste] = MODULLER[idx];
      while (true) {
        console.clear();
        console.log(`╔══ ${kat.toUpperCase()} ══╗`);
        liste.forEach(([cmd, acik], j) => console.log(`  [${j + 1}] ${cmd}\n      ↳ ${acik}`));
        console.log("  [0] Üst Menüye Dön");
        const mSec = (await sor("\nModül seçin: ")).trim();
        if (mSec === "0") break;
        const mod = liste[Number(mSec) - 1];
        if (mod) {
          console.log(`\n[BİLGİ] ${mod[1]}\n[ÖRNEK] ${mod[2]}`);
          const giris = (await sor("Komut (Enter = Örnek): ")).trim() || mod[2];
          console.log("\n--- SONUÇ ---");
          await satirIsle(giris);
          await sor("\nDevam etmek için Enter'a basın...");
        }
      }
    }
  }
}

function guiBaslat() {
  const docsJson = JSON.stringify(MODULLER);
  const HTML = `<!DOCTYPE html><html lang="tr"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
  <title>AlfSec v10.0 — Türkçe OSINT & Pentest Paneli</title>
  <style>body{background:#090d16;color:#e2e8f0;font-family:system-ui,sans-serif;margin:0;padding:14px}
  h2{color:#38bdf8;margin:0 0 12px 0;font-size:18px}.kart{background:#111827;border:1px solid #1e293b;border-radius:10px;padding:12px;margin-bottom:12px}
  input{width:100%;box-sizing:border-box;background:#090d16;border:1px solid #334155;color:#fff;padding:10px;border-radius:8px;font-family:monospace;margin-bottom:8px}
  button{background:#0284c7;color:#fff;border:none;padding:8px 12px;border-radius:6px;font-weight:600;cursor:pointer;margin:2px}
  button.alt{background:#1e293b;color:#38bdf8;border:1px solid #334155}
  pre{background:#05080f;border:1px solid #1e293b;color:#22c55e;padding:12px;border-radius:8px;min-height:150px;white-space:pre-wrap;font-size:12px}</style></head>
  <body><h2>🛡️ AlfSec v10.0 — Türkçe Siber Güvenlik & OSINT Merkezi</h2>
  <div class="kart"><input id="c" value='tam_analiz("kripto-hat.onrender.com")'><button onclick="calistir(document.getElementById('c').value)">Komutu Çalıştır</button>
  <button class="alt" onclick="calistir('sistem_bilgi()')">Sistem Durumu</button><button class="alt" onclick="calistir('dis_ip()')">Dış IP</button></div>
  <div class="kart"><pre id="o">Hazır. Aşağıdaki kategorilerden bir modül seçip tek tıkla Türkçe rapor alabilirsiniz.</pre></div>
  <div id="moduller"></div>
  <script>const M=${docsJson};async function calistir(cmd){document.getElementById('c').value=cmd;document.getElementById('o').textContent='⏳ Çalıştırılıyor: '+cmd+'...';const r=await fetch('/run?c='+encodeURIComponent(cmd));document.getElementById('o').textContent=await r.text();}
  const alan=document.getElementById('moduller');M.forEach(([kat,list])=>{let h='<div class="kart"><h3 style="color:#38bdf8;margin-top:0;font-size:14px">📂 '+kat+'</h3>';list.forEach(([cmd,acik,ornek])=>{const esc=ornek.replace(/"/g,'&quot;');h+='<div style="padding:6px 0;border-bottom:1px solid #1e293b;display:flex;justify-content:space-between;align-items:center;gap:8px"><div><b style="color:#22c55e;font-family:monospace">'+cmd+'</b><div style="font-size:12px;color:#94a3b8">'+acik+'</div></div><button class="alt" onclick="calistir(\\''+esc+'\\')">Çalıştır</button></div>';});alan.innerHTML+=h+'</div>';});</script></body></html>`;
  http.createServer(async (req, res) => {
    const u = new URL(req.url, "http://localhost");
    if (u.pathname === "/") { res.writeHead(200, { "Content-Type": "text/html; charset=utf-8" }); return res.end(HTML); }
    if (u.pathname === "/run") {
      let out = ""; const orig = console.log; console.log = (...a) => { out += a.join(" ") + "\n"; };
      await satirIsle(u.searchParams.get("c") || ""); console.log = orig;
      res.writeHead(200, { "Content-Type": "text/plain; charset=utf-8" }); return res.end(out || "[✓] Tamamlandı.");
    }
  }).listen(8080, "127.0.0.1", () => {
    console.log("[*] AlfSec v10.0 Web GUI hazır: http://127.0.0.1:8080");
    try { require("child_process").exec("termux-open-url http://127.0.0.1:8080 || xdg-open http://127.0.0.1:8080"); } catch {}
  });
}

(async () => {
  const args = process.argv.slice(2);
  if (args[0] === "gui") return guiBaslat();
  if (args[0] === "tui") { if (await tuiBaslat() !== "cli") return; }
  if (args[0] === "-c" && args[1]) return await satirIsle(args.slice(1).join(" "));
  console.log("=== ALFSEC v10.0 — TÜRKÇE SİBER GÜVENLİK KONSOLU ('yardim' | 'tui' | 'cikis') ===");
  const rl = readline.createInterface({ input: process.stdin, output: process.stdout, prompt: "\nalfsec> " });
  rl.prompt();
  rl.on("line", async line => {
    const g = line.trim();
    if (["cikis", "exit"].includes(g.toLowerCase())) process.exit(0);
    if (g.toLowerCase() === "tui") { rl.close(); await tuiBaslat(); return; }
    await satirIsle(g); rl.prompt();
  });
})();
