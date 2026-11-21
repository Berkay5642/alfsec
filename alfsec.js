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
const { execSync, execFileSync } = require("child_process");

const KASA_YOLU = path.join(os.homedir(), ".alfsec_kasa.json");

// === YENİ YARDIMCI: güvenli varlık kontrolü (shell'siz) ===
function _aracVarMi(cmd) {
  if (!/^[a-zA-Z0-9._-]+$/.test(cmd)) return false;
  const yollar = (process.env.PATH || "").split(path.delimiter);
  for (const y of yollar) {
    if (!y) continue;
    try {
      const tam = path.join(y, cmd);
      const st = fs.statSync(tam);
      if (st.isFile() && (st.mode & 0o111)) return true;
    } catch {}
  }
  return false;
}

function _anahtarTuret(parola, salt) { return crypto.scryptSync(parola, salt, 32); }
function _temizDomain(hedef) { return String(hedef || "").replace(/^https?:\/\//i, "").split("/")[0].split(":")[0].trim(); }

// === YENİ YARDIMCI: SSRF koruması (özel/yerel ağ tespiti) ===
function _isPrivateHost(hostname) {
  const h = String(hostname || "").toLowerCase().replace(/^\[|\]$/g, "");
  if (!h) return true;
  if (h === "localhost" || h === "ip6-localhost" || h === "ip6-loopback") return true;
  if (h === "0.0.0.0") return true;
  const v4 = h.match(/^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/);
  if (v4) {
    const a = Number(v4[1]), b = Number(v4[2]);
    if (a === 0 || a === 10 || a === 127) return true;
    if (a === 169 && b === 254) return true;
    if (a === 172 && b >= 16 && b <= 31) return true;
    if (a === 192 && b === 168) return true;
    if (a === 100 && b >= 64 && b <= 127) return true;
    if (a >= 224) return true;
    return false;
  }
  if (h.includes(":")) {
    if (h === "::1" || h === "::") return true;
    if (/^fe80:/i.test(h)) return true;
    if (/^fc[0-9a-f]{2}:/i.test(h) || /^fd[0-9a-f]{2}:/i.test(h)) return true;
    if (/^::ffff:127\./i.test(h)) return true;
    if (/^::ffff:(10|127|169\.254|192\.168|172\.(1[6-9]|2[0-9]|3[01]))/i.test(h)) return true;
  }
  return false;
}

// === YENİ YARDIMCI: HTML kaçış (XSS koruması) ===
function escapeHtml(s) {
  return String(s ?? "").replace(/[&<>"']/g, c => ({
    "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;"
  }[c]));
}

// === YENİ YARDIMCI: SOCKS5 (Tor) TCP soketi — fail-closed ===
function _socks5Socket(proxyHost, proxyPort, hedefHost, hedefPort) {
  return new Promise((resolve, reject) => {
    const s = net.connect({ host: proxyHost, port: proxyPort });
    let stage = 0;
    const zaman = setTimeout(() => { s.destroy(); reject(new Error("SOCKS5 zaman aşımı")); }, 5000);
    s.on("error", e => { clearTimeout(zaman); reject(e); });
    s.on("connect", () => s.write(Buffer.from([0x05, 0x01, 0x00])));
    s.on("data", buf => {
      if (stage === 0) {
        if (buf[0] !== 0x05 || buf[1] !== 0x00) { clearTimeout(zaman); s.destroy(); return reject(new Error("SOCKS5 kimlik doğrulama reddedildi")); }
        stage = 1;
        const hb = Buffer.from(hedefHost, "utf8");
        const req = Buffer.concat([
          Buffer.from([0x05, 0x01, 0x00, 0x03, hb.length]),
          hb,
          Buffer.from([(hedefPort >> 8) & 0xff, hedefPort & 0xff])
        ]);
        s.write(req);
      } else if (stage === 1) {
        if (buf[0] !== 0x05 || buf[1] !== 0x00) { clearTimeout(zaman); s.destroy(); return reject(new Error("SOCKS5 bağlantı reddedildi (kod: " + buf[1] + ")")); }
        clearTimeout(zaman);
        s.removeAllListeners("data");
        s.removeAllListeners("error");
        resolve(s);
      }
    });
  });
}

async function _httpGet(url, opts = {}) {
  const u = new URL(url);
  const izinVer = process.env.ALFSEC_ALLOW_LOCAL === "1";
  if (!izinVer && _isPrivateHost(u.hostname)) {
    throw new Error(`SSRF koruması: özel/yerel ağa istek engellendi (${u.hostname}). Test için ALFSEC_ALLOW_LOCAL=1 ayarlayın.`);
  }
  const maxBody = Math.min(Number(opts.maxBody) || 200000, 500000);
  const timeout = Number(opts.timeout) || 8000;
  const isHttps = u.protocol === "https:";
  const port = Number(u.port) || (isHttps ? 443 : 80);
  const useTor = process.env.ALFSEC_USE_TOR === "1";

  let socket = null;
  if (useTor) {
    try {
      socket = await _socks5Socket("127.0.0.1", 9050, u.hostname, port);
    } catch (e) {
      throw new Error(`Tor modu aktif (ALFSEC_USE_TOR=1) ancak SOCKS5 127.0.0.1:9050 erişilemedi: ${e.message}. Gerçek IP sızıntısı engellendi.`);
    }
  }

  return new Promise((resolve, reject) => {
    const mod = isHttps ? https : http;
    const reqOpts = {
      method: "GET",
      hostname: u.hostname,
      port,
      path: (u.pathname || "/") + (u.search || ""),
      headers: { "User-Agent": "Mozilla/5.0 (Linux; AlfSec/10.5)", ...(opts.headers || {}) },
      timeout,
      agent: false
    };

    let req;
    if (useTor && socket) {
      if (isHttps) {
        const tlsSock = tls.connect({ socket, servername: u.hostname, rejectUnauthorized: true });
        req = mod.request({ ...reqOpts, createConnection: () => tlsSock });
      } else {
        req = mod.request({ ...reqOpts, createConnection: () => socket });
      }
    } else {
      req = mod.request(reqOpts);
    }

    req.on("timeout", () => { req.destroy(); reject(new Error("Zaman aşımı")); });
    req.on("error", reject);
    req.on("response", res => {
      const chunks = [];
      let size = 0, bitti = false;
      const bitir = () => {
        if (bitti) return; bitti = true;
        resolve({ status: res.statusCode, headers: res.headers, body: Buffer.concat(chunks).toString("utf8") });
      };
      res.on("data", c => {
        if (size < maxBody) { chunks.push(c); size += c.length; }
        if (size >= maxBody) res.destroy();
      });
      res.on("end", bitir);
      res.on("error", bitir);
      res.on("aborted", bitir);
      res.on("close", bitir);
    });
    req.end();
  });
}

// ==========================================
// 1. PASİF OSINT & İSTİHBARAT (10 MODÜL)
// ==========================================
async function kullanici_ara(kullanici) {
  kullanici = String(kullanici || "").replace(/^@/, "").trim();
  if (!/^[a-zA-Z0-9._-]{1,64}$/.test(kullanici)) {
    return console.log("[!] Geçersiz kullanıcı adı biçimi.");
  }
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
  if (!/^[a-zA-Z0-9]([a-zA-Z0-9.-]*[a-zA-Z0-9])?$/.test(domain) || domain.length > 253) {
    return console.log("[!] Geçersiz alan adı biçimi.");
  }
  console.log(`=== WHOIS ALAN ADI KİMLİĞİ: ${domain} ===`);
  if (!_aracVarMi("whois")) return console.log("  [!] Sistemde 'whois' aracı yok (Kurulum: pkg install whois veya apt install whois).");
  try {
    const ham = execFileSync("whois", [domain], { encoding: "utf8", timeout: 8000, maxBuffer: 2 * 1024 * 1024 });
    const sozluk = {
      "registrar:": "Kayıt Kuruluşu",
      "creation date:": "Oluşturulma Tarihi",
      "registry expiry date:": "Bitiş Tarihi",
      "updated date:": "Son Güncelleme",
      "name server:": "İsim Sunucusu"
    };
    for (const s of ham.split(/\r?\n/)) {
      const alt = s.toLowerCase().trim();
      for (const [en, tr] of Object.entries(sozluk)) {
        if (alt.startsWith(en)) console.log(`  • ${tr.padEnd(20)}: ${s.split(":").slice(1).join(":").trim()}`);
      }
    }
  } catch (e) {
    console.log(`[!] WHOIS sorgusu başarısız: ${e.message}`);
  }
}

async function subdomain_bul(domain) {
  domain = _temizDomain(domain);
  if (!/^[a-zA-Z0-9.-]+$/.test(domain)) return console.log("[!] Geçersiz alan adı.");
  console.log(`[*] ${domain} için alt alan adları (Sertifika Şeffaflığı) taranıyor...`);
  try {
    const r = await _httpGet(`https://crt.sh/?q=%25.${encodeURIComponent(domain)}&output=json`, { maxBody: 400000, timeout: 12000 });
    const subs = [...new Set(JSON.parse(r.body).map(x => x.name_value.toLowerCase().trim()).filter(x => !x.includes("*")))].sort();
    subs.slice(0, 35).forEach(s => console.log(`  [+] ${s}`));
    console.log(`[✓] Toplam ${subs.length} benzersiz alt alan adı bulundu.`);
  } catch { console.log("[!] Sertifika kayıtları şu an alınamadı."); }
}

async function ip_analiz(ip = "") {
  ip = String(ip || "").trim();
  if (ip && !/^[a-zA-Z0-9.:_-]{1,64}$/.test(ip)) {
    return console.log("[!] Geçersiz IP/hostname biçimi.");
  }
  try {
    const r = await _httpGet(`http://ip-api.com/json/${encodeURIComponent(ip)}?lang=tr`);
    const j = JSON.parse(r.body);
    if (j.status !== "success") return console.log(`[!] IP bilgisi alınamadı: ${j.message}`);
    console.log(`=== IP COĞRAFİ & AĞ ANALİZİ: ${j.query} ===`);
    console.log(`  • Konum    : ${j.country} / ${j.regionName} / ${j.city}`);
    console.log(`  • Sağlayıcı: ${j.isp} (${j.org})`);
    console.log(`  • ASN Kodu : ${j.as}`);
  } catch (e) { console.log(`[HATA] ${e.message}`); }
}

async function ters_dns(ip) {
  ip = String(ip || "").trim();
  if (!/^[a-zA-Z0-9.:_-]{1,64}$/.test(ip)) return console.log("[!] Geçersiz IP biçimi.");
  try {
    const hostlar = await dns.reverse(ip);
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
  console.log(`\n╔══════════════════════════════════════════════════════╗\n║   ALFSEC v10.5 — OTOMATİK TAM OSINT & GÜVENLİK RAPORU║\n╚══════════════════════════════════════════════════════╝`);
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
async function guncelle() {
  const url = "https://raw.githubusercontent.com/Berkay5642/alfsec/main/alfsec.js";
  const hedef = process.argv[1];
  console.log("[*] GitHub deposundan en güncel AlfSec sürümü kontrol ediliyor...");
  if (!hedef || !fs.existsSync(hedef)) {
    return console.log("[!] Hedef betik yolu tespit edilemedi; güncelleme iptal edildi.");
  }
  try {
    const r = await _httpGet(url, { timeout: 12000, maxBody: 500000 });
    if (r.status !== 200 || !r.body.includes("ALFSEC") || r.body.length < 1000) {
      return console.log("[!] Güncelleme dosyası doğrulanamadı (HTTP " + r.status + ").");
    }
    const gecici = hedef + ".tmp";
    const yedek = hedef + ".bak";
    try { fs.copyFileSync(hedef, yedek); } catch {}
    fs.writeFileSync(gecici, r.body, "utf8");
    fs.renameSync(gecici, hedef);
    fs.chmodSync(hedef, 0o755);
    console.log("[✓] AlfSec başarıyla güncellendi! Değişikliklerin aktif olması için aracı yeniden başlatın.");
    console.log(`    Yedek: ${yedek}`);
  } catch (e) {
    console.log("[HATA] Güncelleme başarısız: " + e.message);
  }
}

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
  if (!/^[a-zA-Z0-9.-]+$/.test(hedef) || hedef.length > 253) {
    return console.log("[!] Geçersiz hedef biçimi (nmap için).");
  }
  if (_aracVarMi("nmap")) {
    console.log(`=== NMAP TÜRKÇE SERVİS & PORT RAPORU: ${hedef} ===`);
    try {
      const ham = execFileSync(
        "nmap",
        ["-sV", "-T4", "--top-ports", "100", "--", hedef],
        { encoding: "utf8", timeout: 25000, maxBuffer: 4 * 1024 * 1024 }
      );
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
    const host = _temizDomain(hedef);
    if (!/^[a-zA-Z0-9.-]+$/.test(host)) { console.log("[!] Geçersiz hedef."); return resolve(); }
    const pNo = Number(port);
    if (!Number.isInteger(pNo) || pNo < 1 || pNo > 65535) { console.log("[!] Geçersiz port."); return resolve(); }
    const s = new net.Socket(); s.setTimeout(2500);
    s.connect(pNo, host, () => s.write(`HEAD / HTTP/1.0\r\nHost: ${host}\r\n\r\n`));
    s.on("data", d => { console.log(`=== BANNER (${host}:${pNo}) ===\n${d.toString("utf8").split("\r\n\r\n")[0]}`); s.destroy(); });
    s.on("error", e => { console.log(`[HATA] ${e.message}`); resolve(); });
    s.on("timeout", () => { console.log("[!] Servis yanıt vermedi."); s.destroy(); });
    s.on("close", resolve);
  });
}

function yerel_ag_tara(onek = "192.168.1") {
  return new Promise(resolve => {
    if (!/^\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(onek)) {
      console.log("[!] Geçersiz ağ öneki. Örnek: yerel_ag_tara(\"192.168.1\")");
      return resolve();
    }
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
    s.setTimeout(8000, () => { console.log("[!] SSL zaman aşımı."); s.destroy(); resolve(); });
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
    req.setTimeout(8000, () => { req.destroy(); console.log("[!] OPTIONS zaman aşımı."); resolve(); });
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
    if (raw.length < 44) throw new Error("şifreli veri çok kısa");
    const salt = raw.subarray(0, 16);
    const iv = raw.subarray(16, 28);
    const tag = raw.subarray(28, 44);
    const enc = raw.subarray(44);
    const decipher = crypto.createDecipheriv("aes-256-gcm", _anahtarTuret(String(parola), salt), iv);
    decipher.setAuthTag(tag);
    console.log(`[ÇÖZÜLEN METİN] ${Buffer.concat([decipher.update(enc), decipher.final()]).toString("utf8")}`);
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


// ==========================================
// 6. AKILLI DENETİM & RAPORLAMA (v10.5 İMZA MODÜLLERİ)
// ==========================================
async function guvenlik_karnesi(domain) {
  domain = _temizDomain(domain);
  console.log(`╔══════════════════════════════════════════════════════╗`);
  console.log(`║     🎓 ALFSEC v10.5 — 100 PUANLIK GÜVENLİK KARNESİ   ║`);
  console.log(`╚══════════════════════════════════════════════════════╝`);
  console.log(`Hedef: ${domain} | İnceleme Başlatılıyor...\n`);

  let puan = 100;
  const eksikler = [];
  const artilar = [];

  const txt = await dns.resolveTxt(domain).catch(() => []);
  const dmarc = await dns.resolveTxt(`_dmarc.${domain}`).catch(() => []);
  const spf = txt.map(t => t.join("")).find(t => t.toLowerCase().startsWith("v=spf1"));
  if (spf) artilar.push("SPF e-posta sahtecilik koruması aktif (+10)");
  else { puan -= 10; eksikler.push("[-10 Puan] SPF kaydı eksik -> Alan adınız üzerinden sahte e-posta gönderilebilir."); }

  if (dmarc.length) artilar.push("DMARC politikası tanımlı (+10)");
  else { puan -= 10; eksikler.push("[-10 Puan] DMARC kaydı yok -> Oltalama saldırılarına karşı alan adı itibarı savunmasız."); }

  try {
    const r = await _httpGet(`https://${domain}`);
    const h = r.headers;
    artilar.push("HTTPS bağlantısı aktif (+15)");
    if (h["strict-transport-security"]) artilar.push("HSTS (Zorunlu HTTPS) aktif (+15)");
    else { puan -= 15; eksikler.push("[-15 Puan] HSTS başlığı eksik -> Araya girme (MITM) saldırılarında HTTP'ye düşürülebilir."); }

    if (h["content-security-policy"]) artilar.push("CSP (XSS Kalkanı) yapılandırılmış (+15)");
    else { puan -= 15; eksikler.push("[-15 Puan] Content-Security-Policy (CSP) eksik -> Zararlı betik (XSS) riski artar."); }

    if (h["x-frame-options"]) artilar.push("Clickjacking koruması aktif (+10)");
    else { puan -= 10; eksikler.push("[-10 Puan] X-Frame-Options eksik -> Site sahte bir iframe içine gömülebilir."); }

    if (h["x-content-type-options"]) artilar.push("MIME-Sniffing koruması aktif (+5)");
    else { puan -= 5; eksikler.push("[-5 Puan] X-Content-Type-Options: nosniff başlığı eksik."); }

    if (h["x-powered-by"]) { puan -= 5; eksikler.push(`[-5 Puan] Sunucu altyapı bilgisini (${h["x-powered-by"]}) açıkça sızdırıyor.`); }
  } catch {
    puan -= 40;
    eksikler.push("[-40 Puan] HTTPS bağlantısı kurulamadı veya sunucu yanıt vermedi.");
  }

  puan = Math.max(0, puan);
  const harf = puan >= 90 ? "A+ (MÜKEMMEL)" : puan >= 75 ? "B (İYİ)" : puan >= 55 ? "C (ORTA - İYİLEŞTİRME GEREKLİ)" : puan >= 35 ? "D (ZAYIF)" : "F (KRİTİK RİSK)";

  console.log(`📊 GENEL GÜVENLİK SKORU : ${puan} / 100  |  DERECE: ${harf}\n`);
  console.log("✅ GÜÇLÜ YÖNLER:");
  artilar.forEach(a => console.log(`   • ${a}`));
  console.log("\n⚠️ TESPİT EDİLEN EKSİKLER & ÇÖZÜM ÖNERİLERİ:");
  if (!eksikler.length) console.log("   • Tebrikler! Temel web ve DNS güvenlik katmanlarının tamamı aktif.");
  else eksikler.forEach(e => console.log(`   • ${e}`));
  return { domain, puan, harf, artilar, eksikler };
}

async function sizinti_kontrol(parola) {
  const p = String(parola || "");
  if (!p) return console.log("[!] Lütfen kontrol edilecek parolayı girin.");
  const sha1 = crypto.createHash("sha1").update(p).digest("hex").toUpperCase();
  const prefix = sha1.slice(0, 5);
  const suffix = sha1.slice(5);
  console.log(`[*] K-Anonimlik (Zero-Knowledge) sorgusu başlatıldı (Önek: ${prefix}***)...`);
  console.log(`[*] Parolanız cihazınızdan dışarı gönderilmiyor, yalnızca ilk 5 hash karakteri sorgulanıyor.`);
  try {
    const r = await _httpGet(`https://api.pwnedpasswords.com/range/${prefix}`);
    const satirlar = r.body.split(/\r?\n/);
    const eslesen = satirlar.find(s => s.startsWith(suffix + ":"));
    if (eslesen) {
      const sayi = Number(eslesen.split(":")[1]).toLocaleString("tr-TR");
      console.log(`\n🚨 [TEHLİKE] Bu parola küresel veri sızıntılarında tam ${sayi} KEZ ele geçirilmiş!`);
      console.log(`   ↳ Öneri: Bu parolayı hiçbir hesabınızda kullanmayın ve derhal değiştirin.`);
    } else {
      console.log(`\n✅ [TEMİZ] Bu parola bilinen küresel veri sızıntı listelerinde bulunamadı.`);
    }
  } catch (e) {
    console.log(`[HATA] Sızıntı veritabanına ulaşılamadı: ${e.message}`);
  }
}

async function oltalama_analiz(supheliUrl) {
  let ham = String(supheliUrl || "").trim();
  if (!ham.startsWith("http")) ham = "https://" + ham;
  console.log(`=== OLTALAMA (PHISHING) & SAHTE LİNK ANALİZİ ===`);
  console.log(`İncelenen Bağlantı: ${ham}\n`);
  let risk = 0;
  const bulgular = [];

  try {
    const u = new URL(ham);
    const host = u.hostname.toLowerCase();

    if (u.username || u.password || /^[a-z]+:\/\/[^/?#]*@/i.test(ham)) {
      risk += 50;
      bulgular.push("[+50 Risk] URL içinde '@' userinfo hilesi tespit edildi (gerçek hedef gizleniyor).");
    }
    if (u.protocol === "http:") { risk += 25; bulgular.push("[+25 Risk] Bağlantı şifresiz (HTTP) kullanıyor."); }

    if (host.startsWith("xn--") || host.includes(".xn--")) {
      risk += 40;
      bulgular.push("[+40 Risk] Punycode (IDN Homograph) karakter hilesi tespit edildi!");
    }
    if (/^\d+\.\d+\.\d+\.\d+$/.test(host)) { risk += 35; bulgular.push("[+35 Risk] Alan adı yerine doğrudan ham IP adresi kullanılıyor."); }
    if (host.split(".").length > 3) { risk += 20; bulgular.push("[+20 Risk] Çok katmanlı şüpheli alt alan adı yapısı."); }

    const guvenliDomainler = ["turkiye.gov.tr", "papara.com", "ziraatbank.com.tr", "garantibbva.com.tr"];
    const guvenliMi = guvenliDomainler.some(d => host === d || host.endsWith("." + d));
    const taklitAnahtar = /(giris|login|verify|onay|iade|hediye|destek|guncelle|kargo|edevlet|papara|ziraat|garanti)/i;
    if (taklitAnahtar.test(host) && !guvenliMi) {
      risk += 35;
      bulgular.push("[+35 Risk] Alan adında kurumsal marka/işlem taklidi anahtar kelimesi tespit edildi!");
    }

    const r = await _httpGet(ham, { maxBody: 150000 }).catch(() => null);
    if (r) {
      if (r.status >= 300 && r.status < 400 && r.headers.location) {
        risk += 15;
        bulgular.push(`[+15 Risk] Bağlantı başka bir adrese yönlendiriyor -> ${r.headers.location}`);
      }
      if (/type=["']password["']/i.test(r.body)) {
        risk += 20;
        bulgular.push("[+20 Risk] Sayfa içerisinde parola giriş formu (Login) bulunuyor.");
      }
    }

    risk = Math.min(100, risk);
    const karar = risk >= 60 ? "🔴 YÜKSEK OLTALAMA RİSKİ (KESİNLİKLE TIKLAMAYIN)" : risk >= 30 ? "🟡 ŞÜPHELİ BAĞLANTI (DİKKATLİ OLUN)" : "🟢 DÜŞÜK RİSK (BELİRGİN TUZAK İZİ YOK)";
    console.log(`🎯 RİSK SKORU : %${risk}  |  KARAR: ${karar}\n`);
    if (!bulgular.length) console.log("  • Belirgin bir oltalama göstergesi tespit edilmedi.");
    else bulgular.forEach(b => console.log(`  • ${b}`));
  } catch {
    console.log("[!] Geçersiz URL biçimi.");
  }
}

async function rapor_olustur(domain) {
  domain = _temizDomain(domain);
  console.log(`[*] '${domain}' için tam kapsamlı HTML güvenlik raporu hazırlanıyor...`);
  const karne = await guvenlik_karnesi(domain);
  const aKayit = await dns.resolve4(domain).catch(() => ["Bulunamadı"]);
  const mxKayit = await dns.resolveMx(domain).catch(() => []);
  const tarih = new Date().toLocaleString("tr-TR");
  const dosyaAdi = `alfsec_rapor_${domain.replace(/[^a-z0-9.-]/gi, "_")}.html`;
  const kayitYolu = path.join(process.cwd(), dosyaAdi);

  const d = escapeHtml(domain);
  const aStr = aKayit.map(escapeHtml).join(", ");
  const mxStr = mxKayit.map(x => escapeHtml(x.exchange)).join(", ") || "Yok";
  const artilarHtml = karne.artilar.map(x => "<li>" + escapeHtml(x) + "</li>").join("");
  const eksiklerHtml = (karne.eksikler.length ? karne.eksikler : ["Kritik eksik tespit edilmedi."])
    .map(x => "<li>" + escapeHtml(x) + "</li>").join("");
  const puan = Number(karne.puan) || 0;
  const harf = escapeHtml(karne.harf);

  const html = `<!DOCTYPE html><html lang="tr"><head><meta charset="UTF-8"><title>AlfSec Güvenlik Raporu - ${d}</title>
  <style>body{background:#090d16;color:#e2e8f0;font-family:system-ui,sans-serif;padding:24px;max-width:850px;margin:auto}
  .baslik{border-bottom:2px solid #0284c7;padding-bottom:12px;margin-bottom:20px}
  .skor{background:#111827;border:1px solid #1e293b;padding:20px;border-radius:12px;font-size:22px;font-weight:bold;color:#38bdf8;margin-bottom:20px}
  .kutu{background:#111827;border:1px solid #1e293b;padding:16px;border-radius:10px;margin-bottom:16px}
  h3{color:#38bdf8;margin-top:0}li{margin-bottom:6px}</style></head>
  <body><div class="baslik"><h1>🛡️ AlfSec v10.5 — Siber Güvenlik Denetim Raporu</h1><p>Hedef: <b>${d}</b> | Tarih: ${escapeHtml(tarih)}</p></div>
  <div class="skor">Güvenlik Puanı: ${puan} / 100 — ${harf}</div>
  <div class="kutu"><h3>🌐 Temel Ağ & DNS Özeti</h3><p><b>IPv4 Adresleri:</b> ${aStr}</p><p><b>Posta Sunucuları (MX):</b> ${mxStr}</p></div>
  <div class="kutu"><h3>✅ Aktif Güvenlik Katmanları</h3><ul>${artilarHtml}</ul></div>
  <div class="kutu"><h3>⚠️ Tespit Edilen Eksikler & Öneriler</h3><ul>${eksiklerHtml}</ul></div>
  <p style="font-size:12px;color:#64748b;text-align:center">Bu rapor AlfSec v10.5 Türkçe Siber Güvenlik Merkezi tarafından otomatik oluşturulmuştur.</p></body></html>`;

  fs.writeFileSync(kayitYolu, html, "utf8");
  console.log(`\n[✓] Profesyonel HTML rapor kaydedildi: ${kayitYolu}`);
}


// ==========================================
// 7. AĞ MİMARİSİ & ZAFİYET YÜZEYİ (v10.5 MODÜLLERİ)
// ==========================================
function alt_ag_hesapla(cidrGirdi) {
  const ham = String(cidrGirdi || "").trim();
  const parcalar = ham.split("/");
  const ipStr = parcalar[0];
  const prefix = Number(parcalar[1] ?? 24);
  const oktetler = ipStr.split(".").map(Number);

  if (oktetler.length !== 4 || oktetler.some(n => isNaN(n) || n < 0 || n > 255) || isNaN(prefix) || prefix < 0 || prefix > 32) {
    return console.log("[!] Geçersiz CIDR formatı. Örnek kullanım: alt_ag_hesapla(\"192.168.45.142/26\")");
  }

  const ipNum = ((oktetler[0] << 24) | (oktetler[1] << 16) | (oktetler[2] << 8) | oktetler[3]) >>> 0;
  const maskeNum = prefix === 0 ? 0 : ((0xffffffff << (32 - prefix)) >>> 0);
  const agNum = (ipNum & maskeNum) >>> 0;
  const broadcastNum = (agNum | (~maskeNum >>> 0)) >>> 0;
  const toplamAdres = Math.pow(2, 32 - prefix);
  const kullanilabilirHost = prefix >= 31 ? toplamAdres : Math.max(0, toplamAdres - 2);

  const numToIp = n => [(n >>> 24) & 255, (n >>> 16) & 255, (n >>> 8) & 255, n & 255].join(".");
  const ilkHost = prefix >= 31 ? numToIp(agNum) : numToIp((agNum + 1) >>> 0);
  const sonHost = prefix >= 31 ? numToIp(broadcastNum) : numToIp((broadcastNum - 1) >>> 0);

  console.log(`=== IPv4 ALT AĞ (SUBNET) HESAPLAMA: ${ipStr}/${prefix} ===`);
  console.log(`  • Alt Ağ Maskesi    : ${numToIp(maskeNum)} (/ ${prefix})`);
  console.log(`  • Ağ Adresi (Network): ${numToIp(agNum)}`);
  console.log(`  • Yayın (Broadcast)  : ${numToIp(broadcastNum)}`);
  console.log(`  • Kullanılabilir Aralık: ${ilkHost}  -->  ${sonHost}`);
  console.log(`  • Kullanılabilir Host: ${kullanilabilirHost.toLocaleString("tr-TR")} cihaz (Toplam ${toplamAdres.toLocaleString("tr-TR")} adres)`);
}

async function guvenlik_acigi_tarama(domain) {
  domain = _temizDomain(domain);
  const kritikYollar = [
    ["/.git/HEAD", "Açık Git deposu (Kaynak kod sızıntısı riski)"],
    ["/.env", "Ortam değişkenleri dosyası (API anahtarı / şifre sızıntısı riski)"],
    ["/backup.zip", "Yedek arşiv dosyası"],
    ["/db.sql", "Veritabanı dökümü"],
    ["/phpinfo.php", "PHP yapılandırma bilgi sayfası"],
    ["/server-status", "Apache sunucu durum paneli"],
    ["/admin", "Yönetim paneli giriş yolu"],
    ["/wp-config.php.bak", "WordPress yedek yapılandırma dosyası"]
  ];
  console.log(`=== HASSAS DOSYA & YÜZEY TARAMASI: ${domain} ===`);
  let bulgu = 0;
  for (const [yolEk, aciklama] of kritikYollar) {
    try {
      const r = await _httpGet(`https://${domain}${yolEk}`, { maxBody: 30000 });
      if (r.status === 200 || r.status === 403) {
        console.log(`  [${r.status === 200 ? "KRİTİK/AÇIK" : "KISITLI"}] ${yolEk.padEnd(20)} -> HTTP ${r.status} | ${aciklama}`);
        if (r.status === 200) bulgu++;
      }
    } catch {}
  }
  console.log(`[✓] Tarama tamamlandı. Doğrudan açık (HTTP 200) kritik yol sayısı: ${bulgu}`);
}

async function baslik_analiz(domain) {
  domain = _temizDomain(domain);
  try {
    const r = await _httpGet(`https://${domain}`);
    const h = r.headers;
    console.log(`=== HTTP YANIT BAŞLIKLARI DENETİMİ: ${domain} ===`);
    for (const [k, v] of Object.entries(h)) {
      let not = "";
      if (k === "x-powered-by" || k === "server") not = " [Bilgi Sızıntısı / Sürüm İzi]";
      if (k === "access-control-allow-origin" && v === "*") not = " [Tüm Kaynaklara Açık CORS (*)]";
      if (k === "strict-transport-security") not = " [HTTPS Zorlama Kalkanı]";
      if (k === "content-security-policy") not = " [XSS Kalkan Politikası]";
      console.log(`  • ${k}: ${v}${not}`);
    }
  } catch (e) { console.log(`[HATA] ${e.message}`); }
}

async function toplu_hedef_tara(hedefListesi) {
  const hedefler = String(hedefListesi || "").split(",").map(x => _temizDomain(x)).filter(Boolean);
  if (!hedefler.length) return console.log("[!] En az bir hedef girin. Örnek: toplu_hedef_tara(\"google.com,github.com\")");
  console.log(`=== TOPLU HEDEF KARŞILAŞTIRMA (${hedefler.length} Hedef) ===\n`);
  for (const h of hedefler) {
    if (!/^[a-zA-Z0-9.-]+$/.test(h)) { console.log(`  • ${h.padEnd(28)} | GEÇERSİZ HEDEF`); continue; }
    try {
      const r = await _httpGet(`https://${h}`);
      const hsts = r.headers["strict-transport-security"] ? "HSTS:VAR" : "HSTS:YOK";
      const csp = r.headers["content-security-policy"] ? "CSP:VAR" : "CSP:YOK";
      console.log(`  • ${h.padEnd(28)} | HTTP ${String(r.status).padEnd(3)} | ${hsts} | ${csp}`);
    } catch {
      console.log(`  • ${h.padEnd(28)} | ERİŞİM HATASI / ZAMAN AŞIMI`);
    }
  }
}


// ==========================================
// 8. YÜZEY ANALİZİ & URL İNCELEME (v10.5 MODÜLLERİ)
// ==========================================
function url_coz(hamUrl) {
  const ham = String(hamUrl || "").trim();
  if (!ham) return console.log("[!] Çözümlenecek bir URL girin.");
  let cozulmus = ham;
  try { cozulmus = decodeURIComponent(ham); } catch {}
  console.log("=== URL ÇÖZÜMLEME & PARAMETRE ANALİZİ ===");
  console.log(`  • Ham Girdi   : ${ham}`);
  console.log(`  • Çözümlenmiş : ${cozulmus}`);
  try {
    const hedef = cozulmus.startsWith("http") ? cozulmus : "https://" + cozulmus;
    const u = new URL(hedef);
    console.log(`  • Protokol    : ${u.protocol}`);
    console.log(`  • Alan Adı    : ${u.hostname}`);
    console.log(`  • Yol (Path)  : ${u.pathname}`);
    const params = [...u.searchParams.entries()];
    if (params.length) {
      console.log("  • Parametreler:");
      params.forEach(([k, v]) => console.log(`      - ${k} = ${v}`));
    }
  } catch {}
}


// ==========================================
// 9. SAVUNMA, SERVİS REHBERİ & BÜTÜNLÜK (v10.5 MODÜLLERİ)
// ==========================================
function port_rehberi(portNo) {
  const p = Number(portNo);
  const tablo = {
    21: ["FTP", "Dosya Transferi", "Şifresiz kimlik bilgisi riski ve anonim giriş denetimi."],
    22: ["SSH", "Güvenli Uzak Kabuk", "Kaba kuvvet (Brute-Force), anahtar yönetimi ve port yönlendirme."],
    23: ["Telnet", "Şifresiz Uzak Bağlantı", "Veri ve parola trafiği düz metin (cleartext) akar; kapatılmalıdır."],
    25: ["SMTP", "Posta Aktarımı", "Open relay, spam ve sahte gönderici (spoofing) denetimi."],
    53: ["DNS", "Alan Adı Çözümleme", "Zone transfer, DNS amplification ve kayıt doğrulama."],
    80: ["HTTP", "Şifresiz Web", "HTTPS yönlendirmesi eksikse araya girme (MITM) riski."],
    110: ["POP3", "E-posta Alma", "Şifresiz bağlantı yerine POP3S (995) tercih edilmelidir."],
    143: ["IMAP", "E-posta Erişimi", "Şifresiz bağlantı yerine IMAPS (993) tercih edilmelidir."],
    443: ["HTTPS", "Şifreli Web (TLS)", "Sertifika geçerliliği, TLS sürümü ve HSTS kontrolü."],
    445: ["SMB", "Windows Dosya Paylaşımı", "Ağ içi yanal hareket ve zafiyet yamaları açısından kritik port."],
    3306: ["MySQL", "Veritabanı Servisi", "Dış internete açık bırakılmamalı, yalnızca yetkili IP'lere açılmalı."],
    3389: ["RDP", "Uzak Masaüstü", "Dış ağa açık bırakıldığında yüksek kaba kuvvet hedefidir."],
    5432: ["PostgreSQL", "Veritabanı Servisi", "Ağ erişim kuralları ve güçlü kimlik doğrulama gerekir."],
    6379: ["Redis", "Bellek İçi Veri Deposu", "Parolasız veya dışa açık bırakıldığında kritik veri riski taşır."],
    8080: ["HTTP-Alt", "Alternatif Web / Proxy", "Geliştirme panelleri veya ters proxy servisleri sıkça burada çalışır."]
  };

  if (!p || p < 1 || p > 65535) {
    return console.log("[!] Geçerli bir port numarası girin (1-65535). Örnek: port_rehberi(445)");
  }

  const kayit = tablo[p];
  console.log(`=== PORT REHBERİ: TCP/UDP ${p} ===`);
  if (kayit) {
    console.log(`  • Yaygın Servis : ${kayit[0]} (${kayit[1]})`);
    console.log(`  • Güvenlik Notu : ${kayit[2]}`);
  } else {
    const bolge = p <= 1023 ? "Well-Known (Sistem/Yetkili Port)" : p <= 49151 ? "Registered (Kayıtlı Uygulama Portu)" : "Dynamic/Ephemeral (Dinamik Port)";
    console.log(`  • Port Sınıfı   : ${bolge}`);
    console.log(`  • Güvenlik Notu : Açık ise hangi uygulamanın dinlediği 'servis_banner' veya 'nmap_turkce' ile doğrulanmalıdır.`);
  }
}

async function dns_guvenlik(domain) {
  domain = _temizDomain(domain);
  console.log(`=== DNS & E-POSTA GÜVENLİK DENETİMİ: ${domain} ===`);
  const ns = await dns.resolveNs(domain).catch(() => []);
  const txt = await dns.resolveTxt(domain).catch(() => []);
  const dmarc = await dns.resolveTxt(`_dmarc.${domain}`).catch(() => []);
  const duzTxt = txt.map(t => t.join(""));
  const spf = duzTxt.find(t => t.toLowerCase().startsWith("v=spf1"));

  console.log(`  • NS Sunucuları : ${ns.length ? ns.join(", ") : "Bulunamadı"}`);
  console.log(`  • SPF Kaydı     : ${spf ? "VAR (" + spf + ")" : "EKSİK"}`);
  console.log(`  • DMARC Kaydı   : ${dmarc.length ? "VAR (" + dmarc.map(x => x.join("")).join(" | ") + ")" : "EKSİK"}`);

  if (!spf || !dmarc.length) {
    console.log("  ⚠️ Uyarı: SPF veya DMARC eksikliği alan adınız adına sahte e-posta gönderilmesini kolaylaştırabilir.");
  } else {
    console.log("  ✅ Temel e-posta kimlik doğrulama (SPF + DMARC) kayıtları mevcut.");
  }
}

function metin_temizle_analiz(girdi) {
  const ham = String(girdi ?? "");
  const gorunmeyenSayisi = (ham.match(/[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]/g) || []).length;
  const temiz = ham.replace(/[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]/g, "");
  const base64Benzeri = /[A-Za-z0-9+/]{24,}={0,2}/.test(temiz);
  const urlBenzeri = /https?:\/\/[^\s]+/i.test(temiz);

  console.log("=== METİN & GİRDİ GÜVENLİK ANALİZİ ===");
  console.log(`  • Uzunluk             : ${ham.length} karakter (Temizlenmiş: ${temiz.length})`);
  console.log(`  • Gizli Kontrol Baytı : ${gorunmeyenSayisi} adet`);
  console.log(`  • Base64 Benzeri Blok : ${base64Benzeri ? "TESPİT EDİLDİ" : "Yok"}`);
  console.log(`  • Bağlantı İçeriyor mu: ${urlBenzeri ? "EVET (oltalama_analiz ile kontrol önerilir)" : "Hayır"}`);
  console.log(`  • Temiz Çıktı         : ${temiz}`);
}

function ozet_karsilastir(metin1, metin2) {
  const a = String(metin1 ?? "");
  const b = String(metin2 ?? "");
  const h1 = crypto.createHash("sha256").update(a).digest("hex");
  const h2 = crypto.createHash("sha256").update(b).digest("hex");
  const esit = h1 === h2;

  console.log("=== SHA-256 BÜTÜNLÜK & EŞLEŞME KARŞILAŞTIRMA ===");
  console.log(`  • 1. Girdi SHA-256 : ${h1}`);
  console.log(`  • 2. Girdi SHA-256 : ${h2}`);
  console.log(`  • Sonuç            : ${esit ? "✅ EŞLEŞİYOR (Birebir aynı)" : "❌ EŞLEŞMİYOR (Farklı)"}`);
}


// ==========================================
// 10. İLERİ WEB GÜVENLİĞİ TESTLERİ (v10.5 YENİ MODÜLLER)
// ==========================================
async function sertifika_zincir(domain) {
  domain = _temizDomain(domain);
  if (!/^[a-zA-Z0-9.-]+$/.test(domain) || domain.length > 253) {
    return console.log("[!] Geçersiz alan adı biçimi.");
  }
  console.log(`=== SSL/TLS SERTİFİKA ZİNCİRİ & SAN ANALİZİ: ${domain} ===`);
  return new Promise(resolve => {
    let bitti = false;
    const bitir = () => { if (!bitti) { bitti = true; resolve(); } };
    const s = tls.connect(443, domain, { servername: domain, rejectUnauthorized: false }, () => {
      try {
        let cert = s.getPeerCertificate(true);
        const sanSet = new Set();
        let i = 0;
        const gorulen = new Set();
        while (cert && i < 10) {
          const ozet = (cert.fingerprint256 || "") + "|" + (cert.subject?.CN || "");
          if (gorulen.has(ozet)) break;
          gorulen.add(ozet);
          console.log(`  [${i}] Subject CN: ${cert.subject?.CN || "?"} | Issuer CN: ${cert.issuer?.CN || "?"}`);
          console.log(`      Geçerlilik: ${cert.valid_from || "?"} -> ${cert.valid_to || "?"}`);
          if (cert.subjectaltname) {
            cert.subjectaltname.split(",").forEach(san => sanSet.add(san.trim()));
          }
          if (cert.issuerCertificate && cert.issuerCertificate !== cert) cert = cert.issuerCertificate;
          else break;
          i++;
        }
        if (sanSet.size) {
          console.log(`  • SAN (Alternatif Alan Adları) — ${sanSet.size} adet:`);
          [...sanSet].slice(0, 25).forEach(san => console.log(`      - ${san}`));
          if (sanSet.size > 25) console.log(`      ... (+${sanSet.size - 25} adet daha)`);
        }
        try {
          console.log(`  • Aktif TLS: ${s.getProtocol()} / ${s.getCipher().name}`);
        } catch {}
      } catch (e) {
        console.log(`[!] Zincir analizi hatası: ${e.message}`);
      }
      try { s.end(); } catch {}
      bitir();
    });
    s.on("error", e => { console.log(`[HATA] ${e.message}`); bitir(); });
    s.setTimeout(8000, () => { console.log("[!] SSL zaman aşımı."); try { s.destroy(); } catch {} bitir(); });
  });
}

async function csrf_denetle(url) {
  const hedef = String(url || "").trim();
  if (!hedef) return console.log("[!] Denetlenecek URL girin. Örnek: csrf_denetle(\"https://site.com/form\")");
  const tam = hedef.startsWith("http") ? hedef : "https://" + hedef;
  console.log(`=== CSRF (SİTE İÇİ İSTEK SAHTECİLİĞİ) DENETİMİ ===`);
  console.log(`İncelenen Sayfa: ${tam}\n`);
  try {
    const r = await _httpGet(tam, { maxBody: 300000 });
    if (r.status !== 200) {
      return console.log(`[!] Sayfa alınamadı (HTTP ${r.status}).`);
    }
    const formRegex = /<form\b[^>]*>([\s\S]*?)<\/form>/gi;
    const formlar = [...r.body.matchAll(formRegex)];
    if (!formlar.length) {
      return console.log("  • Sayfada <form> etiketi bulunamadı.");
    }
    const tokenAdlari = /^(csrf|_csrf|csrfmiddlewaretoken|csrf_token|authenticity_token|_token|__requestverificationtoken|x-csrf-token|xsrf-token|_xsrf)$/i;
    let postSayisi = 0, korumaliSayisi = 0;
    for (let i = 0; i < formlar.length; i++) {
      const form = formlar[i][0];
      const methodM = form.match(/method\s*=\s*["'](post|get)["']/i);
      const method = (methodM ? methodM[1] : "get").toLowerCase();
      if (method !== "post") continue;
      postSayisi++;
      const inputlar = [...form.matchAll(/<input\b[^>]*>/gi)].map(m => m[0]);
      const tokenVar = inputlar.some(inp => {
        const nameM = inp.match(/name\s*=\s*["']([^"']+)["']/i);
        return nameM && tokenAdlari.test(nameM[1]);
      });
      const actionM = form.match(/action\s*=\s*["']([^"']*)["']/i);
      const action = actionM ? actionM[1] : "(kendi sayfası)";
      if (tokenVar) {
        korumaliSayisi++;
        console.log(`  [✓ KORUMALI] ${i + 1}. form POST -> ${action} (CSRF token alanı mevcut)`);
      } else {
        console.log(`  [⚠️ EKSİK] ${i + 1}. form POST -> ${action} (CSRF token alanı YOK)`);
      }
    }
    if (postSayisi === 0) {
      console.log(`  • Toplam ${formlar.length} form var, hiçbiri POST metodu kullanmıyor.`);
    } else {
      console.log(`\n  [ÖZET] ${postSayisi} POST formdan ${korumaliSayisi} tanesi CSRF token içeriyor.`);
      if (korumaliSayisi < postSayisi) {
        console.log(`  🚨 [RİSK] ${postSayisi - korumaliSayisi} form CSRF korumasından yoksun olabilir.`);
      } else {
        console.log(`  ✅ Tüm POST formlarında token alanı tespit edildi.`);
      }
    }
  } catch (e) {
    console.log(`[HATA] ${e.message}`);
  }
}

async function acik_yonlendirme(url) {
  const hedef = String(url || "").trim();
  if (!hedef) return console.log("[!] Test edilecek URL girin. Örnek: acik_yonlendirme(\"https://site.com/redirect?url=x\")");
  const tam = hedef.startsWith("http") ? hedef : "https://" + hedef;
  console.log(`=== AÇIK YÖNLENDİRME (OPEN REDIRECT) TESTİ ===`);
  let u;
  try { u = new URL(tam); } catch { return console.log("[!] Geçersiz URL biçimi."); }
  if (!/^https?:$/.test(u.protocol)) return console.log("[!] Yalnızca HTTP/HTTPS desteklenir.");
  const testHedef = "https://example.org/alfsec-open-redirect-test";
  const parametreler = ["url", "next", "redirect", "redirect_url", "redirect_uri", "return", "returnUrl", "return_url", "target", "dest", "destination", "continue", "goto", "redir", "r", "u"];
  const mevcut = [...u.searchParams.keys()];
  const adaylar = mevcut.length ? [...new Set([...mevcut, ...parametreler])] : parametreler;
  console.log(`Temel URL: ${u.origin}${u.pathname}`);
  console.log(`Denenecek parametre sayısı: ${adaylar.length}\n`);
  let bulunan = 0, denenen = 0;
  for (const p of adaylar) {
    const deneme = new URL(tam);
    deneme.searchParams.set(p, testHedef);
    try {
      const r = await _httpGet(deneme.toString(), { maxBody: 50000, timeout: 6000 });
      denenen++;
      const loc = r.headers?.location;
      if (r.status >= 300 && r.status < 400 && loc) {
        if (loc.includes("example.org")) {
          console.log(`  🚨 [AÇIK] ?${p}= -> HTTP ${r.status} -> ${loc}`);
          bulunan++;
        } else if (!loc.startsWith(u.origin) && /^https?:\/\//i.test(loc)) {
          console.log(`  ⚠️ [ŞÜPHELİ] ?${p}= -> Harici yönlendirme: ${loc}`);
          bulunan++;
        }
      }
    } catch {}
  }
  console.log(`\n[✓] Test bitti (${denenen}/${adaylar.length} istek atıldı). Açık yönlendirme sinyali: ${bulunan}`);
  if (bulunan > 0) console.log("  ↳ Not: Bu zafiyet oltalama kampanyalarında kullanılabilir. Sunucu tarafında allowlist uygulanmalıdır.");
}


const MODULLER = [
  ["Savunma, Port Rehberi & Bütünlük (v10.5)", [
    ["port_rehberi(445)", "Portun servisini, sınıfını ve güvenlik risklerini Türkçe açıklar.", "port_rehberi(445)"],
    ["dns_guvenlik(\"ornek.com\")", "NS, SPF ve DMARC kayıtlarını denetleyerek e-posta/DNS güvenliğini özetler.", "dns_guvenlik(\"github.com\")"],
    ["metin_temizle_analiz(\"metin\")", "Gizli kontrol karakterlerini, Base64 kalıplarını ve URL varlığını inceler.", "metin_temizle_analiz(\"dGVzdC12ZXJpLTEyMzQ1Njc4OTA=\")"],
    ["ozet_karsilastir(\"a\", \"b\")", "İki metnin SHA-256 özetini çıkarıp birebir eşleşip eşleşmediğini doğrular.", "ozet_karsilastir(\"alfsec\", \"alfsec\")"]
  ]],
  ["İleri Web Güvenliği Testleri (v10.5 YENİ)", [
    ["sertifika_zincir(\"ornek.com\")", "Sunucu sertifikasının tam zincirini ve SAN (alternatif ad) listesini çıkarır.", "sertifika_zincir(\"github.com\")"],
    ["csrf_denetle(\"https://site.com/form\")", "Formlarda CSRF token alanı (hidden input) olup olmadığını denetler.", "csrf_denetle(\"https://github.com/login\")"],
    ["acik_yonlendirme(\"https://site.com/r?url=...\")", "URL parametrelerinde açık yönlendirme (Open Redirect) zafiyetini test eder.", "acik_yonlendirme(\"https://github.com/login?return_to=x\")"]
  ]],
  ["Yüzey Analizi & URL İnceleme (v10.5)", [
    ["guvenlik_acigi_tarama(\"ornek.com\")", ".git, .env, yedek ve kritik yolların dışa açık olup olmadığını denetler.", "guvenlik_acigi_tarama(\"kripto-hat.onrender.com\")"],
    ["baslik_analiz(\"ornek.com\")", "HTTP yanıt başlıklarını bilgi sızıntısı ve güvenlik açısından inceler.", "baslik_analiz(\"kripto-hat.onrender.com\")"],
    ["toplu_hedef_tara(\"site1.com,site2.com\")", "Birden fazla hedefi tek seferde HTTP durum ve kalkan açısından özetler.", "toplu_hedef_tara(\"kripto-hat.onrender.com,github.com\")"],
    ["url_coz(\"url\")", "Kodlanmış URL'leri çözer, alan adını, yolu ve parametreleri ayrıştırır.", "url_coz(\"https%3A%2F%2Fgithub.com%2FBerkay5642%2Falfsec%3Fref%3Dv10.5\")"]
  ]],
  ["Ağ Mimarisi & Zafiyet Yüzeyi (v10.5)", [
    ["alt_ag_hesapla(\"192.168.45.142/26\")", "CIDR bloğunun ağ, broadcast, ilk/son IP ve host kapasitesini hesaplar.", "alt_ag_hesapla(\"192.168.45.142/26\")"],
    ["guvenlik_acigi_tarama(\"ornek.com\")", ".git, .env, yedek ve kritik yolların dışa açık olup olmadığını denetler.", "guvenlik_acigi_tarama(\"kripto-hat.onrender.com\")"],
    ["baslik_analiz(\"ornek.com\")", "HTTP yanıt başlıklarını bilgi sızıntısı ve güvenlik açısından inceler.", "baslik_analiz(\"kripto-hat.onrender.com\")"],
    ["toplu_hedef_tara(\"site1.com,site2.com\")", "Birden fazla hedefi tek seferde HTTP durum ve kalkan açısından özetler.", "toplu_hedef_tara(\"kripto-hat.onrender.com,github.com\")"]
  ]],
  ["Akıllı Denetim & İmza Araçları (4 Özel Modül)", [
    ["guvenlik_karnesi(\"ornek.com\")", "Hedefi tarayıp 100 üzerinden puanlı risk karnesi ve çözüm rehberi çıkarır.", "guvenlik_karnesi(\"kripto-hat.onrender.com\")"],
    ["sizinti_kontrol(\"parola\")", "K-Anonimlik ile parolayı dışarı göndermeden küresel veri sızıntılarında arar.", "sizinti_kontrol(\"123456\")"],
    ["oltalama_analiz(\"supheli_link\")", "Şüpheli linkleri marka taklidi, Punycode ve yönlendirme tuzaklarına karşı inceler.", "oltalama_analiz(\"http://edevlet-iade-onay.com\")"],
    ["rapor_olustur(\"ornek.com\")", "Denetim sonuçlarını şık tasarımlı bir HTML güvenlik raporuna dönüştürür.", "rapor_olustur(\"kripto-hat.onrender.com\")"]
  ]],
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
    ["sistem_bilgi()", "İşletim sistemini ve kurulu güvenlik araçlarını denetler.", "sistem_bilgi()"],
    ["guncelle()", "GitHub deposundan AlfSec'in en son sürümünü otomatik indirip kurar.", "guncelle()"]
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
  port_rehberi, dns_guvenlik, metin_temizle_analiz, ozet_karsilastir, alt_ag_hesapla, guvenlik_acigi_tarama, baslik_analiz, toplu_hedef_tara, url_coz,
  sertifika_zincir, csrf_denetle, acik_yonlendirme,
  guvenlik_karnesi, sizinti_kontrol, oltalama_analiz, rapor_olustur,
  tam_analiz, kullanici_ara, eposta_denetle, dns_detay, whois_sorgu, subdomain_bul, ip_analiz, ters_dns, mac_sorgu, telefon_bilgi,
  nmap_turkce, port_tara, yerel_ag_tara, servis_banner, ag_kimlik, dis_ip, tor_kontrol, sistem_bilgi, guncelle,
  web_denetle, ssl_analiz, teknoloji_bul, robots_oku, cerez_denetle, link_cikar, http_metotlar,
  sifrele, coz, ozetle, base64_kodla, base64_coz, hex_kodla, hex_coz, jwt_coz, sifre_uret, parola_guc, kasa_ekle, kasa_oku,
  dosya_hash, dosya_tipi, metin_ayikla, log_analiz
};

async function satirIsle(satir) {
  satir = satir.trim();
  if (!satir || satir.startsWith("#")) return;
  if (satir === "yardim" || satir === "help" || satir === "--help" || satir === "-h") {
    for (const [kat, liste] of MODULLER) {
      console.log(`\n▶ ${kat}:`);
      liste.forEach(([cmd, acik]) => console.log(`  • ${cmd.padEnd(34)} : ${acik}`));
    }
    console.log("\n▶ Sistem Komutları:");
    console.log("  • tui                                                : Etkileşimli menü modu (TUI)");
    console.log("  • gui                                                : Web GUI (http://127.0.0.1:8080)");
    console.log("  • cikis / exit                                       : Programdan çık");
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
  if (!process.stdout.isTTY || !process.stdin.isTTY) {
    console.log("[!] TUI modu için etkileşimli bir terminal (TTY) gereklidir.");
    console.log("    Boru hattı ortamında 'alfsec -c \"komut\"' veya 'alfsec gui' kullanın.");
    return "cli";
  }
  const rl = readline.createInterface({ input: process.stdin, output: process.stdout });
  const sor = q => new Promise(r => rl.question(q, r));
  while (true) {
    console.clear();
    console.log("╔══════════════════════════════════════════════════════════╗");
    console.log("║     🛡️  ALFSEC v10.5 — TÜRKÇE SİBER GÜVENLİK TUI         ║");
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
  <title>AlfSec v10.5 — Türkçe OSINT & Pentest Paneli</title>
  <style>body{background:#090d16;color:#e2e8f0;font-family:system-ui,sans-serif;margin:0;padding:14px}
  h2{color:#38bdf8;margin:0 0 12px 0;font-size:18px}.kart{background:#111827;border:1px solid #1e293b;border-radius:10px;padding:12px;margin-bottom:12px}
  input{width:100%;box-sizing:border-box;background:#090d16;border:1px solid #334155;color:#fff;padding:10px;border-radius:8px;font-family:monospace;margin-bottom:8px}
  button{background:#0284c7;color:#fff;border:none;padding:8px 12px;border-radius:6px;font-weight:600;cursor:pointer;margin:2px}
  button.alt{background:#1e293b;color:#38bdf8;border:1px solid #334155}
  pre{background:#05080f;border:1px solid #1e293b;color:#22c55e;padding:12px;border-radius:8px;min-height:150px;white-space:pre-wrap;font-size:12px}</style></head>
  <body><h2>🛡️ AlfSec v10.5 — Türkçe Siber Güvenlik & OSINT Merkezi</h2>
  <div class="kart"><input id="c" value='tam_analiz("kripto-hat.onrender.com")'><button onclick="calistir(document.getElementById('c').value)">Komutu Çalıştır</button>
  <button class="alt" onclick="calistir('sistem_bilgi()')">Sistem Durumu</button><button class="alt" onclick="calistir('dis_ip()')">Dış IP</button></div>
  <div class="kart"><pre id="o">Hazır. Aşağıdaki kategorilerden bir modül seçip tek tıkla Türkçe rapor alabilirsiniz.</pre></div>
  <div id="moduller"></div>
  <script>const M=${docsJson};async function calistir(cmd){document.getElementById('c').value=cmd;document.getElementById('o').textContent='⏳ Çalıştırılıyor: '+cmd+'...';const r=await fetch('/run?c='+encodeURIComponent(cmd));document.getElementById('o').textContent=await r.text();}
  const alan=document.getElementById('moduller');M.forEach(([kat,list])=>{let h='<div class="kart"><h3 style="color:#38bdf8;margin-top:0;font-size:14px">📂 '+kat+'</h3>';list.forEach(([cmd,acik,ornek])=>{const esc=ornek.replace(/"/g,'&quot;');h+='<div style="padding:6px 0;border-bottom:1px solid #1e293b;display:flex;justify-content:space-between;align-items:center;gap:8px"><div><b style="color:#22c55e;font-family:monospace">'+cmd+'</b><div style="font-size:12px;color:#94a3b8">'+acik+'</div></div><button class="alt" onclick="calistir(\\''+esc+'\\')">Çalıştır</button></div>';});alan.innerHTML+=h+'</div>';});</script></body></html>`;
  const sunucu = http.createServer(async (req, res) => {
    const u = new URL(req.url, "http://localhost");
    if (u.pathname === "/") { res.writeHead(200, { "Content-Type": "text/html; charset=utf-8" }); return res.end(HTML); }
    if (u.pathname === "/run") {
      let out = ""; const orig = console.log; console.log = (...a) => { out += a.join(" ") + "\n"; };
      try {
        await satirIsle(u.searchParams.get("c") || "");
      } catch (e) {
        out += "[HATA] " + (e?.message || String(e)) + "\n";
      } finally {
        console.log = orig;
      }
      res.writeHead(200, { "Content-Type": "text/plain; charset=utf-8" }); return res.end(out || "[✓] Tamamlandı.");
    }
    res.writeHead(404, { "Content-Type": "text/plain; charset=utf-8" }); res.end("Not Found");
  });
  sunucu.on("error", e => { console.log(`[HATA] GUI sunucusu başlatılamadı: ${e.message}`); process.exit(1); });
  sunucu.listen(8080, "127.0.0.1", () => {
    console.log("[*] AlfSec v10.5 Web GUI hazır: http://127.0.0.1:8080");
    try { require("child_process").execFile("termux-open-url", ["http://127.0.0.1:8080"]); }
    catch { try { require("child_process").execFile("xdg-open", ["http://127.0.0.1:8080"]); } catch {} }
  });
}

(async () => {
  const args = process.argv.slice(2);
  if (args[0] === "gui") return guiBaslat();
  if (args[0] === "tui") { if (await tuiBaslat() !== "cli") return; }
  if (["--help", "-h", "help", "yardim"].includes(args[0])) { await satirIsle("yardim"); return; }
  if (args[0] === "-c" && args[1]) return await satirIsle(args.slice(1).join(" "));
  if (args[0] && !args[0].startsWith("-")) return await satirIsle(args.join(" "));
  console.log("=== ALFSEC v10.5 — TÜRKÇE SİBER GÜVENLİK KONSOLU ('yardim' | 'tui' | 'gui' | 'cikis') ===");
  const rl = readline.createInterface({ input: process.stdin, output: process.stdout, prompt: "\nalfsec> " });
  rl.prompt();
  rl.on("line", async line => {
    const g = line.trim();
    if (["cikis", "exit"].includes(g.toLowerCase())) process.exit(0);
    if (g.toLowerCase() === "tui") { rl.close(); await tuiBaslat(); return; }
    await satirIsle(g); rl.prompt();
  });
})();

if (typeof port_rehberi !== "undefined") global.port_rehberi = port_rehberi;
if (typeof dns_guvenlik !== "undefined") global.dns_guvenlik = dns_guvenlik;
if (typeof metin_temizle_analiz !== "undefined") global.metin_temizle_analiz = metin_temizle_analiz;
if (typeof ozet_karsilastir !== "undefined") global.ozet_karsilastir = ozet_karsilastir;
if (typeof guvenlik_acigi_tarama !== "undefined") global.guvenlik_acigi_tarama = guvenlik_acigi_tarama;
if (typeof baslik_analiz !== "undefined") global.baslik_analiz = baslik_analiz;
if (typeof toplu_hedef_tara !== "undefined") global.toplu_hedef_tara = toplu_hedef_tara;
if (typeof url_coz !== "undefined") global.url_coz = url_coz;
if (typeof alt_ag_hesapla !== "undefined") global.alt_ag_hesapla = alt_ag_hesapla;
if (typeof guvenlik_karnesi !== "undefined") global.guvenlik_karnesi = guvenlik_karnesi;
if (typeof sizinti_kontrol !== "undefined") global.sizinti_kontrol = sizinti_kontrol;
if (typeof oltalama_analiz !== "undefined") global.oltalama_analiz = oltalama_analiz;
if (typeof rapor_olustur !== "undefined") global.rapor_olustur = rapor_olustur;
if (typeof sertifika_zincir !== "undefined") global.sertifika_zincir = sertifika_zincir;
if (typeof csrf_denetle !== "undefined") global.csrf_denetle = csrf_denetle;
if (typeof acik_yonlendirme !== "undefined") global.acik_yonlendirme = acik_yonlendirme;
