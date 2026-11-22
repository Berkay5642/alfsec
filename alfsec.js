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
const zlib = require("zlib");
const { AsyncLocalStorage } = require("async_hooks");
const { execFile, execFileSync } = require("child_process");

const KASA_YOLU = path.join(os.homedir(), ".alfsec_kasa.json");
const _logAls = new AsyncLocalStorage();

// === YARDIMCI: güvenli araç varlık kontrolü (shell'siz, X_OK doğrulamalı) ===
function _aracVarMi(cmd) {
  if (!/^[a-zA-Z0-9._-]+$/.test(cmd)) return false;
  const yollar = (process.env.PATH || "").split(path.delimiter);
  for (const y of yollar) {
    if (!y) continue;
    try {
      const tam = path.join(y, cmd);
      const st = fs.statSync(tam);
      if (st.isFile()) {
        fs.accessSync(tam, fs.constants.X_OK);
        return true;
      }
    } catch {}
  }
  return false;
}

function _anahtarTuret(parola, salt) { return crypto.scryptSync(parola, salt, 32); }

function _temizDomain(hedef) {
  let s = String(hedef || "").trim();
  if (!s) return "";
  if (!/^[a-z]+:\/\//i.test(s)) s = "http://" + s;
  try {
    const u = new URL(s);
    return u.hostname.replace(/^\[|\]$/g, "");
  } catch {
    return String(hedef || "").replace(/^https?:\/\//i, "").split("/")[0].split("@").pop().split(":")[0].trim();
  }
}

// === YARDIMCI: DNS hata ayırıcı (ağ/Termux hatasını "kayıt yok" sanmayı önler) ===
async function _dnsGuvenliCoz(fn, ...args) {
  try {
    return { ok: true, data: await fn(...args), hata: null };
  } catch (e) {
    if (e && (e.code === "ENOTFOUND" || e.code === "ENODATA" || e.code === "NXDOMAIN")) {
      return { ok: true, data: [], hata: null };
    }
    return { ok: false, data: [], hata: e?.code || e?.message || "Bilinmeyen DNS hatası" };
  }
}

// === YARDIMCI: SSRF koruması (özel/yerel ağ tespiti) ===
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

// === YARDIMCI: HTML kaçış (XSS koruması) ===
function escapeHtml(s) {
  return String(s ?? "").replace(/[&<>"']/g, c => ({
    "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;"
  }[c]));
}

// === YARDIMCI: SOCKS5 (Tor) TCP soketi — fail-closed ===
function _socks5Socket(proxyHost, proxyPort, hedefHost, hedefPort) {
  return new Promise((resolve, reject) => {
    const s = net.connect({ host: proxyHost, port: proxyPort });
    let stage = 0;
    const zaman = setTimeout(() => { s.destroy(); reject(new Error("SOCKS5 zaman aşımı")); }, 5000);
    s.on("error", e => { clearTimeout(zaman); reject(e); });
    s.on("connect", () => s.write(Buffer.from([0x05, 0x01, 0x00])));
    s.on("data", buf => {
      if (stage === 0) {
        if (buf[0] !== 0x05 || buf[1] !== 0x00) {
          clearTimeout(zaman); s.destroy();
          return reject(new Error("SOCKS5 kimlik doğrulama reddedildi"));
        }
        stage = 1;
        const hb = Buffer.from(hedefHost, "utf8");
        const req = Buffer.concat([
          Buffer.from([0x05, 0x01, 0x00, 0x03, hb.length]),
          hb,
          Buffer.from([(hedefPort >> 8) & 0xff, hedefPort & 0xff])
        ]);
        s.write(req);
      } else if (stage === 1) {
        if (buf[0] !== 0x05 || buf[1] !== 0x00) {
          clearTimeout(zaman); s.destroy();
          return reject(new Error("SOCKS5 bağlantı reddedildi (kod: " + buf[1] + ")"));
        }
        clearTimeout(zaman);
        s.removeAllListeners("data");
        s.removeAllListeners("error");
        resolve(s);
      }
    });
  });
}

// === YARDIMCI: HTTP/HTTPS İstemcisi (Redirect + Gzip/Br + Sert Timeout + SSRF Koruması) ===
async function _httpGet(url, opts = {}) {
  const followRedirects = opts.followRedirects === true;
  const maxRedirects = Number(opts.maxRedirects ?? 5);
  let mevcutUrl = url;
  const ziyaretEdilen = [];

  for (let hop = 0; hop <= (followRedirects ? maxRedirects : 0); hop++) {
    const u = new URL(mevcutUrl);
    if (u.protocol !== "http:" && u.protocol !== "https:") {
      throw new Error(`Desteklenmeyen protokol: ${u.protocol}`);
    }
    const izinVer = process.env.ALFSEC_ALLOW_LOCAL === "1";
    if (!izinVer && _isPrivateHost(u.hostname)) {
      throw new Error(`SSRF koruması: özel/yerel ağa istek engellendi (${u.hostname}). Test için ALFSEC_ALLOW_LOCAL=1 ayarlayın.`);
    }
    const maxBody = Math.min(Number(opts.maxBody) || 200000, 5000000);
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

    const resObj = await new Promise((resolve, reject) => {
      const mod = isHttps ? https : http;
      const reqOpts = {
        method: opts.method || "GET",
        hostname: u.hostname,
        port,
        path: (u.pathname || "/") + (u.search || ""),
        headers: {
          "User-Agent": "Mozilla/5.0 (Linux; Android 13; AlfSec/10.5)",
          "Accept-Encoding": "gzip, deflate, br",
          ...(opts.headers || {})
        },
        agent: false
      };

      const req = (useTor && socket)
        ? mod.request({
            ...reqOpts,
            createConnection: () => isHttps
              ? tls.connect({ socket, servername: u.hostname, rejectUnauthorized: true })
              : socket
          })
        : mod.request(reqOpts);

      const sertZaman = setTimeout(() => { req.destroy(new Error("Zaman aşımı")); }, timeout);
      req.on("error", e => { clearTimeout(sertZaman); reject(e); });
      req.on("response", res => {
        const chunks = [];
        let size = 0, bitti = false;
        const bitir = () => {
          if (bitti) return;
          bitti = true;
          clearTimeout(sertZaman);
          let buf = Buffer.concat(chunks);
          const enc = String(res.headers["content-encoding"] || "").toLowerCase();
          try {
            if (enc.includes("gzip")) buf = zlib.gunzipSync(buf);
            else if (enc.includes("deflate")) buf = zlib.inflateSync(buf);
            else if (enc.includes("br")) buf = zlib.brotliDecompressSync(buf);
          } catch {}
          resolve({
            status: res.statusCode,
            headers: res.headers,
            body: buf.toString("utf8"),
            finalUrl: mevcutUrl,
            redirects: ziyaretEdilen
          });
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

    if (followRedirects && resObj.status >= 300 && resObj.status < 400 && resObj.headers.location && hop < maxRedirects) {
      ziyaretEdilen.push({ status: resObj.status, from: mevcutUrl, to: resObj.headers.location });
      mevcutUrl = new URL(resObj.headers.location, mevcutUrl).toString();
      continue;
    }
    return resObj;
  }
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
    { ad: "GitHub", url: `https://github.com/${kullanici}`, dogrula: r => r.status === 200 && !/Not Found/i.test(r.body) },
    { ad: "GitLab", url: `https://gitlab.com/api/v4/users?username=${encodeURIComponent(kullanici)}`, dogrula: r => r.status === 200 && r.body.trim().startsWith("[{") },
    { ad: "Reddit", url: `https://www.reddit.com/user/${kullanici}/about.json`, dogrula: r => r.status === 200 && r.body.includes('"name"') && !r.body.includes('"error": 404') },
    { ad: "Steam", url: `https://steamcommunity.com/id/${kullanici}`, dogrula: r => r.status === 200 && !/The specified profile could not be found/i.test(r.body) },
    { ad: "Medium", url: `https://medium.com/@${kullanici}`, dogrula: r => r.status === 200 && !/PAGE NOT FOUND|Out of nothing, something/i.test(r.body) && r.body.includes(kullanici) },
    { ad: "Pinterest", url: `https://www.pinterest.com/${kullanici}/`, dogrula: r => r.status === 200 && !/User not found|Sayfa bulunamadı/i.test(r.body) && r.body.includes(`"username":"${kullanici}"`) },
    { ad: "DeviantArt", url: `https://www.deviantart.com/${kullanici}`, dogrula: r => r.status === 200 && !/Llama not found/i.test(r.body) },
    { ad: "Pastebin", url: `https://pastebin.com/u/${kullanici}`, dogrula: r => r.status === 200 && !/Not Found/i.test(r.body) },
    { ad: "DockerHub", url: `https://hub.docker.com/v2/users/${kullanici}/`, dogrula: r => r.status === 200 && r.body.includes('"username"') },
    { ad: "NPM", url: `https://www.npmjs.com/~${kullanici}`, dogrula: r => r.status === 200 && !/404 Not Found/i.test(r.body) },
    { ad: "PyPI", url: `https://pypi.org/user/${kullanici}/`, dogrula: r => r.status === 200 && !/Page Not Found/i.test(r.body) },
    { ad: "Replit", url: `https://replit.com/@${kullanici}`, dogrula: r => r.status === 200 && !/"status":404|Page not found/i.test(r.body) && r.body.includes(kullanici) }
  ];
  console.log(`=== OSINT KULLANICI ADI TARAMASI: @${kullanici} ===`);
  let bulunan = 0, belirsiz = 0;
  for (const s of siteler) {
    try {
      const r = await _httpGet(s.url, { followRedirects: true, timeout: 8000 });
      if (r.status === 403 || r.status === 429) {
        console.log(`  [ENGELLENDİ] ${s.ad.padEnd(11)} -> HTTP ${r.status} (Bot/WAF koruması)`);
        belirsiz++;
      } else if (s.dogrula(r)) {
        console.log(`  [BULUNDU]    ${s.ad.padEnd(11)} -> ${s.url}`);
        bulunan++;
      }
    } catch (e) {
      console.log(`  [AĞ HATASI]  ${s.ad.padEnd(11)} -> ${e.message}`);
      belirsiz++;
    }
  }
  console.log(`[✓] ${siteler.length} platformdan ${bulunan} aktif profil doğrulandı (${belirsiz} platform erişim/WAF nedeniyle belirsiz).`);
}

async function eposta_denetle(eposta) {
  eposta = String(eposta || "").trim();
  const m = eposta.match(/^[^@\s]+@([^@\s]+\.[^@\s]+)$/);
  if (!m) return console.log("[!] Geçersiz e-posta adresi biçimi.");
  const domain = m[1];
  console.log(`=== E-POSTA ALTYAPI & GÜVENLİK DENETİMİ: ${eposta} ===`);
  const [mxRes, txtRes, dmarcRes] = await Promise.all([
    _dnsGuvenliCoz(dns.resolveMx, domain),
    _dnsGuvenliCoz(dns.resolveTxt, domain),
    _dnsGuvenliCoz(dns.resolveTxt, `_dmarc.${domain}`)
  ]);
  if (!mxRes.ok || !txtRes.ok || !dmarcRes.ok) {
    console.log(`  [!] DNS çözümleme hatası (${mxRes.hata || txtRes.hata || dmarcRes.hata}). İnternet/Termux DNS ayarını kontrol edin.`);
  }
  const spf = txtRes.data.map(t => t.join("").trim()).find(t => /^v=spf1(\s|$)/i.test(t));
  const dmarc = dmarcRes.data.map(t => t.join("").trim()).find(t => /^v=DMARC1(\s|;|$)/i.test(t));
  console.log(`  • Posta Sunucusu (MX) : ${!mxRes.ok ? "SORGULANAMADI" : (mxRes.data.length ? mxRes.data.map(x => x.exchange).join(", ") : "YOK (A/AAAA fallback yoksa e-posta alamaz)")}`);
  console.log(`  • Sahtecilik Kilidi SPF: ${!txtRes.ok ? "SORGULANAMADI" : (spf ? "AKTİF (" + spf + ")" : "EKSİK")}`);
  console.log(`  • DMARC Politikası     : ${!dmarcRes.ok ? "SORGULANAMADI" : (dmarc ? "AKTİF (" + dmarc + ")" : "EKSİK")}`);
}

async function dns_detay(domain) {
  domain = _temizDomain(domain);
  if (!domain) return console.log("[!] Geçerli bir alan adı girin.");
  console.log(`=== TAM DNS KAYIT ANALİZİ: ${domain} ===`);
  const [a, aaaa, cname, mx, ns, txt] = await Promise.all([
    _dnsGuvenliCoz(dns.resolve4, domain),
    _dnsGuvenliCoz(dns.resolve6, domain),
    _dnsGuvenliCoz(dns.resolveCname, domain),
    _dnsGuvenliCoz(dns.resolveMx, domain),
    _dnsGuvenliCoz(dns.resolveNs, domain),
    _dnsGuvenliCoz(dns.resolveTxt, domain)
  ]);
  const goster = (res, fmt) => !res.ok ? `HATA (${res.hata})` : (res.data.length ? fmt(res.data) : "Kayıt yok");
  console.log(`  • IPv4 (A)     : ${goster(a, d => d.join(", "))}`);
  console.log(`  • IPv6 (AAAA)  : ${goster(aaaa, d => d.join(", "))}`);
  console.log(`  • CNAME        : ${goster(cname, d => d.join(", "))}`);
  console.log(`  • E-Posta (MX) : ${goster(mx, d => d.map(x => `${x.exchange} (${x.priority})`).join(", "))}`);
  console.log(`  • İsim Sunucu  : ${goster(ns, d => d.join(", "))}`);
  console.log(`  • TXT Kayıtları: ${goster(txt, d => d.map(t => t.join("")).join(" | "))}`);
}

function _whoisTcp(sunucu, sorgu) {
  return new Promise((resolve, reject) => {
    const s = net.connect(43, sunucu);
    let veri = "";
    s.setTimeout(7000);
    s.on("connect", () => s.write(sorgu + "\r\n"));
    s.on("data", c => { veri += c.toString("utf8"); });
    s.on("end", () => resolve(veri));
    s.on("timeout", () => { s.destroy(); reject(new Error("WHOIS zaman aşımı")); });
    s.on("error", reject);
  });
}

async function whois_sorgu(domain) {
  domain = _temizDomain(domain);
  if (!/^[a-zA-Z0-9]([a-zA-Z0-9.-]*[a-zA-Z0-9])?$/.test(domain) || domain.length > 253) {
    return console.log("[!] Geçersiz alan adı biçimi.");
  }
  console.log(`=== WHOIS ALAN ADI KİMLİĞİ: ${domain} ===`);
  let ham = "";
  try {
    if (_aracVarMi("whois")) {
      ham = execFileSync("whois", [domain], { encoding: "utf8", timeout: 8000, maxBuffer: 2 * 1024 * 1024 });
    } else {
      const iana = await _whoisTcp("whois.iana.org", domain);
      const refM = iana.match(/^refer:\s*(\S+)/mi);
      ham = refM ? await _whoisTcp(refM[1], domain) : iana;
    }
    const eslesmeler = [
      [/^(registrar|sponsoring registrar|organization name)\s*:\s*(.+)/i, "Kayıt Kuruluşu"],
      [/^(creation date|created on|created|registered on)\s*:\s*(.+)/i, "Oluşturulma Tarihi"],
      [/^(registry expiry date|registrar registration expiration date|expiration date|expires on|expiry date|paid-till)\s*:\s*(.+)/i, "Bitiş Tarihi"],
      [/^(updated date|last updated|changed)\s*:\s*(.+)/i, "Son Güncelleme"],
      [/^(name server|nserver|nameserver)\s*:\s*(.+)/i, "İsim Sunucusu"]
    ];
    let yazilan = 0;
    for (const s of ham.split(/\r?\n/)) {
      const t = s.trim();
      for (const [rx, tr] of eslesmeler) {
        const m = t.match(rx);
        if (m) { console.log(`  • ${tr.padEnd(20)}: ${m[2].trim()}`); yazilan++; break; }
      }
    }
    if (!yazilan) {
      ham.split(/\r?\n/).filter(Boolean).slice(0, 15).forEach(s => console.log(`  ${s}`));
    }
  } catch (e) {
    console.log(`[!] WHOIS sorgusu başarısız: ${e.message}`);
  }
}

async function subdomain_bul(domain) {
  domain = _temizDomain(domain);
  if (!/^[a-zA-Z0-9.-]+$/.test(domain) || !domain.includes(".")) return console.log("[!] Geçersiz alan adı.");
  console.log(`[*] ${domain} için alt alan adları (Sertifika Şeffaflığı) taranıyor...`);
  try {
    const r = await _httpGet(`https://crt.sh/?q=%25.${encodeURIComponent(domain)}&output=json`, { maxBody: 5000000, timeout: 18000 });
    if (r.status !== 200) return console.log(`[!] crt.sh API hatası (HTTP ${r.status}).`);
    let liste;
    try { liste = JSON.parse(r.body); }
    catch { return console.log("[!] crt.sh yanıtı geçerli JSON değil (yanıt kesilmiş veya servis yoğun)."); }
    const subs = [...new Set(
      liste.flatMap(x => String(x.name_value || "").split(/\r?\n/))
        .map(x => x.toLowerCase().trim())
        .filter(x => x && !x.includes("*") && (x === domain.toLowerCase() || x.endsWith("." + domain.toLowerCase())))
    )].sort();
    subs.slice(0, 35).forEach(s => console.log(`  [+] ${s}`));
    if (subs.length > 35) console.log(`  ... (+${subs.length - 35} adet daha)`);
    console.log(`[✓] Toplam ${subs.length} benzersiz alt alan adı bulundu.`);
  } catch (e) { console.log(`[!] Sertifika kayıtları alınamadı: ${e.message}`); }
}

async function ip_analiz(ip = "") {
  ip = _temizDomain(ip);
  if (ip && !/^[a-zA-Z0-9.:_-]{1,64}$/.test(ip)) {
    return console.log("[!] Geçersiz IP/hostname biçimi.");
  }
  try {
    const r = await _httpGet(`https://ipwho.is/${encodeURIComponent(ip)}?lang=tr`);
    if (r.status !== 200) return console.log(`[!] IP servisi HTTP ${r.status} döndürdü.`);
    const j = JSON.parse(r.body);
    if (j.success === false) return console.log(`[!] IP bilgisi alınamadı: ${j.message}`);
    console.log(`=== IP COĞRAFİ & AĞ ANALİZİ: ${j.ip} ===`);
    console.log(`  • Konum    : ${j.country} / ${j.region} / ${j.city}`);
    console.log(`  • Sağlayıcı: ${j.connection?.isp || "-"} (${j.connection?.org || "-"})`);
    console.log(`  • ASN Kodu : AS${j.connection?.asn || "-"}`);
  } catch (e) { console.log(`[HATA] ${e.message}`); }
}

async function ters_dns(ip) {
  ip = String(ip || "").trim();
  if (!net.isIP(ip)) return console.log("[!] Geçerli bir IPv4 veya IPv6 adresi girin.");
  try {
    const hostlar = await dns.reverse(ip);
    console.log(`[TERS DNS] ${ip} -> ${hostlar.join(", ")}`);
  } catch (e) {
    if (e.code === "ENOTFOUND" || e.code === "ENODATA" || e.code === "NXDOMAIN") {
      console.log(`[TERS DNS] ${ip} için PTR alan adı kaydı bulunamadı.`);
    } else {
      console.log(`[HATA] Ters DNS sorgulanamadı (${e.code || e.message}).`);
    }
  }
}

function mac_sorgu(mac) {
  const hex = String(mac || "").toUpperCase().replace(/[^0-9A-F]/g, "");
  if (hex.length < 6 || (hex.length !== 6 && hex.length !== 12)) {
    return console.log("[!] Geçersiz MAC adresi. Örnek: 00:1A:11:22:33:44");
  }
  const ilkByte = parseInt(hex.slice(0, 2), 16);
  const yerelMi = (ilkByte & 0x02) !== 0;
  const temiz = hex.slice(0, 6);
  const ureticiler = {
    "001A11": "Google", "3C5AB4": "Google", "F4F5D8": "Google",
    "286C07": "Xiaomi", "64B473": "Xiaomi", "7C1DD9": "Xiaomi",
    "00163E": "Xen Virtual", "080027": "Oracle VirtualBox", "000C29": "VMware", "005056": "VMware",
    "B827EB": "Raspberry Pi", "DCA632": "Raspberry Pi", "E45F01": "Raspberry Pi",
    "001E52": "Apple", "3C0754": "Apple", "F01898": "Apple", "A483E7": "Apple",
    "001247": "Samsung", "5C0A5B": "Samsung", "8C7712": "Samsung",
    "18D6C7": "TP-Link", "50C7BF": "TP-Link", "C025E9": "TP-Link",
    "001B21": "Intel", "3C970E": "Intel", "A44CC8": "Dell", "00E04C": "Realtek",
    "00E0FC": "Huawei", "4846FB": "Huawei", "B0E5ED": "Huawei", "04D9F5": "ASUS"
  };
  const sonuc = ureticiler[temiz] || (yerelMi ? "Rastgele / Yerel Yönetim (LAA) MAC Adresi" : `Bilinmeyen Üretici (OUI: ${temiz})`);
  console.log(`[MAC OUI] ${mac} -> Üretici: ${sonuc}`);
}

function telefon_bilgi(tel) {
  let temiz = String(tel || "").replace(/[\s\-()]/g, "");
  if (!/^[+0-9]{5,18}$/.test(temiz)) return console.log("[!] Geçersiz telefon numarası biçimi.");
  if (temiz.startsWith("00")) temiz = "+" + temiz.slice(2);
  const ulkeler = {
    "+994": "Azerbaycan", "+90": "Türkiye", "+49": "Almanya", "+44": "Birleşik Krallık",
    "+33": "Fransa", "+31": "Hollanda", "+1": "ABD / Kanada", "+7": "Rusya / Kazakistan"
  };
  const kod = Object.keys(ulkeler).sort((a, b) => b.length - a.length).find(k => temiz.startsWith(k));
  const trYerel = !kod && /^05\d{9}$/.test(temiz);
  console.log(`=== TELEFON FORMAT ANALİZİ: ${tel} ===`);
  console.log(`  • Ülke Bölgesi : ${kod ? ulkeler[kod] + " (" + kod + ")" : (trYerel ? "Türkiye (Yerel 05xx)" : "Bilinmeyen Ülke Kodu")}`);
  console.log(`  • Rakam Sayısı : ${temiz.replace(/\D/g, "").length} hane (${temiz.startsWith("+") ? "Uluslararası E.164" : "Yerel Format"})`);
}

async function tam_analiz(domain) {
  domain = _temizDomain(domain);
  if (!domain || !/^[a-zA-Z0-9.-]+$/.test(domain)) return console.log("[!] Geçerli bir hedef domain girin.");
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
// 2. AĞ TEŞHİSİ & TÜRKÇE NMAP (9 MODÜL)
// ==========================================
async function guncelle() {
  const url = "https://raw.githubusercontent.com/Berkay5642/alfsec/main/alfsec.js";
  const hamHedef = process.argv[1];
  console.log("[*] GitHub deposundan en güncel AlfSec sürümü kontrol ediliyor...");
  if (!hamHedef || !fs.existsSync(hamHedef)) {
    return console.log("[!] Hedef betik yolu tespit edilemedi; güncelleme iptal edildi.");
  }
  const hedef = fs.realpathSync(hamHedef);
  try {
    const r = await _httpGet(url, { timeout: 15000, maxBody: 5000000 });
    if (r.status !== 200 || !r.body.includes("ALFSEC") || !r.body.includes("ARAC_HARITASI") || r.body.length < 1000) {
      return console.log("[!] Güncelleme dosyası doğrulanamadı (HTTP " + r.status + ").");
    }
    const gecici = hedef + ".tmp";
    const yedek = hedef + ".bak";
    fs.writeFileSync(gecici, r.body, "utf8");
    try {
      execFileSync(process.execPath, ["--check", gecici], { timeout: 5000 });
    } catch {
      try { fs.unlinkSync(gecici); } catch {}
      return console.log("[!] İndirilen dosya sözdizimi doğrulamasından geçemedi, güncelleme iptal edildi.");
    }
    try { fs.copyFileSync(hedef, yedek); } catch {}
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
  if (process.env.PREFIX && process.env.PREFIX.includes("termux")) {
    distro = "Android Termux";
  } else if (fs.existsSync("/etc/os-release")) {
    const m = fs.readFileSync("/etc/os-release", "utf8").match(/PRETTY_NAME="([^"]+)"/);
    if (m) distro = m[1];
  }
  const araclar = ["nmap", "whois", "tor", "curl", "openssl"].map(a => `${a}: ${_aracVarMi(a) ? "HAZIR" : "YOK"}`).join(" | ");
  console.log(`=== SİSTEM & ORTAM DURUMU ===\n  • İşletim Sistemi : ${distro} (${os.arch()})\n  • Cihaz Adı       : ${os.hostname()}\n  • Dış Araç Desteği: ${araclar}`);
}

function ag_kimlik() {
  console.log("=== YEREL AĞ ARAYÜZLERİ ===");
  try {
    const ifaces = os.networkInterfaces();
    let sayac = 0;
    for (const [ad, list] of Object.entries(ifaces)) {
      for (const n of list || []) {
        if (!n.internal) {
          console.log(`  • Arayüz: ${ad} | ${n.family}: ${n.address} | MAC: ${n.mac}`);
          sayac++;
        }
      }
    }
    if (!sayac) console.log("  [-] Aktif harici ağ arayüzü bulunamadı.");
  } catch (e) {
    console.log(`  [!] Sistem ağ arayüzleri doğrudan okunamadı (${e.code || e.message}).`);
    if (_aracVarMi("ip")) {
      try {
        const out = execFileSync("ip", ["-o", "-4", "addr", "show"], { encoding: "utf8", timeout: 3000 });
        out.trim().split(/\r?\n/).filter(Boolean).forEach(s => console.log(`  • ${s}`));
        return;
      } catch {}
    }
    console.log("  ↳ Android 11+ güvenlik politikası nedeniyle Termux'ta netlink arayüz listesi kısıtlanmış olabilir.");
  }
}

async function dis_ip() {
  try {
    const r = await _httpGet("https://api.ipify.org?format=json");
    if (r.status !== 200) return console.log(`[!] Dış IP servisi HTTP ${r.status} döndürdü.`);
    console.log(`[DIŞ IP] İnternet Çıkış IP Adresiniz: ${JSON.parse(r.body).ip}`);
  } catch (e) { console.log(`[!] Dış IP adresi sorgulanamadı: ${e.message}`); }
}

function tor_kontrol() {
  return new Promise(resolve => {
    const s = new net.Socket(); s.setTimeout(1000);
    s.connect(9050, "127.0.0.1", () => { console.log("[TOR] AKTİF — Yerel Tor SOCKS5 proxy (127.0.0.1:9050) çalışıyor."); s.destroy(); resolve(); });
    s.on("error", () => { console.log("[TOR] KAPALI — 9050 portu dinlenmiyor."); s.destroy(); resolve(); });
    s.on("timeout", () => { console.log("[TOR] KAPALI — Zaman aşımı."); s.destroy(); resolve(); });
  });
}

async function port_tara(hedef, bas = 1, bit = 100) {
  hedef = _temizDomain(hedef);
  const b = Number(bas), sPort = Number(bit);
  if (!hedef || !Number.isInteger(b) || !Number.isInteger(sPort) || b < 1 || sPort > 65535 || b > sPort) {
    return console.log("[!] Geçersiz hedef veya port aralığı (1-65535).");
  }
  let ip = hedef;
  if (!net.isIP(hedef)) {
    try { ip = (await dns.lookup(hedef)).address; }
    catch (e) { return console.log(`[HATA] Hedef çözümlenemedi: ${e.message}`); }
  }
  return new Promise(resolve => {
    console.log(`[*] ${hedef} [${ip}] (${b}-${sPort}) TCP portları taranıyor...`);
    let aktif = 0, mevcut = b;
    const aciklar = [];
    function sonraki() {
      if (mevcut > sPort && aktif === 0) {
        aciklar.sort((x, y) => x - y);
        console.log(`[✓] Tarama bitti. Açık portlar: ${aciklar.length ? aciklar.join(", ") : "Bulunamadı"}`);
        return resolve();
      }
      while (aktif < 40 && mevcut <= sPort) {
        const p = mevcut++; aktif++;
        const s = new net.Socket(); s.setTimeout(800);
        s.connect(p, ip, () => { aciklar.push(p); console.log(`  [+] Port ${p}/TCP -> AÇIK`); s.destroy(); });
        s.on("error", () => s.destroy());
        s.on("timeout", () => s.destroy());
        s.on("close", () => { aktif--; sonraki(); });
      }
    }
    sonraki();
  });
}

async function nmap_turkce(hedef) {
  hedef = _temizDomain(hedef);
  if (!hedef || (!/^[a-zA-Z0-9.-]+$/.test(hedef) && !net.isIP(hedef)) || hedef.length > 253) {
    return console.log("[!] Geçersiz hedef biçimi (nmap için).");
  }
  if (_aracVarMi("nmap")) {
    console.log(`=== NMAP TÜRKÇE SERVİS & PORT RAPORU: ${hedef} ===`);
    try {
      const args = ["-sT", "-Pn", "-sV", "-T4", "--top-ports", "100"];
      if (net.isIPv6(hedef)) args.unshift("-6");
      const ham = execFileSync("nmap", [...args, "--", hedef], { encoding: "utf8", timeout: 45000, maxBuffer: 4 * 1024 * 1024 });
      let acik = 0;
      for (const s of ham.split(/\r?\n/)) {
        if (s.includes("Host is up")) console.log(`  • Hedef Durumu : ÇEVRİMİÇİ`);
        else if (/^\d+\/(tcp|udp)\s+open/.test(s)) {
          const p = s.trim().split(/\s+/);
          console.log(`  [+] Port ${p[0].padEnd(10)} | Durum: ${p[1].toUpperCase()} | Servis: ${(p[2] || "bilinmiyor").padEnd(10)} | Sürüm: ${p.slice(3).join(" ") || "Gizli"}`);
          acik++;
        }
      }
      if (acik === 0) console.log("  [-] İlk 100 yaygın portta açık servis bulunamadı.");
      return;
    } catch (e) { console.log(`[!] Nmap hatası (${e.code || e.message}), dahili tarayıcıya geçiliyor...`); }
  }
  await port_tara(hedef, 1, 100);
}

function servis_banner(hedef, port = 80) {
  return new Promise(resolve => {
    const host = _temizDomain(hedef);
    const pNo = Number(port);
    if (!host || !Number.isInteger(pNo) || pNo < 1 || pNo > 65535) {
      console.log("[!] Geçersiz hedef veya port."); return resolve();
    }
    let bitti = false, veri = "", hataOldu = false;
    const bitir = () => { if (!bitti) { bitti = true; resolve(); } };
    const tlsMi = pNo === 443 || pNo === 8443;
    const s = tlsMi
      ? tls.connect(pNo, host, { servername: net.isIP(host) ? undefined : host, rejectUnauthorized: false })
      : net.connect(pNo, host);
    s.setTimeout(3000);
    let yazmaTimer = null;
    s.on(tlsMi ? "secureConnect" : "connect", () => {
      if (tlsMi || pNo === 80 || pNo === 8080 || pNo === 8000) {
        s.write(`HEAD / HTTP/1.0\r\nHost: ${host}\r\n\r\n`);
      } else {
        yazmaTimer = setTimeout(() => { try { s.write(`HEAD / HTTP/1.0\r\nHost: ${host}\r\n\r\n`); } catch {} }, 600);
      }
    });
    s.on("data", d => {
      if (yazmaTimer) { clearTimeout(yazmaTimer); yazmaTimer = null; }
      veri += d.toString("utf8");
      if (veri.length > 4096 || veri.includes("\r\n\r\n")) s.destroy();
    });
    s.on("error", e => { hataOldu = true; console.log(`[HATA] ${e.message}`); bitir(); });
    s.on("timeout", () => { s.destroy(); });
    s.on("close", () => {
      if (yazmaTimer) clearTimeout(yazmaTimer);
      if (veri.trim()) console.log(`=== BANNER (${host}:${pNo}) ===\n${veri.split("\r\n\r\n")[0].trim()}`);
      else if (!hataOldu && !bitti) console.log("[!] Servis banner verisi döndürmedi.");
      bitir();
    });
  });
}

function yerel_ag_tara(onek = "192.168.1") {
  const okt = String(onek || "").trim().split(".").map(Number);
  if (okt.length !== 3 || okt.some(n => !Number.isInteger(n) || n < 0 || n > 255)) {
    return console.log('[!] Geçersiz ağ öneki. Örnek: yerel_ag_tara("192.168.1")');
  }
  const portlar = [80, 443, 22, 445, 53, 8080];
  return new Promise(resolve => {
    console.log(`[*] ${onek}.1 - ${onek}.254 yerel ağı taranıyor (çoklu port probe)...`);
    let aktif = 0, ipNo = 1;
    const bulunanlar = new Map();
    function denePort(ip, idx, cb) {
      if (idx >= portlar.length) return cb();
      const s = new net.Socket();
      s.setTimeout(500);
      s.connect(portlar[idx], ip, () => {
        bulunanlar.set(ip, `Port ${portlar[idx]} açık`);
        s.destroy(); cb();
      });
      s.on("error", err => {
        s.destroy();
        if (err.code === "ECONNREFUSED") {
          bulunanlar.set(ip, "Çevrimiçi (RST yanıtı)");
          return cb();
        }
        denePort(ip, idx + 1, cb);
      });
      s.on("timeout", () => { s.destroy(); denePort(ip, idx + 1, cb); });
    }
    function sonraki() {
      if (ipNo > 254 && aktif === 0) {
        console.log(`[✓] Yerel ağ taraması bitti. ${bulunanlar.size} aktif cihaz bulundu.`);
        return resolve();
      }
      while (aktif < 25 && ipNo <= 254) {
        const ip = `${onek}.${ipNo++}`;
        aktif++;
        denePort(ip, 0, () => {
          if (bulunanlar.has(ip)) console.log(`  [+] Aktif Cihaz: ${ip} (${bulunanlar.get(ip)})`);
          aktif--; sonraki();
        });
      }
    }
    sonraki();
  });
}

// ==========================================
// 3. WEB GÜVENLİĞİ & SSL DENETİMİ (7 MODÜL)
// ==========================================
async function web_denetle(domain) {
  domain = _temizDomain(domain);
  if (!domain) return console.log("[!] Geçerli bir alan adı girin.");
  try {
    const r = await _httpGet(`https://${domain}`, { followRedirects: true });
    const h = r.headers;
    const csp = h["content-security-policy"] || "";
    const clickjack = h["x-frame-options"] ? `AKTİF (${h["x-frame-options"]})` : (/frame-ancestors/i.test(csp) ? "AKTİF (CSP frame-ancestors)" : "EKSİK");
    console.log(`=== WEB GÜVENLİK KALKANLARI: ${domain} (HTTP ${r.status} | Son URL: ${r.finalUrl}) ===`);
    console.log(`  • Zorunlu HTTPS (HSTS)    : ${h["strict-transport-security"] ? "AKTİF" : "EKSİK"}`);
    console.log(`  • XSS Kalkanı (CSP)       : ${csp ? "AKTİF" : "EKSİK"}`);
    console.log(`  • Clickjacking Koruması   : ${clickjack}`);
    console.log(`  • Dosya Tipi Kilidi (MIME): ${h["x-content-type-options"] ? "AKTİF" : "EKSİK"}`);
    console.log(`  • Referrer Politikası     : ${h["referrer-policy"] ? "AKTİF (" + h["referrer-policy"] + ")" : "EKSİK"}`);
  } catch (e) { console.log(`[HATA] ${e.message}`); }
}

function ssl_analiz(domain) {
  domain = _temizDomain(domain);
  if (!domain) return console.log("[!] Geçerli bir alan adı girin.");
  return new Promise(resolve => {
    let bitti = false;
    const bitir = () => { if (!bitti) { bitti = true; resolve(); } };
    const s = tls.connect(443, domain, { servername: net.isIP(domain) ? undefined : domain, rejectUnauthorized: false }, () => {
      const cert = s.getPeerCertificate();
      const gecerli = s.authorized ? "EVET (Güvenilir)" : `HAYIR (${s.authorizationError})`;
      console.log(`=== SSL/TLS SERTİFİKA ANALİZİ: ${domain} ===`);
      console.log(`  • Güvenilirlik      : ${gecerli}`);
      console.log(`  • TLS Sürümü        : ${s.getProtocol()}`);
      console.log(`  • Şifreleme Paketi  : ${s.getCipher()?.name || "?"}`);
      console.log(`  • Sertifika Kurumu  : ${cert.issuer?.O || cert.issuer?.CN || "Bilinmiyor"}`);
      console.log(`  • Geçerlilik Bitişi : ${cert.valid_to || "?"}`);
      s.end(); bitir();
    });
    s.on("error", e => { console.log(`[HATA] ${e.message}`); bitir(); });
    s.setTimeout(8000, () => { console.log("[!] SSL zaman aşımı."); s.destroy(); bitir(); });
  });
}

async function teknoloji_bul(domain) {
  domain = _temizDomain(domain);
  if (!domain) return console.log("[!] Geçerli bir alan adı girin.");
  try {
    const r = await _httpGet(`https://${domain}`, { followRedirects: true });
    const h = r.headers;
    const b = r.body;
    const tespitler = [];
    if (h["server"]) tespitler.push(`Sunucu: ${h["server"]}`);
    if (h["x-powered-by"]) tespitler.push(`Altyapı: ${h["x-powered-by"]}`);
    if (h["cf-ray"]) tespitler.push("CDN/WAF: Cloudflare");
    if (h["x-vercel-id"]) tespitler.push("Barındırma: Vercel");
    if (/\/wp-content\/|\/wp-includes\//i.test(b)) tespitler.push("CMS: WordPress");
    if (/__NEXT_DATA__|\/_next\/static\//i.test(b)) tespitler.push("Framework: Next.js");
    if (/data-reactroot|__REACT_DEVTOOLS|react(?:\.production\.min|\.development)?\.js/i.test(b)) tespitler.push("Arayüz: React");
    if (/ng-version=|angular(?:\.min)?\.js/i.test(b)) tespitler.push("Framework: Angular");
    if (/data-v-[0-9a-f]+|vue(?:\.runtime)?(?:\.min)?\.js/i.test(b)) tespitler.push("Arayüz: Vue.js");
    console.log(`=== TEKNOLOJİ & ALTYAPI İZİ: ${domain} ===\n  • ${tespitler.length ? tespitler.join("\n  • ") : "Belirgin teknoloji başlığı/imzası gizlenmiş."}`);
  } catch (e) { console.log(`[HATA] ${e.message}`); }
}

async function robots_oku(domain) {
  domain = _temizDomain(domain);
  if (!domain) return console.log("[!] Geçerli bir alan adı girin.");
  try {
    const r = await _httpGet(`https://${domain}/robots.txt`, { followRedirects: true });
    console.log(`=== ROBOTS.TXT ANALİZİ: ${domain} (HTTP ${r.status}) ===`);
    if (r.status === 200) {
      const satirlar = r.body.split(/\r?\n/);
      console.log(satirlar.slice(0, 30).join("\n"));
      if (satirlar.length > 30) console.log(`... (+${satirlar.length - 30} satır daha)`);
    } else {
      console.log("  [-] robots.txt dosyası bulunamadı.");
    }
  } catch (e) { console.log(`[HATA] ${e.message}`); }
}

async function cerez_denetle(domain) {
  domain = _temizDomain(domain);
  if (!domain) return console.log("[!] Geçerli bir alan adı girin.");
  try {
    const r = await _httpGet(`https://${domain}`, { followRedirects: true });
    const raw = r.headers["set-cookie"];
    const cookies = Array.isArray(raw) ? raw : (raw ? [raw] : []);
    console.log(`=== ÇEREZ (COOKIE) GÜVENLİK DENETİMİ: ${domain} ===`);
    if (!cookies.length) return console.log("  • Sunucu başlangıçta çerez göndermedi.");
    cookies.forEach(c => {
      const ad = String(c).split("=")[0].trim();
      const sec = /;\s*secure\b/i.test(c) ? "EVET" : "HAYIR";
      const httpOnly = /;\s*httponly\b/i.test(c) ? "EVET" : "HAYIR";
      const ss = (c.match(/;\s*samesite=([^;]+)/i) || [])[1] || "YOK";
      console.log(`  • Çerez: ${ad} | Secure: ${sec} | HttpOnly: ${httpOnly} | SameSite: ${ss}`);
    });
  } catch (e) { console.log(`[HATA] ${e.message}`); }
}

async function link_cikar(url) {
  let ham = String(url || "").trim();
  if (!ham) return console.log("[!] Geçerli bir URL girin.");
  if (!/^https?:\/\//i.test(ham)) ham = "https://" + ham;
  try {
    const r = await _httpGet(ham, { followRedirects: true, maxBody: 1000000 });
    const hamHrefler = [...r.body.matchAll(/href\s*=\s*["']([^"'#]+)["']/gi)].map(m => m[1].trim());
    const cozulmus = [...new Set(hamHrefler.map(h => {
      try { return new URL(h, r.finalUrl || ham).toString(); } catch { return null; }
    }).filter(u => u && /^https?:/i.test(u)))];
    console.log(`=== BAĞLANTI ANALİZİ (${cozulmus.length} Link) ===`);
    cozulmus.slice(0, 25).forEach(l => console.log(`  • ${l}`));
    if (cozulmus.length > 25) console.log(`  ... (+${cozulmus.length - 25} link daha)`);
  } catch (e) { console.log(`[HATA] ${e.message}`); }
}

async function http_metotlar(domain) {
  domain = _temizDomain(domain);
  if (!domain) return console.log("[!] Geçerli bir alan adı girin.");
  try {
    const r = await _httpGet(`https://${domain}/`, { method: "OPTIONS", timeout: 8000 });
    const allow = r.headers["allow"] || r.headers["access-control-allow-methods"];
    console.log(`[HTTP METOTLAR] ${domain} -> İzin Verilenler: ${allow || "Sunucu Allow başlığı döndürmedi (HTTP " + r.status + ")"}`);
  } catch (e) {
    console.log(`[HATA] ${e.message}`);
  }
}

// ==========================================
// 4. KRİPTOGRAFİ, KODLAMA & ŞİFRE KASASI (12 MODÜL)
// ==========================================
function sifrele(metin, parola) {
  if (metin === undefined || !parola) return console.log('[!] Kullanım: sifrele("metin", "parola")');
  const salt = crypto.randomBytes(16), iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv("aes-256-gcm", _anahtarTuret(String(parola), salt), iv);
  const enc = Buffer.concat([cipher.update(String(metin), "utf8"), cipher.final()]);
  console.log(`[ŞİFRELİ METİN] ${Buffer.concat([salt, iv, cipher.getAuthTag(), enc]).toString("base64")}`);
}

function coz(b64, parola) {
  if (!b64 || !parola) return console.log('[!] Kullanım: coz("sifreli_base64", "parola")');
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
  if (metin === undefined) return console.log('[!] Kullanım: ozetle("metin")');
  const s = String(metin);
  console.log(`=== KRİPTOGRAFİK ÖZET (HASH) ===`);
  console.log(`  • MD5     : ${crypto.createHash("md5").update(s).digest("hex")}`);
  console.log(`  • SHA-1   : ${crypto.createHash("sha1").update(s).digest("hex")}`);
  console.log(`  • SHA-256 : ${crypto.createHash("sha256").update(s).digest("hex")}`);
  console.log(`  • SHA-512 : ${crypto.createHash("sha512").update(s).digest("hex")}`);
}

function base64_kodla(metin) {
  if (metin === undefined) return console.log('[!] Kullanım: base64_kodla("metin")');
  console.log(`[BASE64] ${Buffer.from(String(metin), "utf8").toString("base64")}`);
}

function base64_coz(kodStr) {
  const s = String(kodStr || "").trim();
  if (!s || !/^[A-Za-z0-9+/]+={0,2}$/.test(s) || s.length % 4 !== 0) {
    return console.log("[!] Geçersiz Base64 biçimi.");
  }
  console.log(`[ÇÖZÜLDÜ] ${Buffer.from(s, "base64").toString("utf8")}`);
}

function hex_kodla(metin) {
  if (metin === undefined) return console.log('[!] Kullanım: hex_kodla("metin")');
  console.log(`[HEX] ${Buffer.from(String(metin), "utf8").toString("hex")}`);
}

function hex_coz(hexStr) {
  const s = String(hexStr || "").trim().replace(/^0x/i, "").replace(/\s+/g, "");
  if (!s || s.length % 2 !== 0 || !/^[0-9a-fA-F]+$/.test(s)) {
    return console.log("[!] Geçersiz Hexadecimal biçimi.");
  }
  console.log(`[ÇÖZÜLDÜ] ${Buffer.from(s, "hex").toString("utf8")}`);
}

function jwt_coz(token) {
  try {
    const parcalar = String(token || "").trim().split(".");
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
  const n = Number(uzunluk);
  if (!Number.isInteger(n) || n < 4 || n > 4096) {
    return console.log("[!] Uzunluk 4 ile 4096 arasında tam sayı olmalıdır.");
  }
  const chars = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789!@#$%^&*_-+=";
  let sifre = "";
  for (let i = 0; i < n; i++) sifre += chars[crypto.randomInt(chars.length)];
  console.log(`[ÜRETİLEN PAROLA] ${sifre}`);
}

function parola_guc(parola) {
  if (parola === undefined || parola === "") return console.log("[!] İncelenecek parolayı girin.");
  const p = String(parola);
  let havuz = 0;
  if (/[a-z]/.test(p)) havuz += 26;
  if (/[A-Z]/.test(p)) havuz += 26;
  if (/[0-9]/.test(p)) havuz += 10;
  if (/[^a-zA-Z0-9]/.test(p)) havuz += 32;
  const benzersizOran = new Set(p).size / p.length;
  let entropi = Math.round(p.length * Math.log2(havuz || 1) * benzersizOran);
  const ardisik = /(0123|1234|2345|3456|4567|5678|6789|abcd|qwerty|asdf|password|sifre|123456)/i.test(p);
  if (ardisik) entropi = Math.min(entropi, 28);
  const seviye = entropi < 40 ? "ZAYIF" : entropi < 65 ? "ORTA" : entropi < 90 ? "GÜÇLÜ" : "ÇOK GÜÇLÜ";
  console.log(`=== PAROLA GÜÇ ANALİZİ ===\n  • Uzunluk : ${p.length} karakter (Benzersiz: ${new Set(p).size})\n  • Entropi : ~${entropi} bit\n  • Seviye  : ${seviye}${ardisik ? " (Tahmin edilebilir kalıp!)" : ""}`);
}

function kasa_ekle(etiket, veri, parola) {
  if (!etiket || veri === undefined || !parola) {
    return console.log('[!] Kullanım: kasa_ekle("etiket", "veri", "parola")');
  }
  let kasa = {};
  if (fs.existsSync(KASA_YOLU)) {
    try { kasa = JSON.parse(fs.readFileSync(KASA_YOLU, "utf8")); }
    catch { return console.log("[!] Kasa dosyası bozulmuş, üzerine yazma engellendi."); }
  }
  const salt = crypto.randomBytes(16), iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv("aes-256-gcm", _anahtarTuret(String(parola), salt), iv);
  const enc = Buffer.concat([cipher.update(String(veri), "utf8"), cipher.final()]);
  kasa[etiket] = Buffer.concat([salt, iv, cipher.getAuthTag(), enc]).toString("base64");
  fs.writeFileSync(KASA_YOLU, JSON.stringify(kasa, null, 2), { mode: 0o600 });
  console.log(`[KASA] '${etiket}' AES-256-GCM ile şifrelenip kaydedildi.`);
}

function kasa_oku(etiket, parola) {
  if (!fs.existsSync(KASA_YOLU)) return console.log("[KASA] Henüz kayıtlı bir kasa yok.");
  let kasa;
  try { kasa = JSON.parse(fs.readFileSync(KASA_YOLU, "utf8")); }
  catch { return console.log("[!] Kasa dosyası okunamadı veya bozuk."); }
  if (!etiket) {
    const anahtarlar = Object.keys(kasa);
    return console.log(`[KASA] Kayıtlı etiketler (${anahtarlar.length}): ${anahtarlar.join(", ") || "Yok"}`);
  }
  if (!kasa[etiket]) return console.log(`[KASA] '${etiket}' kaydı bulunamadı.`);
  if (!parola) return console.log('[!] Parola gerekli: kasa_oku("etiket", "parola")');
  coz(kasa[etiket], parola);
}

// ==========================================
// 5. ADLİ BİLİŞİM (FORENSICS) & DOSYA ANALİZİ (4 MODÜL)
// ==========================================
async function dosya_hash(dosyaYolu) {
  if (!dosyaYolu || !fs.existsSync(dosyaYolu)) return console.log(`[!] Dosya bulunamadı: ${dosyaYolu}`);
  const st = fs.statSync(dosyaYolu);
  if (!st.isFile()) return console.log(`[!] Hedef bir dosya değil (klasör/özel aygıt): ${dosyaYolu}`);
  const md5 = crypto.createHash("md5"), sha256 = crypto.createHash("sha256");
  await new Promise((resolve, reject) => {
    const stream = fs.createReadStream(dosyaYolu);
    stream.on("data", c => { md5.update(c); sha256.update(c); });
    stream.on("end", resolve);
    stream.on("error", reject);
  });
  console.log(`=== DOSYA BÜTÜNLÜK İMZASI: ${path.basename(dosyaYolu)} (${st.size} bayt) ===`);
  console.log(`  • MD5     : ${md5.digest("hex")}`);
  console.log(`  • SHA-256 : ${sha256.digest("hex")}`);
}

function dosya_tipi(dosyaYolu) {
  if (!dosyaYolu || !fs.existsSync(dosyaYolu)) return console.log(`[!] Dosya bulunamadı: ${dosyaYolu}`);
  const st = fs.statSync(dosyaYolu);
  if (!st.isFile()) return console.log(`[!] Hedef bir dosya değil: ${dosyaYolu}`);
  if (st.size === 0) return console.log(`[SİHİRLİ BAYT] ${path.basename(dosyaYolu)} -> Boş Dosya (0 bayt)`);
  const buf = Buffer.alloc(16);
  const fd = fs.openSync(dosyaYolu, "r");
  let okunan = 0;
  try { okunan = fs.readSync(fd, buf, 0, 16, 0); } finally { fs.closeSync(fd); }
  const hex = buf.subarray(0, okunan).toString("hex").toUpperCase();
  const imzalar = [
    ["89504E47", "PNG Görsel Dosyası"],
    ["FFD8FF", "JPEG Görsel Dosyası"],
    ["47494638", "GIF Görsel Dosyası"],
    ["25504446", "PDF Belgesi"],
    ["504B0304", "ZIP / APK / DOCX Arşivi"],
    ["7F454C46", "Linux ELF Çalıştırılabilir Dosyası"],
    ["4D5A", "Windows EXE / DLL Dosyası"],
    ["526172211A07", "RAR Arşivi"],
    ["1F8B", "GZIP Sıkıştırılmış Dosya"],
    ["53514C697465", "SQLite Veritabanı"],
    ["2321", "Betik Dosyası (Shebang #!)"]
  ];
  const bulunan = imzalar.find(([sig]) => hex.startsWith(sig));
  console.log(`[SİHİRLİ BAYT] ${path.basename(dosyaYolu)} -> Gerçek Tür: ${bulunan ? bulunan[1] : "Metin veya Bilinmeyen İkili (Hex: " + hex.slice(0, 12) + ")"}`);
}

async function metin_ayikla(dosyaYolu) {
  if (!dosyaYolu || !fs.existsSync(dosyaYolu)) return console.log(`[!] Dosya bulunamadı: ${dosyaYolu}`);
  const st = fs.statSync(dosyaYolu);
  if (!st.isFile()) return console.log(`[!] Hedef bir dosya değil: ${dosyaYolu}`);
  const dizeler = [];
  await new Promise((resolve, reject) => {
    const stream = fs.createReadStream(dosyaYolu, { encoding: "latin1", highWaterMark: 64 * 1024 });
    let artik = "";
    stream.on("data", chunk => {
      const birlesik = artik + chunk;
      const eslesen = birlesik.match(/[\x20-\x7E]{6,}/g) || [];
      for (const d of eslesen) { if (dizeler.length < 200) dizeler.push(d); }
      artik = birlesik.slice(-64);
      if (dizeler.length >= 200) { stream.destroy(); resolve(); }
    });
    stream.on("end", resolve);
    stream.on("error", reject);
  });
  console.log(`=== METİN AYIKLAMA (STRINGS): ${path.basename(dosyaYolu)} (İlk ${Math.min(30, dizeler.length)} dize) ===`);
  dizeler.slice(0, 30).forEach(d => console.log(`  • ${d}`));
}

async function log_analiz(logYolu) {
  if (!logYolu || !fs.existsSync(logYolu)) return console.log(`[!] Log dosyası bulunamadı: ${logYolu}`);
  const st = fs.statSync(logYolu);
  if (!st.isFile()) return console.log(`[!] Hedef bir dosya değil: ${logYolu}`);
  const ipSayac = {}, kodSayac = {};
  let satirSayisi = 0;
  try {
    const rl = readline.createInterface({ input: fs.createReadStream(logYolu, { encoding: "utf8" }), crlfDelay: Infinity });
    for await (const s of rl) {
      if (!s) continue;
      satirSayisi++;
      const ipler = s.match(/\b(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\b/g) || [];
      for (const ip of ipler) ipSayac[ip] = (ipSayac[ip] || 0) + 1;
      const kod = s.match(/(?:^|\s|"|:)(200|201|204|301|302|304|400|401|403|404|405|429|500|502|503|504)(?:\s|,|"|$)/);
      if (kod) kodSayac[kod[1]] = (kodSayac[kod[1]] || 0) + 1;
    }
  } catch (e) {
    return console.log(`[HATA] Log dosyası okunamadı (${e.code || e.message}).`);
  }
  console.log(`=== LOG GÜVENLİK ÖZETİ: ${path.basename(logYolu)} (${satirSayisi} satır) ===`);
  console.log("  • HTTP Durum Dağılımı:", Object.entries(kodSayac).map(([k, v]) => `${k}: ${v} kez`).join(" | ") || "Standart HTTP kodu yok");
  const topIp = Object.entries(ipSayac).sort((a, b) => b[1] - a[1]).slice(0, 5);
  console.log("  • En Çok Geçen IP'ler:", topIp.map(([ip, c]) => `${ip} (${c})`).join(", ") || "IP kaydı yok");
}

// ==========================================
// 6. AKILLI DENETİM & RAPORLAMA (v10.5 İMZA MODÜLLERİ)
// ==========================================
async function guvenlik_karnesi(domain) {
  domain = _temizDomain(domain);
  if (!domain) return console.log("[!] Geçerli bir alan adı girin.");
  console.log(`╔══════════════════════════════════════════════════════╗`);
  console.log(`║     🎓 ALFSEC v10.5 — 100 PUANLIK GÜVENLİK KARNESİ   ║`);
  console.log(`╚══════════════════════════════════════════════════════╝`);
  console.log(`Hedef: ${domain} | İnceleme Başlatılıyor...\n`);

  let puan = 100;
  const eksikler = [];
  const artilar = [];

  const [txtRes, dmarcRes] = await Promise.all([
    _dnsGuvenliCoz(dns.resolveTxt, domain),
    _dnsGuvenliCoz(dns.resolveTxt, `_dmarc.${domain}`)
  ]);
  if (txtRes.ok) {
    const spf = txtRes.data.map(t => t.join("").trim()).find(t => /^v=spf1(\s|$)/i.test(t));
    if (spf) artilar.push("SPF e-posta sahtecilik koruması aktif (+10)");
    else { puan -= 10; eksikler.push("[-10 Puan] SPF kaydı eksik -> Alan adınız üzerinden sahte e-posta gönderilebilir."); }
  } else { puan -= 10; eksikler.push(`[-10 Puan] DNS TXT sorgulanamadı (${txtRes.hata}).`); }

  if (dmarcRes.ok) {
    const dmarc = dmarcRes.data.map(t => t.join("").trim()).find(t => /^v=DMARC1(\s|;|$)/i.test(t));
    if (dmarc) artilar.push("DMARC politikası tanımlı (+10)");
    else { puan -= 10; eksikler.push("[-10 Puan] DMARC kaydı yok -> Oltalama saldırılarına karşı alan adı itibarı savunmasız."); }
  } else { puan -= 10; eksikler.push(`[-10 Puan] DMARC sorgulanamadı (${dmarcRes.hata}).`); }

  try {
    const r = await _httpGet(`https://${domain}`, { followRedirects: true });
    const h = r.headers;
    const csp = h["content-security-policy"] || "";
    artilar.push("HTTPS bağlantısı aktif (+15)");
    if (h["strict-transport-security"]) artilar.push("HSTS (Zorunlu HTTPS) aktif (+15)");
    else { puan -= 15; eksikler.push("[-15 Puan] HSTS başlığı eksik -> MITM saldırılarında HTTP'ye düşürülebilir."); }

    if (csp) artilar.push("CSP (XSS Kalkanı) yapılandırılmış (+15)");
    else { puan -= 15; eksikler.push("[-15 Puan] Content-Security-Policy (CSP) eksik -> Zararlı betik (XSS) riski artar."); }

    if (h["x-frame-options"] || /frame-ancestors/i.test(csp)) artilar.push("Clickjacking koruması aktif (+10)");
    else { puan -= 10; eksikler.push("[-10 Puan] X-Frame-Options / CSP frame-ancestors eksik -> Site sahte iframe içine gömülebilir."); }

    if (h["x-content-type-options"]) artilar.push("MIME-Sniffing koruması aktif (+5)");
    else { puan -= 5; eksikler.push("[-5 Puan] X-Content-Type-Options: nosniff başlığı eksik."); }

    if (h["x-powered-by"]) { puan -= 5; eksikler.push(`[-5 Puan] Sunucu altyapı bilgisini (${h["x-powered-by"]}) açıkça sızdırıyor.`); }
  } catch (e) {
    puan = 0;
    eksikler.push(`[KRİTİK] HTTPS bağlantısı kurulamadı (${e.message}).`);
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
    const r = await _httpGet(`https://api.pwnedpasswords.com/range/${prefix}`, { headers: { "Add-Padding": "true" } });
    if (r.status !== 200) {
      return console.log(`[!] Sızıntı API hatası (HTTP ${r.status}). Doğrulama yapılamadı.`);
    }
    const eslesen = r.body.split(/\r?\n/).find(s => s.startsWith(suffix + ":"));
    if (eslesen && Number(eslesen.split(":")[1]) > 0) {
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
  if (!ham) return console.log("[!] İncelenecek URL girin.");
  if (!/^https?:\/\//i.test(ham)) ham = "https://" + ham;
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
    if (net.isIP(host)) { risk += 35; bulgular.push("[+35 Risk] Alan adı yerine doğrudan ham IP adresi kullanılıyor."); }
    const trIkinciDuzey = /\.(com|gov|edu|org|bel|pol|tsk|k12|av|dr)\.tr$/i.test(host);
    if (host.split(".").length > (trIkinciDuzey ? 4 : 3)) {
      risk += 20;
      bulgular.push("[+20 Risk] Çok katmanlı şüpheli alt alan adı yapısı.");
    }

    const guvenliMi = /\.(gov\.tr|edu\.tr|tsk\.tr|pol\.tr)$/i.test(host) ||
      ["turkiye.gov.tr", "papara.com", "ziraatbank.com.tr", "garantibbva.com.tr", "accounts.google.com", "login.microsoftonline.com"].some(d => host === d || host.endsWith("." + d));
    const taklitAnahtar = /(edevlet|papara|ziraat|garanti|vakifbank|halkbank|isbank|ptt|yurtici).*(giris|login|verify|onay|iade|hediye|destek|guncelle|kargo)|(giris|login|verify|onay|iade|hediye|guncelle).*(edevlet|papara|ziraat|garanti)/i;
    if (taklitAnahtar.test(host) && !guvenliMi) {
      risk += 35;
      bulgular.push("[+35 Risk] Alan adında kurumsal marka/işlem taklidi kalıbı tespit edildi!");
    }

    try {
      const r = await _httpGet(ham, { maxBody: 150000, followRedirects: false });
      if (r.status >= 300 && r.status < 400 && r.headers.location) {
        const hedefHost = new URL(r.headers.location, ham).hostname.toLowerCase();
        if (hedefHost !== host) {
          risk += 20;
          bulgular.push(`[+20 Risk] Bağlantı farklı bir alana yönlendiriyor -> ${r.headers.location}`);
        }
      }
      if (/type=["']password["']/i.test(r.body)) {
        risk += 20;
        bulgular.push("[+20 Risk] Sayfa içerisinde parola giriş formu (Login) bulunuyor.");
      }
    } catch (e) {
      bulgular.push(`[BİLGİ] Sayfa içeriği alınamadı (${e.message}); yalnızca URL yapısı puanlandı.`);
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
  if (!domain) return console.log("[!] Geçerli bir alan adı girin.");
  console.log(`[*] '${domain}' için tam kapsamlı HTML güvenlik raporu hazırlanıyor...`);
  const karne = await guvenlik_karnesi(domain);
  const aRes = await _dnsGuvenliCoz(dns.resolve4, domain);
  const mxRes = await _dnsGuvenliCoz(dns.resolveMx, domain);
  const tarih = new Date().toLocaleString("tr-TR");
  const dosyaAdi = `alfsec_rapor_${domain.replace(/[^a-z0-9.-]/gi, "_")}.html`;
  const kayitYolu = path.join(process.cwd(), dosyaAdi);

  const d = escapeHtml(domain);
  const aStr = aRes.ok ? (aRes.data.map(escapeHtml).join(", ") || "Yok") : escapeHtml(aRes.hata);
  const mxStr = mxRes.ok ? (mxRes.data.map(x => escapeHtml(x.exchange)).join(", ") || "Yok") : escapeHtml(mxRes.hata);
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

  try {
    fs.writeFileSync(kayitYolu, html, "utf8");
    console.log(`\n[✓] Profesyonel HTML rapor kaydedildi: ${kayitYolu}`);
  } catch (e) {
    console.log(`[HATA] Rapor kaydedilemedi (${e.code || e.message}). Yazılabilir bir dizine geçin.`);
  }
}

// ==========================================
// 7. AĞ MİMARİSİ & ZAFİYET YÜZEYİ (v10.5 MODÜLLERİ)
// ==========================================
function alt_ag_hesapla(cidrGirdi) {
  const ham = String(cidrGirdi || "").trim();
  const m = ham.match(/^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})(?:\/(\d{1,2}))?$/);
  if (!m) return console.log('[!] Geçersiz CIDR formatı. Örnek kullanım: alt_ag_hesapla("192.168.45.142/26")');
  const oktetler = [Number(m[1]), Number(m[2]), Number(m[3]), Number(m[4])];
  const prefix = m[5] !== undefined ? Number(m[5]) : 24;

  if (oktetler.some(n => n < 0 || n > 255) || prefix < 0 || prefix > 32) {
    return console.log("[!] Geçersiz IPv4 oktet veya prefix değeri.");
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

  console.log(`=== IPv4 ALT AĞ (SUBNET) HESAPLAMA: ${oktetler.join(".")}/${prefix} ===`);
  console.log(`  • Alt Ağ Maskesi    : ${numToIp(maskeNum)} (/${prefix})`);
  console.log(`  • Ağ Adresi (Network): ${numToIp(agNum)}`);
  console.log(`  • Yayın (Broadcast)  : ${numToIp(broadcastNum)}`);
  console.log(`  • Kullanılabilir Aralık: ${ilkHost}  -->  ${sonHost}`);
  console.log(`  • Kullanılabilir Host: ${kullanilabilirHost.toLocaleString("tr-TR")} cihaz (Toplam ${toplamAdres.toLocaleString("tr-TR")} adres)`);
}

async function guvenlik_acigi_tarama(domain) {
  domain = _temizDomain(domain);
  if (!domain) return console.log("[!] Geçerli bir alan adı girin.");
  const kritikYollar = [
    ["/.git/HEAD", "Açık Git deposu (Kaynak kod sızıntısı riski)", r => /^ref:\s*refs\/|^[0-9a-f]{40}/i.test(r.body.trim())],
    ["/.env", "Ortam değişkenleri dosyası (API anahtarı / şifre sızıntısı riski)", r => !/<html|<body|<!doctype/i.test(r.body) && /^[A-Z0-9_]{2,}=/m.test(r.body)],
    ["/backup.zip", "Yedek arşiv dosyası", r => /zip|octet-stream/i.test(r.headers["content-type"] || "") || r.body.startsWith("PK")],
    ["/db.sql", "Veritabanı dökümü", r => !/<html/i.test(r.body) && /(CREATE TABLE|INSERT INTO|mysqldump|PostgreSQL)/i.test(r.body)],
    ["/phpinfo.php", "PHP yapılandırma bilgi sayfası", r => /PHP Version|phpinfo\(\)/i.test(r.body)],
    ["/server-status", "Apache sunucu durum paneli", r => /Apache Server Status|Total accesses:/i.test(r.body)],
    ["/admin", "Yönetim paneli giriş yolu", r => /type=["']password["']|admin|yönetim|login/i.test(r.body)],
    ["/wp-config.php.bak", "WordPress yedek yapılandırma dosyası", r => /DB_NAME|DB_PASSWORD|<\?php/i.test(r.body)]
  ];
  console.log(`=== HASSAS DOSYA & YÜZEY TARAMASI: ${domain} ===`);
  let bulgu = 0, hata = 0;
  for (const [yolEk, aciklama, dogrula] of kritikYollar) {
    try {
      const r = await _httpGet(`https://${domain}${yolEk}`, { maxBody: 30000, followRedirects: true });
      if (r.status === 200 && dogrula(r)) {
        console.log(`  [KRİTİK/AÇIK] ${yolEk.padEnd(20)} -> HTTP 200 | ${aciklama}`);
        bulgu++;
      } else if (r.status === 403) {
        console.log(`  [KISITLI]     ${yolEk.padEnd(20)} -> HTTP 403 | ${aciklama}`);
      }
    } catch { hata++; }
  }
  if (hata === kritikYollar.length) return console.log("[HATA] Hedefe hiç erişilemedi; tarama sonuçsuz.");
  console.log(`[✓] Tarama tamamlandı. Doğrulanmış açık kritik yol sayısı: ${bulgu} (Ağ hatası: ${hata})`);
}

async function baslik_analiz(domain) {
  domain = _temizDomain(domain);
  if (!domain) return console.log("[!] Geçerli bir alan adı girin.");
  try {
    const r = await _httpGet(`https://${domain}`, { followRedirects: true });
    console.log(`=== HTTP YANIT BAŞLIKLARI DENETİMİ: ${domain} (HTTP ${r.status}) ===`);
    for (const [k, v] of Object.entries(r.headers)) {
      let not = "";
      if (k === "x-powered-by" || k === "server") not = " [Bilgi Sızıntısı / Sürüm İzi]";
      if (k === "access-control-allow-origin" && v === "*") not = " [Tüm Kaynaklara Açık CORS (*)]";
      if (k === "strict-transport-security") not = " [HTTPS Zorlama Kalkanı]";
      if (k === "content-security-policy") not = " [XSS Kalkan Politikası]";
      console.log(`  • ${k}: ${v}${not}`);
    }
  } catch (e) { console.log(`[HATA] ${e.message}`); }
}

async function toplu_hedef_tara(...girdiler) {
  const hedefler = girdiler.join(",").split(",").map(x => _temizDomain(x)).filter(Boolean);
  if (!hedefler.length) return console.log('[!] En az bir hedef girin. Örnek: toplu_hedef_tara("google.com,github.com")');
  console.log(`=== TOPLU HEDEF KARŞILAŞTIRMA (${hedefler.length} Hedef) ===\n`);
  for (const h of hedefler) {
    if (!/^[a-zA-Z0-9.-]+$/.test(h)) { console.log(`  • ${h.padEnd(28)} | GEÇERSİZ HEDEF`); continue; }
    try {
      const r = await _httpGet(`https://${h}`, { followRedirects: true });
      const hsts = r.headers["strict-transport-security"] ? "HSTS:VAR" : "HSTS:YOK";
      const csp = r.headers["content-security-policy"] ? "CSP:VAR" : "CSP:YOK";
      console.log(`  • ${h.padEnd(28)} | HTTP ${String(r.status).padEnd(3)} | ${hsts} | ${csp}`);
    } catch (e) {
      console.log(`  • ${h.padEnd(28)} | HATA: ${e.message}`);
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
    const tam = /^https?:\/\//i.test(ham) ? ham : (/^https?%3A/i.test(ham) ? cozulmus : "https://" + ham);
    const u = new URL(tam);
    console.log(`  • Protokol    : ${u.protocol}`);
    console.log(`  • Alan Adı    : ${u.hostname}${u.port ? ":" + u.port : ""}`);
    console.log(`  • Yol (Path)  : ${decodeURIComponent(u.pathname)}`);
    if (u.hash) console.log(`  • Fragment    : ${u.hash}`);
    const params = [...u.searchParams.entries()];
    if (params.length) {
      console.log("  • Parametreler:");
      params.forEach(([k, v]) => console.log(`      - ${k} = ${v}`));
    }
  } catch (e) {
    console.log(`  [!] URL yapısı çözümlenemedi: ${e.message}`);
  }
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

  if (!Number.isInteger(p) || p < 1 || p > 65535) {
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
  if (!domain) return console.log("[!] Geçerli bir alan adı girin.");
  console.log(`=== DNS & E-POSTA GÜVENLİK DENETİMİ: ${domain} ===`);
  const [nsRes, txtRes, dmarcRes] = await Promise.all([
    _dnsGuvenliCoz(dns.resolveNs, domain),
    _dnsGuvenliCoz(dns.resolveTxt, domain),
    _dnsGuvenliCoz(dns.resolveTxt, `_dmarc.${domain}`)
  ]);
  const spf = txtRes.data.map(t => t.join("").trim()).find(t => /^v=spf1(\s|$)/i.test(t));
  const dmarc = dmarcRes.data.map(t => t.join("").trim()).find(t => /^v=DMARC1(\s|;|$)/i.test(t));

  console.log(`  • NS Sunucuları : ${!nsRes.ok ? `HATA (${nsRes.hata})` : (nsRes.data.length ? nsRes.data.join(", ") : "Bulunamadı")}`);
  console.log(`  • SPF Kaydı     : ${!txtRes.ok ? `HATA (${txtRes.hata})` : (spf ? "VAR (" + spf + ")" : "EKSİK")}`);
  console.log(`  • DMARC Kaydı   : ${!dmarcRes.ok ? `HATA (${dmarcRes.hata})` : (dmarc ? "VAR (" + dmarc + ")" : "EKSİK")}`);

  if (nsRes.ok && txtRes.ok && dmarcRes.ok) {
    if (!spf || !dmarc) {
      console.log("  ⚠️ Uyarı: SPF veya DMARC eksikliği alan adınız adına sahte e-posta gönderilmesini kolaylaştırabilir.");
    } else {
      console.log("  ✅ Temel e-posta kimlik doğrulama (SPF + DMARC) kayıtları mevcut.");
    }
  }
}

function metin_temizle_analiz(girdi) {
  if (girdi === undefined) return console.log("[!] İncelenecek metni girin.");
  const ham = String(girdi);
  const gorunmeyenSayisi = (ham.match(/[\x00-\x08\x0B\x0C\x0E-\x1F\x7F\u200B-\u200F\u202A-\u202E\uFEFF]/g) || []).length;
  const temiz = ham.replace(/[\x00-\x08\x0B\x0C\x0E-\x1F\x7F\u200B-\u200F\u202A-\u202E\uFEFF]/g, "");
  const b64Adaylari = temiz.match(/\b[A-Za-z0-9+/]{16,}={0,2}\b/g) || [];
  const gecerliB64 = b64Adaylari.some(b => {
    if (b.length % 4 !== 0) return false;
    try { return Buffer.from(b, "base64").toString("base64") === b; } catch { return false; }
  });
  const urlBenzeri = /https?:\/\/[^\s]+/i.test(temiz);

  console.log("=== METİN & GİRDİ GÜVENLİK ANALİZİ ===");
  console.log(`  • Uzunluk              : ${ham.length} karakter (Temizlenmiş: ${temiz.length})`);
  console.log(`  • Gizli Kontrol/Unicode: ${gorunmeyenSayisi} adet`);
  console.log(`  • Geçerli Base64 Blok  : ${gecerliB64 ? "TESPİT EDİLDİ" : "Yok"}`);
  console.log(`  • Bağlantı İçeriyor mu : ${urlBenzeri ? "EVET (oltalama_analiz ile kontrol önerilir)" : "Hayır"}`);
  console.log(`  • Temiz Çıktı          : ${temiz}`);
}

function ozet_karsilastir(metin1, metin2) {
  if (metin1 === undefined || metin2 === undefined) {
    return console.log('[!] Kullanım: ozet_karsilastir("metin1", "metin2")');
  }
  const h1 = crypto.createHash("sha256").update(String(metin1)).digest("hex");
  const h2 = crypto.createHash("sha256").update(String(metin2)).digest("hex");
  const esit = h1 === h2;

  console.log("=== SHA-256 BÜTÜNLÜK & EŞLEŞME KARŞILAŞTIRMA ===");
  console.log(`  • 1. Girdi SHA-256 : ${h1}`);
  console.log(`  • 2. Girdi SHA-256 : ${h2}`);
  console.log(`  • Sonuç            : ${esit ? "✅ EŞLEŞİYOR (Birebir aynı)" : "❌ EŞLEŞMİYOR (Farklı)"}`);
}

// ==========================================
// 10. İLERİ WEB GÜVENLİĞİ TESTLERİ (v10.5 MODÜLLERİ)
// ==========================================
async function sertifika_zincir(domain) {
  domain = _temizDomain(domain);
  if (!domain || (!/^[a-zA-Z0-9.-]+$/.test(domain) && !net.isIP(domain)) || domain.length > 253) {
    return console.log("[!] Geçersiz alan adı biçimi.");
  }
  console.log(`=== SSL/TLS SERTİFİKA ZİNCİRİ & SAN ANALİZİ: ${domain} ===`);
  return new Promise(resolve => {
    let bitti = false;
    const bitir = () => { if (!bitti) { bitti = true; resolve(); } };
    const s = tls.connect(443, domain, { servername: net.isIP(domain) ? undefined : domain, rejectUnauthorized: false }, () => {
      try {
        console.log(`  • Zincir Doğrulama: ${s.authorized ? "✅ GÜVENİLİR" : "⚠️ GÜVENSİZ (" + s.authorizationError + ")"}`);
        let cert = s.getPeerCertificate(true);
        const sanSet = new Set();
        let i = 0;
        const gorulen = new Set();
        while (cert && i < 10) {
          const ozet = (cert.fingerprint256 || "") + "|" + (cert.subject?.CN || "");
          if (gorulen.has(ozet)) break;
          gorulen.add(ozet);
          const suresiDolmus = cert.valid_to && new Date(cert.valid_to) < new Date();
          console.log(`  [${i}] Subject CN: ${cert.subject?.CN || "?"} | Issuer CN: ${cert.issuer?.CN || "?"}`);
          console.log(`      Geçerlilik: ${cert.valid_from || "?"} -> ${cert.valid_to || "?"}${suresiDolmus ? " [SÜRESİ DOLMUŞ]" : ""}`);
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
        console.log(`  • Aktif TLS: ${s.getProtocol()} / ${s.getCipher()?.name || "?"}`);
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
  if (!hedef) return console.log('[!] Denetlenecek URL girin. Örnek: csrf_denetle("https://site.com/form")');
  const tam = /^https?:\/\//i.test(hedef) ? hedef : "https://" + hedef;
  console.log(`=== CSRF (SİTE İÇİ İSTEK SAHTECİLİĞİ) DENETİMİ ===`);
  console.log(`İncelenen Sayfa: ${tam}\n`);
  try {
    const r = await _httpGet(tam, { maxBody: 500000, followRedirects: true });
    if (r.status !== 200) {
      return console.log(`[!] Sayfa alınamadı (HTTP ${r.status}).`);
    }
    const metaToken = /<meta\b[^>]*name\s*=\s*["']?(?:csrf-token|xsrf-token|_csrf)["']?[^>]*>/i.test(r.body);
    const formlar = [...r.body.matchAll(/<form\b[^>]*>([\s\S]*?)<\/form>/gi)];
    if (!formlar.length) {
      return console.log("  • Sayfada <form> etiketi bulunamadı.");
    }
    let postSayisi = 0, korumaliSayisi = 0;
    for (let i = 0; i < formlar.length; i++) {
      const form = formlar[i][0];
      const methodM = form.match(/\bmethod\s*=\s*(?:["']([^"']+)["']|([^\s>]+))/i);
      const method = (methodM ? (methodM[1] || methodM[2]) : "get").toLowerCase();
      if (method !== "post") continue;
      postSayisi++;
      const inputlar = [...form.matchAll(/<input\b[^>]*>/gi)].map(m => m[0]);
      const inputToken = inputlar.some(inp => {
        const nameM = inp.match(/\bname\s*=\s*(?:["']([^"']+)["']|([^\s>]+))/i);
        const ad = nameM ? (nameM[1] || nameM[2]) : "";
        return /(csrf|xsrf|authenticity_token|__requestverificationtoken|^_token$)/i.test(ad);
      });
      const actionM = form.match(/\baction\s*=\s*(?:["']([^"']*)["']|([^\s>]+))/i);
      const action = actionM ? (actionM[1] || actionM[2]) : "(kendi sayfası)";
      if (inputToken || metaToken) {
        korumaliSayisi++;
        console.log(`  [✓ KORUMALI] ${i + 1}. form POST -> ${action} (${inputToken ? "Form token" : "Meta CSRF token"} mevcut)`);
      } else {
        console.log(`  [⚠️ EKSİK] ${i + 1}. form POST -> ${action} (Form/Meta CSRF token görülmedi)`);
      }
    }
    if (postSayisi === 0) {
      console.log(`  • Toplam ${formlar.length} form var, hiçbiri POST metodu kullanmıyor.`);
    } else {
      console.log(`\n  [ÖZET] ${postSayisi} POST formdan ${korumaliSayisi} tanesinde CSRF token izi bulundu.`);
      if (korumaliSayisi < postSayisi) {
        console.log(`  🚨 [RİSK] ${postSayisi - korumaliSayisi} form CSRF korumasından yoksun olabilir.`);
      } else {
        console.log(`  ✅ Tüm POST formlarında token koruması tespit edildi.`);
      }
    }
  } catch (e) {
    console.log(`[HATA] ${e.message}`);
  }
}

async function acik_yonlendirme(url) {
  const hedef = String(url || "").trim();
  if (!hedef) return console.log('[!] Test edilecek URL girin. Örnek: acik_yonlendirme("https://site.com/redirect?url=x")');
  const tam = /^https?:\/\//i.test(hedef) ? hedef : "https://" + hedef;
  console.log(`=== AÇIK YÖNLENDİRME (OPEN REDIRECT) TESTİ ===`);
  let u;
  try { u = new URL(tam); } catch { return console.log("[!] Geçersiz URL biçimi."); }
  if (!/^https?:$/.test(u.protocol)) return console.log("[!] Yalnızca HTTP/HTTPS desteklenir.");
  const testHost = "example.org";
  const testHedef = `https://${testHost}/alfsec-open-redirect-test`;
  const parametreler = ["url", "next", "redirect", "redirect_url", "redirect_uri", "return", "returnUrl", "return_url", "return_to", "target", "dest", "destination", "continue", "goto", "redir", "r", "u"];
  const adaylar = [...new Set([...u.searchParams.keys(), ...parametreler])];
  const anaKok = u.hostname.split(".").slice(-2).join(".");
  console.log(`Temel URL: ${u.origin}${u.pathname}`);
  console.log(`Denenecek parametre sayısı: ${adaylar.length}\n`);
  let bulunan = 0, denenen = 0, hatalar = 0;
  for (const p of adaylar) {
    const deneme = new URL(tam);
    deneme.searchParams.set(p, testHedef);
    try {
      const r = await _httpGet(deneme.toString(), { maxBody: 50000, timeout: 6000, followRedirects: false });
      denenen++;
      const loc = r.headers?.location;
      if (r.status >= 300 && r.status < 400 && loc) {
        let locUrl;
        try { locUrl = new URL(loc, u.origin); } catch { continue; }
        if (locUrl.hostname === testHost || locUrl.hostname.endsWith("." + testHost)) {
          console.log(`  🚨 [AÇIK] ?${p}= -> HTTP ${r.status} -> ${loc}`);
          bulunan++;
        } else if (locUrl.hostname !== u.hostname && !locUrl.hostname.endsWith("." + anaKok)) {
          console.log(`  ⚠️ [HARİCİ] ?${p}= -> ${loc}`);
        }
      }
    } catch { hatalar++; }
  }
  if (denenen === 0) return console.log(`[HATA] Hiçbir istek gönderilemedi (${hatalar} ağ/SSRF hatası).`);
  console.log(`\n[✓] Test bitti (${denenen}/${adaylar.length} istek atıldı, ${hatalar} hata). Açık yönlendirme sinyali: ${bulunan}`);
  if (bulunan > 0) console.log("  ↳ Not: Bu zafiyet oltalama kampanyalarında kullanılabilir. Sunucu tarafında allowlist uygulanmalıdır.");
}

const ORNEK_DOSYA = fs.existsSync(process.argv[1] || "") ? process.argv[1] : "alfsec.js";

const MODULLER = [
  ["Savunma, Port Rehberi & Bütünlük (4 Modül)", [
    ["port_rehberi(445)", "Portun servisini, sınıfını ve güvenlik risklerini Türkçe açıklar.", "port_rehberi(445)"],
    ["dns_guvenlik(\"ornek.com\")", "NS, SPF ve DMARC kayıtlarını denetleyerek e-posta/DNS güvenliğini özetler.", "dns_guvenlik(\"github.com\")"],
    ["metin_temizle_analiz(\"metin\")", "Gizli kontrol/Unicode karakterlerini, Base64 kalıplarını ve URL varlığını inceler.", "metin_temizle_analiz(\"dGVzdC12ZXJpLTEyMzQ1Njc4OTA=\")"],
    ["ozet_karsilastir(\"a\", \"b\")", "İki metnin SHA-256 özetini çıkarıp birebir eşleşip eşleşmediğini doğrular.", "ozet_karsilastir(\"alfsec\", \"alfsec\")"]
  ]],
  ["İleri Web Güvenliği Testleri (3 Modül)", [
    ["sertifika_zincir(\"ornek.com\")", "Sunucu sertifikasının tam zincirini, güvenilirliğini ve SAN listesini çıkarır.", "sertifika_zincir(\"github.com\")"],
    ["csrf_denetle(\"https://site.com/form\")", "Formlarda ve meta etiketlerinde CSRF token alanı olup olmadığını denetler.", "csrf_denetle(\"https://github.com/login\")"],
    ["acik_yonlendirme(\"https://site.com/r?url=...\")", "URL parametrelerinde açık yönlendirme (Open Redirect) zafiyetini test eder.", "acik_yonlendirme(\"https://github.com/login?return_to=x\")"]
  ]],
  ["Ağ Mimarisi & Yüzey Analizi (5 Modül)", [
    ["alt_ag_hesapla(\"192.168.45.142/26\")", "CIDR bloğunun ağ, broadcast, ilk/son IP ve host kapasitesini hesaplar.", "alt_ag_hesapla(\"192.168.45.142/26\")"],
    ["guvenlik_acigi_tarama(\"ornek.com\")", ".git, .env, yedek ve kritik yolların dışa açık olup olmadığını içerik doğrulamalı tarar.", "guvenlik_acigi_tarama(\"github.com\")"],
    ["baslik_analiz(\"ornek.com\")", "HTTP yanıt başlıklarını bilgi sızıntısı ve güvenlik açısından inceler.", "baslik_analiz(\"github.com\")"],
    ["toplu_hedef_tara(\"site1.com,site2.com\")", "Birden fazla hedefi tek seferde HTTP durum ve kalkan açısından özetler.", "toplu_hedef_tara(\"example.com,github.com\")"],
    ["url_coz(\"url\")", "Kodlanmış URL'leri çözer, alan adını, yolu ve parametreleri ayrıştırır.", "url_coz(\"https%3A%2F%2Fgithub.com%2FBerkay5642%2Falfsec%3Fref%3Dv10.5\")"]
  ]],
  ["Akıllı Denetim & İmza Araçları (4 Modül)", [
    ["guvenlik_karnesi(\"ornek.com\")", "Hedefi tarayıp 100 üzerinden puanlı risk karnesi ve çözüm rehberi çıkarır.", "guvenlik_karnesi(\"github.com\")"],
    ["sizinti_kontrol(\"parola\")", "K-Anonimlik ile parolayı dışarı göndermeden küresel veri sızıntılarında arar.", "sizinti_kontrol(\"123456\")"],
    ["oltalama_analiz(\"supheli_link\")", "Şüpheli linkleri marka taklidi, Punycode ve yönlendirme tuzaklarına karşı inceler.", "oltalama_analiz(\"http://edevlet-iade-onay.com\")"],
    ["rapor_olustur(\"ornek.com\")", "Denetim sonuçlarını şık tasarımlı bir HTML güvenlik raporuna dönüştürür.", "rapor_olustur(\"github.com\")"]
  ]],
  ["Pasif OSINT & İstihbarat (10 Modül)", [
    ["tam_analiz(\"ornek.com\")", "DNS, Web Kalkanı, Teknoloji, SSL, Subdomain ve Nmap taramasını birleştirir.", "tam_analiz(\"example.com\")"],
    ["kullanici_ara(\"kullanici\")", "12 popüler platformda içerik doğrulamalı kullanıcı profil izi tarar.", "kullanici_ara(\"torvalds\")"],
    ["eposta_denetle(\"mail@site.com\")", "E-posta alan adının MX, SPF ve DMARC güvenlik kayıtlarını doğrular.", "eposta_denetle(\"info@github.com\")"],
    ["dns_detay(\"ornek.com\")", "A, AAAA, CNAME, MX, NS ve TXT kayıtlarının tamamını döker.", "dns_detay(\"google.com\")"],
    ["whois_sorgu(\"ornek.com\")", "Alan adının kayıt şirketini ve geçerlilik tarihlerini Türkçe gösterir.", "whois_sorgu(\"github.com\")"],
    ["subdomain_bul(\"ornek.com\")", "Sertifika şeffaflığı kayıtlarından alt alan adlarını listeler.", "subdomain_bul(\"example.com\")"],
    ["ip_analiz(\"8.8.8.8\")", "IP adresinin ülke, şehir, sağlayıcı ve ASN bilgisini getirir.", "ip_analiz(\"8.8.8.8\")"],
    ["ters_dns(\"8.8.8.8\")", "IP adresinin bağlı olduğu PTR alan adını sorgular.", "ters_dns(\"8.8.8.8\")"],
    ["mac_sorgu(\"00:1A:11:00:00:00\")", "MAC adresinin ilk 6 hanesinden cihaz üreticisini ve LAA durumunu tespit eder.", "mac_sorgu(\"00:1A:11:22:33:44\")"],
    ["telefon_bilgi(\"+905551234567\")", "Telefon numarasının ülke bölgesi ve E.164 format analizini yapar.", "telefon_bilgi(\"+905551234567\")"]
  ]],
  ["Ağ Teşhisi & Türkçe Nmap (9 Modül)", [
    ["nmap_turkce(\"hedef\")", "Sistemdeki Nmap'i çalıştırıp açık portları ve sürümleri Türkçe raporlar.", "nmap_turkce(\"127.0.0.1\")"],
    ["port_tara(\"hedef\", 1, 100)", "Dahili Node.js motoruyla hızlı TCP port taraması yapar.", "port_tara(\"127.0.0.1\", 1, 100)"],
    ["yerel_ag_tara(\"192.168.1\")", "Yerel ağınızdaki aktif cihazları çoklu port taramasıyla bulur.", "yerel_ag_tara(\"192.168.1\")"],
    ["servis_banner(\"hedef\", 80)", "Açık porttaki servisin kimlik (banner) bilgisini okur.", "servis_banner(\"example.com\", 80)"],
    ["ag_kimlik()", "Cihazın yerel IP adreslerini ve MAC bilgilerini gösterir.", "ag_kimlik()"],
    ["dis_ip()", "İnternete çıktığınız güncel genel IP adresini gösterir.", "dis_ip()"],
    ["tor_kontrol()", "Yerel Tor proxy servisinin (9050) aktif olup olmadığını denetler.", "tor_kontrol()"],
    ["sistem_bilgi()", "İşletim sistemini ve kurulu güvenlik araçlarını denetler.", "sistem_bilgi()"],
    ["guncelle()", "GitHub deposundan AlfSec'in en son sürümünü otomatik indirip kurar.", "guncelle()"]
  ]],
  ["Web Güvenliği & SSL Denetimi (7 Modül)", [
    ["web_denetle(\"ornek.com\")", "HSTS, CSP, Clickjacking, MIME ve Referrer kalkanlarını denetler.", "web_denetle(\"github.com\")"],
    ["ssl_analiz(\"ornek.com\")", "TLS protokol sürümünü ve sertifika geçerlilik/güvenilirlik durumunu inceler.", "ssl_analiz(\"github.com\")"],
    ["teknoloji_bul(\"ornek.com\")", "Sunucu yazılımını, CDN/WAF ve frontend altyapısını tespit eder.", "teknoloji_bul(\"github.com\")"],
    ["robots_oku(\"ornek.com\")", "Sitenin robots.txt kurallarını çekip listeler.", "robots_oku(\"github.com\")"],
    ["cerez_denetle(\"ornek.com\")", "Çerezlerin Secure, HttpOnly ve SameSite güvenlik bayraklarını kontrol eder.", "cerez_denetle(\"github.com\")"],
    ["link_cikar(\"https://ornek.com\")", "Sayfadaki tüm mutlak ve göreli bağlantıları ayıklar.", "link_cikar(\"https://example.com\")"],
    ["http_metotlar(\"ornek.com\")", "Sunucunun izin verdiği HTTP metotlarını sorgular.", "http_metotlar(\"example.com\")"]
  ]],
  ["Kriptografi, Kodlama & Şifre Kasası (12 Modül)", [
    ["sifrele(\"metin\", \"parola\")", "Veriyi AES-256-GCM algoritmasıyla şifreler.", "sifrele(\"gizli veri\", \"Sifre123\")"],
    ["coz(\"sifreli\", \"parola\")", "AES-256-GCM ile şifrelenmiş metni çözer.", "coz(\"...\", \"Sifre123\")"],
    ["ozetle(\"metin\")", "MD5, SHA-1, SHA-256 ve SHA-512 hash özetlerini üretir.", "ozetle(\"AlfSec\")"],
    ["base64_kodla(\"metin\")", "Metni Base64 formatına dönüştürür.", "base64_kodla(\"Merhaba\")"],
    ["base64_coz(\"kod\")", "Base64 kodunu okunabilir metne çevirir.", "base64_coz(\"TWVyaGFiYQ==\")"],
    ["hex_kodla(\"metin\")", "Metni Hexadecimal (16'lık) formata çevirir.", "hex_kodla(\"AlfSec\")"],
    ["hex_coz(\"hex\")", "Hexadecimal diziyi metne dönüştürür.", "hex_coz(\"416c66536563\")"],
    ["jwt_coz(\"token\")", "JWT token başlık ve içerik verisini çözümler.", "jwt_coz(\"eyJhbGciOiJIUzI1NiJ9.eyJ1c2VyIjoiYWxmcmVkIn0.xxx\")"],
    ["sifre_uret(24)", "Kriptografik olarak güvenli parola üretir.", "sifre_uret(24)"],
    ["parola_guc(\"parola\")", "Parolanın entropi bit gücünü ve kalıp zayıflıklarını ölçer.", "parola_guc(\"Deneme123!\")"],
    ["kasa_ekle(\"etiket\", \"veri\", \"parola\")", "Hassas veriyi yerel şifreli kasaya kaydeder.", "kasa_ekle(\"not\", \"1234\", \"anaSifre\")"],
    ["kasa_oku(\"etiket\", \"parola\")", "Yerel şifreli kasadaki veriyi çözer (argümansız etiketleri listeler).", "kasa_oku(\"not\", \"anaSifre\")"]
  ]],
  ["Adli Bilişim (Forensics) & Dosya Analizi (4 Modül)", [
    ["dosya_hash(\"dosya_yolu\")", "Dosyanın MD5 ve SHA-256 bütünlük imzasını akışla çıkarır.", `dosya_hash(${JSON.stringify(ORNEK_DOSYA)})`],
    ["dosya_tipi(\"dosya_yolu\")", "Sihirli baytlardan (Magic Bytes) dosyanın gerçek türünü bulur.", `dosya_tipi(${JSON.stringify(ORNEK_DOSYA)})`],
    ["metin_ayikla(\"dosya_yolu\")", "İkili dosyaların içindeki okunabilir dizeleri akışla ayıklar.", `metin_ayikla(${JSON.stringify(ORNEK_DOSYA)})`],
    ["log_analiz(\"log_yolu\")", "Log dosyasındaki HTTP durum kodlarını ve yoğun IP adreslerini özetler.", `log_analiz(${JSON.stringify(ORNEK_DOSYA)})`]
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

function _argumanAyir(str) {
  const args = [];
  let cur = "", q = null, esc = false, hasVal = false;
  for (let i = 0; i < str.length; i++) {
    const ch = str[i];
    if (esc) { cur += ch; esc = false; hasVal = true; continue; }
    if (ch === "\\" && q) { esc = true; continue; }
    if (q) {
      if (ch === q) q = null;
      else cur += ch;
      continue;
    }
    if (ch === '"' || ch === "'") { q = ch; hasVal = true; continue; }
    if (ch === ",") {
      args.push(cur.trim());
      cur = ""; hasVal = false;
      continue;
    }
    if (!/\s/.test(ch)) hasVal = true;
    cur += ch;
  }
  if (hasVal || args.length > 0) args.push(cur.trim());
  return args;
}

async function satirIsle(satir) {
  satir = String(satir || "").trim();
  if (!satir || satir.startsWith("#")) return;
  if (satir === "yardim" || satir === "help" || satir === "--help" || satir === "-h") {
    for (const [kat, liste] of MODULLER) {
      console.log(`\n▶ ${kat}:`);
      liste.forEach(([cmd, acik]) => console.log(`  • ${cmd.padEnd(36)} : ${acik}`));
    }
    console.log("\n▶ Sistem Komutları:");
    console.log("  • tui                                  : Etkileşimli menü modu (TUI)");
    console.log("  • gui                                  : Web GUI (http://127.0.0.1:8080)");
    console.log("  • cikis / exit                         : Programdan çık");
    return;
  }
  const m = satir.match(/^([a-z0-9_]+)\(([\s\S]*)\)$/i);
  if (!m) return console.log("[!] Geçersiz komut biçimi. Liste için 'yardim' yazın.");
  const fn = m[1];
  const args = m[2].trim() ? _argumanAyir(m[2]) : [];
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
  const origLog = console.log;
  console.log = (...a) => {
    const store = _logAls.getStore();
    if (store) store.push(a.join(" "));
    else origLog(...a);
  };
  const docsJson = JSON.stringify(MODULLER).replace(/</g, "\\u003c");
  const HTML = `<!DOCTYPE html><html lang="tr"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
  <title>AlfSec v10.5 — Türkçe OSINT & Pentest Paneli</title>
  <style>body{background:#090d16;color:#e2e8f0;font-family:system-ui,sans-serif;margin:0;padding:14px}
  h2{color:#38bdf8;margin:0 0 12px 0;font-size:18px}.kart{background:#111827;border:1px solid #1e293b;border-radius:10px;padding:12px;margin-bottom:12px}
  input{width:100%;box-sizing:border-box;background:#090d16;border:1px solid #334155;color:#fff;padding:10px;border-radius:8px;font-family:monospace;margin-bottom:8px}
  button{background:#0284c7;color:#fff;border:none;padding:8px 12px;border-radius:6px;font-weight:600;cursor:pointer;margin:2px}
  button.alt{background:#1e293b;color:#38bdf8;border:1px solid #334155}
  pre{background:#05080f;border:1px solid #1e293b;color:#22c55e;padding:12px;border-radius:8px;min-height:150px;white-space:pre-wrap;font-size:12px}</style></head>
  <body><h2>🛡️ AlfSec v10.5 — Türkçe Siber Güvenlik & OSINT Merkezi</h2>
  <div class="kart"><input id="c" value='tam_analiz("example.com")'><button onclick="calistir(document.getElementById('c').value)">Komutu Çalıştır</button>
  <button class="alt" onclick="calistir('sistem_bilgi()')">Sistem Durumu</button><button class="alt" onclick="calistir('dis_ip()')">Dış IP</button></div>
  <div class="kart"><pre id="o">Hazır. Aşağıdaki kategorilerden bir modül seçip tek tıkla Türkçe rapor alabilirsiniz.</pre></div>
  <div id="moduller"></div>
  <script>const M=${docsJson};
  function escHtml(s){return String(s).replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));}
  async function calistir(cmd){document.getElementById('c').value=cmd;document.getElementById('o').textContent='⏳ Çalıştırılıyor: '+cmd+'...';const r=await fetch('/run?c='+encodeURIComponent(cmd));document.getElementById('o').textContent=await r.text();}
  const alan=document.getElementById('moduller');
  M.forEach(([kat,list])=>{
    const kart=document.createElement('div');kart.className='kart';
    kart.innerHTML='<h3 style="color:#38bdf8;margin-top:0;font-size:14px">📂 '+escHtml(kat)+'</h3>';
    list.forEach(([cmd,acik,ornek])=>{
      const row=document.createElement('div');
      row.style.cssText='padding:6px 0;border-bottom:1px solid #1e293b;display:flex;justify-content:space-between;align-items:center;gap:8px';
      row.innerHTML='<div><b style="color:#22c55e;font-family:monospace">'+escHtml(cmd)+'</b><div style="font-size:12px;color:#94a3b8">'+escHtml(acik)+'</div></div>';
      const btn=document.createElement('button');btn.className='alt';btn.textContent='Çalıştır';
      btn.onclick=()=>calistir(ornek);
      row.appendChild(btn);kart.appendChild(row);
    });
    alan.appendChild(kart);
  });</script></body></html>`;

  const sunucu = http.createServer(async (req, res) => {
    const u = new URL(req.url, "http://localhost");
    if (u.pathname === "/") { res.writeHead(200, { "Content-Type": "text/html; charset=utf-8" }); return res.end(HTML); }
    if (u.pathname === "/run") {
      const satirlar = [];
      await _logAls.run(satirlar, async () => {
        try {
          await satirIsle(u.searchParams.get("c") || "");
        } catch (e) {
          satirlar.push("[HATA] " + (e?.message || String(e)));
        }
      });
      res.writeHead(200, { "Content-Type": "text/plain; charset=utf-8" });
      return res.end(satirlar.join("\n") || "[✓] Tamamlandı.");
    }
    res.writeHead(404, { "Content-Type": "text/plain; charset=utf-8" }); res.end("Not Found");
  });
  sunucu.on("error", e => { origLog(`[HATA] GUI sunucusu başlatılamadı: ${e.message}`); process.exit(1); });
  sunucu.listen(8080, "127.0.0.1", () => {
    origLog("[*] AlfSec v10.5 Web GUI hazır: http://127.0.0.1:8080");
    const opener = _aracVarMi("termux-open-url") ? "termux-open-url" : (_aracVarMi("xdg-open") ? "xdg-open" : null);
    if (opener) {
      const p = execFile(opener, ["http://127.0.0.1:8080"]);
      p.on("error", () => {});
    }
  });
}

function replBaslat() {
  console.log("=== ALFSEC v10.5 — TÜRKÇE SİBER GÜVENLİK KONSOLU ('yardim' | 'tui' | 'gui' | 'cikis') ===");
  const rl = readline.createInterface({ input: process.stdin, output: process.stdout, prompt: "\nalfsec> " });
  rl.prompt();
  rl.on("line", async line => {
    const g = line.trim();
    const alt = g.toLowerCase();
    if (["cikis", "exit"].includes(alt)) process.exit(0);
    if (alt === "gui") { rl.close(); return guiBaslat(); }
    if (alt === "tui") {
      rl.close();
      if (await tuiBaslat() === "cli") return replBaslat();
      return;
    }
    await satirIsle(g);
    rl.prompt();
  });
}

(async () => {
  const args = process.argv.slice(2);
  if (args[0] === "gui") return guiBaslat();
  if (args[0] === "tui") { if (await tuiBaslat() !== "cli") return; }
  if (["--help", "-h", "help", "yardim"].includes(args[0])) { await satirIsle("yardim"); return; }
  if (args[0] === "-c" && args[1]) return await satirIsle(args.slice(1).join(" "));
  if (args[0] && !args[0].startsWith("-")) return await satirIsle(args.join(" "));
  replBaslat();
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