#!/usr/bin/env bash
set -e

echo "[*] AlfSec v10.0 Kurulumu Başlatılıyor..."

if ! command -v node >/dev/null 2>&1; then
  echo "[!] Node.js bulunamadı. Otomatik kuruluyor..."
  if command -v pkg >/dev/null 2>&1; then
    pkg update -y && pkg install -y nodejs
  elif command -v apt >/dev/null 2>&1; then
    sudo apt update && sudo apt install -y nodejs
  elif command -v pacman >/dev/null 2>&1; then
    sudo pacman -Sy --noconfirm nodejs
  else
    echo "[X] Paket yöneticisi algılanamadı. Lütfen Node.js kurup tekrar deneyin."
    exit 1
  fi
fi

HEDEF="${PREFIX:-/usr/local}/bin/alfsec"

if [ -w "$(dirname "$HEDEF")" ]; then
  cp alfsec.js "$HEDEF" && chmod +x "$HEDEF"
else
  sudo cp alfsec.js "$HEDEF" && sudo chmod +x "$HEDEF"
fi

echo "[✓] Kurulum tamamlandı! Artık her klasörden doğrudan 'alfsec', 'alfsec tui' veya 'alfsec gui' yazabilirsiniz."
