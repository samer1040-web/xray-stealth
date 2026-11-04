#!/usr/bin/env bash
# VLESS + WebSocket خلف nginx. TLS يتولاه Railway (نطاق https العام).
set -u

PORT="${PORT:-8080}"
XRAY_PORT=10000
UUID="${UUID:-}"
WS_PATH="${WS_PATH:-}"
export XRAY_LOCATION_ASSET=/usr/local/share/xray
GENERATED=0

if [ -z "$UUID" ]; then
  UUID="$(xray uuid)"
  GENERATED=1
fi
if [ -z "$WS_PATH" ]; then
  WS_PATH="/$(head -c 12 /dev/urandom | od -An -tx1 | tr -d ' \n')"
  GENERATED=1
fi
case "$WS_PATH" in /*) ;; *) WS_PATH="/${WS_PATH}" ;; esac

# ---------- Xray ----------
cat >/etc/xray.json <<EOF
{
  "log": { "loglevel": "none" },
  "inbounds": [{
    "listen": "127.0.0.1",
    "port": ${XRAY_PORT},
    "protocol": "vless",
    "settings": { "clients": [{ "id": "${UUID}" }], "decryption": "none" },
    "streamSettings": { "network": "ws", "wsSettings": { "path": "${WS_PATH}" } },
    "sniffing": { "enabled": true, "destOverride": ["http", "tls"], "routeOnly": true }
  }],
  "outbounds": [
    { "tag": "direct", "protocol": "freedom", "streamSettings": { "sockopt": { "domainStrategy": "UseIPv4" } } },
    { "tag": "block", "protocol": "blackhole" }
  ],
  "routing": {
    "domainStrategy": "IPIfNonMatch",
    "rules": [
      { "type": "field", "ip": ["geoip:private"], "outboundTag": "block" },
      { "type": "field", "protocol": ["bittorrent"], "outboundTag": "block" },
      { "type": "field", "port": "25,465,587,135,137,138,139,445", "outboundTag": "block" },
      { "type": "field", "network": "udp", "port": "443", "outboundTag": "block" }
    ]
  }
}
EOF
chmod 600 /etc/xray.json

# ---------- nginx (تمويه + تمرير WebSocket فقط على المسار السري) ----------
cat >/etc/nginx/nginx.conf <<EOF
worker_processes 1;
pid /run/nginx.pid;
error_log /dev/null crit;
events { worker_connections 1024; }
http {
  include /etc/nginx/mime.types;
  access_log off;
  server_tokens off;
  map \$http_upgrade \$is_ws { default 0; websocket 1; }
  server {
    listen ${PORT};
    root /usr/share/nginx/html;
    index index.html;
    location ${WS_PATH} {
      if (\$is_ws = 0) { return 404; }
      proxy_pass http://127.0.0.1:${XRAY_PORT};
      proxy_http_version 1.1;
      proxy_set_header Upgrade \$http_upgrade;
      proxy_set_header Connection "upgrade";
      proxy_set_header Host \$host;
      proxy_buffering off;
      proxy_read_timeout 3600s;
      proxy_send_timeout 3600s;
    }
    location / { try_files \$uri \$uri/ =404; }
  }
}
EOF

# ---------- تشغيل ----------
(
  while true; do
    xray run -c /etc/xray.json >/dev/null 2>&1
    echo "[xray] exited; restarting in 3s"
    sleep 3
  done
) &

DOMAIN="${RAILWAY_PUBLIC_DOMAIN:-${PUBLIC_DOMAIN:-YOUR-DOMAIN}}"
ENC_PATH="${WS_PATH//\//%2F}"
echo "[xray] ready on :${PORT}"
echo "[link] vless://${UUID}@${DOMAIN}:443?encryption=none&security=tls&sni=${DOMAIN}&fp=chrome&alpn=http%2F1.1&type=ws&host=${DOMAIN}&path=${ENC_PATH}#railway"
if [ "$GENERATED" = "1" ]; then
  echo "[تحذير] UUID أو WS_PATH غير مضبوطين: قيم عشوائية تتغير عند كل نشر. ثبّتهما في Variables."
fi

exec nginx -g 'daemon off;'