FROM nginx:stable

ARG TARGETARCH
ENV PORT=8080 \
    DEBIAN_FRONTEND=noninteractive

RUN apt-get update \
    && apt-get install -y --no-install-recommends curl unzip ca-certificates util-linux \
    && rm -rf /var/lib/apt/lists/*

# Xray-core مثبّت على الإصدار المُختبَر (الإصدارات الأحدث قد تزيل WebSocket)
ARG XRAY_VERSION=v26.10.31
RUN set -eux; \
    case "${TARGETARCH:-$(dpkg --print-architecture)}" in \
        amd64) A=64 ;; \
        arm64) A=arm64-v8a ;; \
        *) echo "unsupported arch"; exit 1 ;; \
    esac; \
    curl -fsSL "https://github.com/XTLS/Xray-core/releases/download/${XRAY_VERSION}/Xray-linux-${A}.zip" -o /tmp/xray.zip; \
    mkdir -p /usr/local/share/xray; \
    unzip -o /tmp/xray.zip xray geoip.dat geosite.dat -d /tmp/xray; \
    mv /tmp/xray/xray /usr/local/bin/xray; \
    mv /tmp/xray/geoip.dat /tmp/xray/geosite.dat /usr/local/share/xray/; \
    chmod +x /usr/local/bin/xray; \
    rm -rf /tmp/xray /tmp/xray.zip; \
    xray version

COPY entrypoint.sh /app/entrypoint.sh
COPY index.html /usr/share/nginx/html/index.html
RUN sed -i 's/\r$//' /app/entrypoint.sh && chmod +x /app/entrypoint.sh

EXPOSE 8080
ENTRYPOINT ["/app/entrypoint.sh"]