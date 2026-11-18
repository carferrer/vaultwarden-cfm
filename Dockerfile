ARG BUILD_FROM=ghcr.io/hassio-addons/debian-base:9.5.2
###############################################################################
# Obtener los contenedores precompilados de Vaultwarden
###############################################################################
FROM "vaultwarden/server:1.37.5" AS vaultwarden

###############################################################################
# Construir el complemento
###############################################################################
# hadolint ignore=DL3006
FROM ${BUILD_FROM}

# Configurar el intérprete de comandos
SHELL ["/bin/bash", "-o", "pipefail", "-c"]

# Copiar Vaultwarden desde las imágenes oficiales
COPY --from=vaultwarden /vaultwarden /opt/vaultwarden
COPY --from=vaultwarden /web-vault /opt/web-vault

# Instalar Nginx y Fail2ban
# hadolint ignore=DL3009
RUN \
    apt-get update \
    \
    && apt-get install -y --no-install-recommends \
        libmariadb-dev-compat=1:11.8.6-0+deb13u1 \
        libpq5=17.11-0+deb13u1 \
        nginx=1.26.3-3+deb13u10 \
        fail2ban=1.1.0-8 \
        sqlite3=3.46.1-7+deb13u2 \
    && apt-get clean \
    && rm -f -r \
        /etc/nginx \
    \
    && mkdir -p /var/log/nginx \
    && touch /var/log/nginx/error.log

# Copiar los archivos de configuración del complemento
COPY rootfs /

RUN chmod +x /etc/s6-overlay/s6-rc.d/init-nginx/run \
    /etc/s6-overlay/s6-rc.d/fail2ban/run

# Argumentos de compilación
ARG BUILD_ARCH
ARG BUILD_DATE
ARG BUILD_DESCRIPTION
ARG BUILD_NAME
ARG BUILD_REF
ARG BUILD_REPOSITORY
ARG BUILD_VERSION

# Metadatos de la imagen
LABEL \
    io.hass.name="${BUILD_NAME}" \
    io.hass.description="${BUILD_DESCRIPTION}" \
    io.hass.arch="${BUILD_ARCH}" \
    io.hass.type="addon" \
    io.hass.version=${BUILD_VERSION} \
    maintainer="Carlos <carferrermar@gmail.com>" \
    org.opencontainers.image.title="${BUILD_NAME}" \
    org.opencontainers.image.description="${BUILD_DESCRIPTION}" \
    org.opencontainers.image.vendor="Home Assistant Community Apps" \
    org.opencontainers.image.authors="Carlos <carferrermar@gmail.com>" \
    org.opencontainers.image.licenses="MIT" \
    org.opencontainers.image.url="https://github.com/carferrer" \
    org.opencontainers.image.source="https://github.com/${BUILD_REPOSITORY}" \
    org.opencontainers.image.documentation="https://github.com/${BUILD_REPOSITORY}/blob/main/README.md" \
    org.opencontainers.image.created=${BUILD_DATE} \
    org.opencontainers.image.revision=${BUILD_REF} \
    org.opencontainers.image.version=${BUILD_VERSION}
