ARG ALPINE_IMAGE
FROM ${ALPINE_IMAGE}

ARG APK_REPOSITORY
RUN printf '%s/main\n%s/community\n' "$APK_REPOSITORY" "$APK_REPOSITORY" > /etc/apk/repositories \
    && apk add --no-cache linux-lts clamav cpio coreutils findutils gzip kmod
COPY usb-scan-init /init
COPY clamav-db/ /var/lib/clamav/
RUN chmod 0755 /init \
    && test -n "$(find /var/lib/clamav -maxdepth 1 \( -name '*.cvd' -o -name '*.cld' \) -print -quit)"
