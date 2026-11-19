FROM python:3.12-alpine

WORKDIR /app

COPY app/server.py /app/server.py
COPY app/adbctl.py /app/adbctl.py
COPY app/pngcheck.py /app/pngcheck.py
COPY app/control.py /app/control.py
COPY app/options_bridge.py /app/options_bridge.py
COPY app/adb_home.py /app/adb_home.py
COPY app/reconnect.py /app/reconnect.py
COPY app/entrypoint.sh /entrypoint.sh

RUN addgroup -g 10001 app \
 && adduser -D -H -h /data -u 10001 -G app app \
 && apk add --no-cache su-exec android-tools \
 && chmod 0755 /entrypoint.sh

ENV HOME=/data
ENV PYTHONUNBUFFERED=1

EXPOSE 8791

ENTRYPOINT ["/entrypoint.sh"]
