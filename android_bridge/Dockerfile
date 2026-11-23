FROM python:3.12-alpine

WORKDIR /app

# Every module under app/ must reach the image. 0.3.28 copied them one at a
# time and never copied app/annotate.py, so the container died at import time.
# Ownership and modes are unchanged: files stay root-owned, with the source
# permissions the per-file copies produced.
COPY app/*.py /app/
COPY app/entrypoint.sh /entrypoint.sh

RUN addgroup -g 10001 app \
 && adduser -D -H -h /data -u 10001 -G app app \
 && apk add --no-cache su-exec android-tools \
 && chmod 0755 /entrypoint.sh

ENV HOME=/data
ENV PYTHONUNBUFFERED=1

EXPOSE 8791

ENTRYPOINT ["/entrypoint.sh"]
