FROM python:3.12-alpine

WORKDIR /app

COPY app/server.py /app/server.py
COPY app/entrypoint.sh /entrypoint.sh

RUN addgroup -g 10001 app \
 && adduser -D -H -u 10001 -G app app \
 && apk add --no-cache su-exec \
 && chmod 0755 /entrypoint.sh

ENV HOME=/data
ENV PYTHONUNBUFFERED=1

EXPOSE 8791

ENTRYPOINT ["/entrypoint.sh"]
