# syntax=docker/dockerfile:1.7
FROM python:3.12-alpine
RUN apk add --no-cache wget && addgroup -S waf && adduser -S -G waf waf
WORKDIR /app
COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt
COPY proxy.py ./
USER waf
EXPOSE 80
ENV LISTEN_PORT=80 BACKEND=http://whoami:80 SHADOWD_HOST=shadowd SHADOWD_PORT=9115 SHADOWD_ENFORCE=false
CMD ["sh", "-c", "exec uvicorn proxy:app --host 0.0.0.0 --port ${LISTEN_PORT} --no-access-log"]
