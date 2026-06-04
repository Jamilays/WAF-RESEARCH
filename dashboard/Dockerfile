# syntax=docker/dockerfile:1.7
# ==============================================================================
# WAF Evasion Lab dashboard — Vite/React/TS/Tailwind built into a static
# bundle and served by nginx. The nginx layer also proxies /api/* to the
# FastAPI container inside the waflab network.
# ==============================================================================
FROM node:20-alpine AS build
WORKDIR /build
COPY package.json ./
RUN npm install --no-audit --no-fund
COPY tsconfig.json vite.config.ts tailwind.config.js postcss.config.js index.html ./
COPY src ./src
RUN npm run build

FROM nginx:1.27-alpine
COPY --from=build /build/dist /usr/share/nginx/html
COPY nginx.conf /etc/nginx/conf.d/default.conf
EXPOSE 80
HEALTHCHECK --interval=10s --timeout=3s --start-period=5s --retries=5 \
  CMD wget -q -O- http://127.0.0.1/healthz >/dev/null || exit 1
