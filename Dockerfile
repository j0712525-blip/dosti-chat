# Dosti Chat — Docker image (optional; for hosts like Fly.io / Koyeb / self-hosting)
FROM node:24-alpine
WORKDIR /app
COPY package*.json .node-version ./
RUN npm ci --omit=dev --no-audit --no-fund
COPY . .
# Data (SQLite + uploads + VAPID keys) lives here; mount a volume for persistence
VOLUME ["/app/data"]
ENV PORT=3000 DATA_DIR=/app/data UPLOAD_DIR=/app/data/uploads
EXPOSE 3000
CMD ["node", "server.js"]
