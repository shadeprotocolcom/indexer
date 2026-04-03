FROM node:20-alpine AS builder

WORKDIR /app

# Install build dependencies for better-sqlite3 native addon.
RUN apk add --no-cache python3 make g++

COPY package.json ./
RUN npm install

COPY tsconfig.json ./
COPY src/ ./src/

RUN npm run build

# -------------------------------------------------------------------
# Production image
# -------------------------------------------------------------------
FROM node:20-alpine

WORKDIR /app

# Runtime dependency for better-sqlite3.
RUN apk add --no-cache python3 make g++

COPY package.json ./
RUN npm install --omit=dev

# Copy compiled JavaScript from builder.
COPY --from=builder /app/dist ./dist

# Data directory for the SQLite database.
RUN mkdir -p /data
ENV DB_PATH=/data/shade-indexer.db

EXPOSE 4000

CMD ["node", "dist/index.js"]
