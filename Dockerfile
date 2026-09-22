# ==============================================================================
# PhishGuard Inspector - Multi-Stage Production Container for Google Cloud Run
# ==============================================================================

# ------------------------------------------------------------------------------
# Stage 1: Build the React / Vite Client Application
# ------------------------------------------------------------------------------
FROM node:22-alpine AS builder

WORKDIR /app

# Copy root and client package definitions for layer caching
COPY package*.json ./
COPY client/package*.json ./client/

# Install root and client dependencies
RUN npm ci
RUN npm --prefix client ci

# Copy source code
COPY . .

# Compile client frontend production assets to client/dist
RUN npm run build --prefix client

# ------------------------------------------------------------------------------
# Stage 2: Minimal, Hardened Production Runtime
# ------------------------------------------------------------------------------
FROM node:22-alpine AS runner

WORKDIR /app

# Set container production environment
ENV NODE_ENV=production
ENV PORT=8080

# Install only production dependencies for root server
COPY package*.json ./
RUN npm ci --omit=dev && npm cache clean --force

# Copy server code
COPY server/ ./server/

# Copy built frontend assets from builder stage
COPY --from=builder /app/client/dist ./client/dist

# Security Hardening: Switch to built-in non-root user 'node'
USER node

# Expose standard Cloud Run ingress port
EXPOSE 8080

# Health check
HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
  CMD wget --no-verbose --tries=1 --spider http://localhost:8080/api/health || exit 1

# Start the Express server
CMD ["node", "server/index.js"]
