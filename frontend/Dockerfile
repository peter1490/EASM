# Dockerfile for frontend - supports both development and production
# Build with: docker build --build-arg ENVIRONMENT=development|production

ARG ENVIRONMENT=production

# ============================================================================
# Development Stage
# ============================================================================
FROM node:20-alpine AS development

WORKDIR /app

# Install build dependencies for native modules (needed for lightningcss, etc.)
RUN apk add --no-cache python3 make g++

# Copy package files
COPY package.json package-lock.json ./

# Install all dependencies (including dev dependencies and optional native binaries)
RUN npm ci --include=optional

# Copy source code
COPY . .

# Expose port
EXPOSE 3000

# Set environment variables for development
ENV NODE_ENV=development
ENV NEXT_TELEMETRY_DISABLED=1

# Run in development mode with hot reload
CMD ["npm", "run", "dev"]

# ============================================================================
# Production Dependencies Stage
# ============================================================================
FROM node:20-alpine AS deps

WORKDIR /app

# Install build dependencies for native modules
RUN apk add --no-cache python3 make g++

COPY package.json package-lock.json ./
RUN npm ci --include=optional

# ============================================================================
# Production Build Stage
# ============================================================================
FROM node:20-alpine AS build

WORKDIR /app

# Install build dependencies for native modules (needed for build step)
RUN apk add --no-cache python3 make g++

COPY --from=deps /app/node_modules ./node_modules
COPY . .
RUN npm run build

# ============================================================================
# Production Runtime Stage
# ============================================================================
FROM node:20-alpine AS production

WORKDIR /app

# Set production environment
ENV NODE_ENV=production
ENV NEXT_TELEMETRY_DISABLED=1

# Install only production dependencies for the runtime image
COPY --from=build /app/package.json /app/package-lock.json ./
RUN npm ci --omit=dev --include=optional

# Copy built assets
COPY --from=build /app/.next ./.next
COPY --from=build /app/public ./public

# Expose port
EXPOSE 3000

# Run the application
CMD ["npm", "start"]

# ============================================================================
# Final Stage - Select based on ENVIRONMENT
# ============================================================================
FROM ${ENVIRONMENT} AS final
