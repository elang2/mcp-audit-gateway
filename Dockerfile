FROM node:20-alpine AS builder
WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci --ignore-scripts
COPY tsconfig.json tsconfig.build.json ./
COPY src/ src/
RUN npx tsc -p tsconfig.build.json

FROM node:20-alpine
WORKDIR /app
COPY --from=builder /app/dist/ dist/
COPY --from=builder /app/node_modules/ node_modules/
COPY --from=builder /app/package.json .
COPY docker/gateway.config.json ./gateway.config.json
COPY docker/echo-server.mjs ./echo-server.mjs
EXPOSE 3000
CMD ["node", "dist/cli.js", "serve", "gateway.config.json"]
