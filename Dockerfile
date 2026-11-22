# syntax=docker/dockerfile:1

# 1) Build the Vue frontend.
FROM node:22-alpine AS web
WORKDIR /src/web
COPY web/package.json web/package-lock.json ./
RUN npm ci --no-audit --no-fund
COPY web/ ./
# vite writes into ../internal/ui/dist, i.e. /src/internal/ui/dist
RUN npm run build

# 2) Build a static Go binary with the frontend embedded.
FROM golang:1.23-alpine AS build
WORKDIR /src
COPY go.mod ./
COPY cmd/ cmd/
COPY internal/ internal/
COPY --from=web /src/internal/ui/dist/ internal/ui/dist/
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/leakscan ./cmd/leakscan

# 3) Small runtime image. git is needed to clone repositories, so not distroless.
FROM alpine:3.20
RUN apk add --no-cache git ca-certificates && adduser -D -H -u 10001 scanner
COPY --from=build /out/leakscan /usr/local/bin/leakscan
USER 10001
EXPOSE 8080
ENTRYPOINT ["leakscan"]
# Listens on $PORT if the platform sets it, otherwise :8080.
CMD ["serve"]
