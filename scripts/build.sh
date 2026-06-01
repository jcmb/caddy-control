#!/bin/bash
set -euo pipefail

APP_NAME="caddy-control"
ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
VERSION="$(cat "$ROOT_DIR/VERSION")"
OUT_DIR="$ROOT_DIR/dist"
LDFLAGS="-X main.version=$VERSION"

mkdir -p "$OUT_DIR"
cd "$ROOT_DIR/app"
go mod tidy

build() {
  local goos=$1 goarch=$2 goarm=${3:-}
  local label=$goarch
  if [ "$goarch" = "arm" ]; then
    label=armv7
  fi

  local out="$OUT_DIR/${APP_NAME}_${VERSION}_${goos}_${label}"
  if [ "$goos" = "windows" ]; then
    out="${out}.exe"
  fi

  echo "Building $APP_NAME v$VERSION for $goos/$goarch${goarm:+ (GOARM=$goarm)}..."
  env GOOS=$goos GOARCH=$goarch GOARM=$goarm CGO_ENABLED=0 \
    go build -ldflags "$LDFLAGS" -o "$out" main.go
  echo "Wrote $out"
}

build windows amd64
build darwin  arm64
build linux   amd64
build linux   arm 7
build linux   arm64

echo "All binaries written to $OUT_DIR/"
