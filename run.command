#!/bin/zsh
set -e
cd "$(dirname "$0")"
if [[ ! -x ./proxy-yaml-web ]]; then
  echo "正在构建 Go 网页工具…"
  go build -trimpath -o proxy-yaml-web .
fi
exec ./proxy-yaml-web -template ./template.yaml
