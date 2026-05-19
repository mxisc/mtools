#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")"

echo "========================================="
echo "  PortDesk 发布脚本"
echo "========================================="

CURRENT_TAG=$(git describe --tags --abbrev=0 2>/dev/null || echo "")

if [[ -z "$CURRENT_TAG" ]]; then
  NEW_TAG="v0.1.0"
else
  VERSION="${CURRENT_TAG#v}"
  IFS='.' read -r MAJOR MINOR PATCH <<< "$VERSION"
  PATCH=$((PATCH + 1))
  NEW_TAG="v${MAJOR}.${MINOR}.${PATCH}"
fi

echo "当前版本: ${CURRENT_TAG:-无}"
echo "新版本: $NEW_TAG"
echo ""

if [[ -n "$(git status --porcelain)" ]]; then
  echo "警告: 工作目录有未提交的更改"
  read -p "是否继续打 tag? (y/N): " CONFIRM
  if [[ "$CONFIRM" != "y" && "$CONFIRM" != "Y" ]]; then
    echo "已取消"
    exit 0
  fi
fi

if git tag -l | grep -q "^${NEW_TAG}$"; then
  echo "错误: tag '$NEW_TAG' 已存在"
  exit 1
fi

git tag -a "$NEW_TAG" -m "Release $NEW_TAG"
git push origin "$NEW_TAG"

echo ""
echo "========================================="
echo "  Tag $NEW_TAG 已推送至远程仓库"
echo "  GitLab CI 流水线已自动触发"
echo "========================================="
echo ""
echo "查看流水线进度: https://gitlab.com/mxisc/mtools/-/pipelines"
