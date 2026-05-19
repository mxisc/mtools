#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")"

echo "========================================="
echo "  PortDesk 发布脚本"
echo "========================================="

# 获取当前版本
CURRENT_TAG=$(git describe --tags --abbrev=0 2>/dev/null || echo "无")
echo "当前最新版本: $CURRENT_TAG"
echo ""

# 输入新版本号
read -p "请输入新版本号 (例如 v1.0.0): " NEW_TAG

if [[ -z "$NEW_TAG" ]]; then
  echo "错误: 版本号不能为空"
  exit 1
fi

if [[ ! "$NEW_TAG" =~ ^v[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
  echo "错误: 版本号格式不正确，应为 vMAJOR.MINOR.PATCH (例如 v1.0.0)"
  exit 1
fi

# 检查本地是否有未提交的更改
if [[ -n "$(git status --porcelain)" ]]; then
  echo ""
  echo "警告: 工作目录有未提交的更改"
  read -p "是否继续打 tag? (y/N): " CONFIRM
  if [[ "$CONFIRM" != "y" && "$CONFIRM" != "Y" ]]; then
    echo "已取消"
    exit 0
  fi
fi

# 检查 tag 是否已存在
if git tag -l | grep -q "^${NEW_TAG}$"; then
  echo "错误: tag '$NEW_TAG' 已存在"
  exit 1
fi

# 创建并推送 tag
echo ""
echo "正在创建 tag: $NEW_TAG"
git tag -a "$NEW_TAG" -m "Release $NEW_TAG"

echo "正在推送 tag 到远程..."
git push origin "$NEW_TAG"

echo ""
echo "========================================="
echo "  Tag $NEW_TAG 已推送至远程仓库"
echo "  GitLab CI 流水线已自动触发"
echo "========================================="
echo ""
echo "查看流水线进度: https://gitlab.com/mxisc/mtools/-/pipelines"
