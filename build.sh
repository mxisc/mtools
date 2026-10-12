#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")"

echo "========================================="
echo "  PortDesk 构建脚本"
echo "========================================="
echo ""
echo "1. 打 tag 触发 CI 流水线（Linux + Windows）"
echo "2. 本地构建 macOS 应用"
echo "3. 本地构建 Linux 应用"
echo "4. 本地构建 Windows 应用"
echo ""

read -p "请选择操作 (1-4): " MODE

case "$MODE" in
  1)
    echo ""
    echo "--- 打 tag 触发 CI 流水线 ---"
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
    echo "请输入本次更新说明（输入空行结束）:"
    NOTES=""
    while IFS= read -r line; do
      [[ -z "$line" ]] && break
      if [[ -n "$NOTES" ]]; then
        NOTES="$NOTES
$line"
      else
        NOTES="$line"
      fi
    done
    if [[ -z "$NOTES" ]]; then
      NOTES="Release $NEW_TAG"
    fi
    git tag -a "$NEW_TAG" -m "$NEW_TAG

$NOTES"
    git push origin "$NEW_TAG"
    echo ""
    echo "========================================="
    echo "  Tag $NEW_TAG 已推送至远程仓库"
    echo "  GitHub Actions 流水线已自动触发"
    echo "========================================="
    echo ""
    echo "查看流水线进度: https://github.com/mxisc/mtools/actions"
    ;;

  2)
    echo ""
    echo "--- 本地构建 macOS 应用 ---"
    export PATH="$PATH:$HOME/go/bin"
    echo "正在构建..."
    wails build -platform darwin/universal
    echo ""
    echo "========================================="
    echo "  构建完成: build/bin/PortDesk.app"
    echo "========================================="
    ;;

  3)
    echo ""
    echo "--- 本地构建 Linux 应用 ---"
    export PATH="$PATH:$HOME/go/bin"
    echo "正在构建..."
    wails build -platform linux/amd64
    echo ""
    echo "========================================="
    echo "  构建完成: build/bin/portdesk"
    echo "========================================="
    ;;

  4)
    echo ""
    echo "--- 本地构建 Windows 应用 ---"
    export PATH="$PATH:$HOME/go/bin"
    echo "正在构建..."
    wails build -platform windows/amd64
    echo ""
    echo "========================================="
    echo "  构建完成: build/bin/portdesk.exe"
    echo "========================================="
    ;;

  *)
    echo "无效选项，已取消"
    exit 1
    ;;
esac
