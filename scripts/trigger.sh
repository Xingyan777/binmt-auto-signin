#!/data/data/com.termux/files/usr/bin/bash
# 外部触发：绕过 GitHub schedule 的不可靠性
# 用法: ./trigger.sh   （由 Termux cron / 定时任务调用）
# 需要 gh CLI 已登录且具备 workflow 权限

set -u
REPO="Xingyan777/binmt-auto-signin"
WF="BBS Auto Sign-In"
LOG="$HOME/binmt-trigger.log"

# 先查今天是否已有成功的 run，有了就跳过，省额度
TODAY=$(date -u +%Y-%m-%d)
COUNT=$(gh run list -R "$REPO" --limit 30 --json conclusion,createdAt,event \
  --jq "[.[] | select(.createdAt[0:10]==\"$TODAY\" and .conclusion==\"success\")] | length" 2>/dev/null || echo 0)

if [ "${COUNT:-0}" -ge 1 ]; then
  echo "$(date '+%F %T') 今日已有 ${COUNT} 次成功 run，跳过" >> "$LOG"
  exit 0
fi

gh workflow run "$WF" -R "$REPO" >> "$LOG" 2>&1
echo "$(date '+%F %T') 已触发（当日成功数=$COUNT）" >> "$LOG"
