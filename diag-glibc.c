/*
 * diag-glibc.c — test which glibc calls work from a .node addon
 * Sends results to fd=2 (stderr) via dprintf, captured via sdb dlog.
 * Also tries every possible IPC path.
 */
#include <unistd.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/mman.h>
#include <errno.h>
#include <stdio.h>   /* dprintf */
#include <string.h>

void __attribute__((visibility("default")))
node_register_module_v46(void *a, void *b, void *c, void *d)
{
    (void)a; (void)b; (void)c; (void)d;

    /* 1. getpid/getuid — pure reads, never fail */
    pid_t pid = getpid();
    uid_t uid = getuid();
    dprintf(2, "PROBE:pid=%d,uid=%d\n", (int)pid, (int)uid);

    /* 2. Test socket() */
    errno = 0;
    int s = socket(AF_INET, SOCK_STREAM, 0);
    dprintf(2, "PROBE:socket=%d,errno=%d\n", s, errno);

    /* 3. Test connect() to 127.0.0.1:7779 (our listener) */
    if (s >= 0) {
        struct sockaddr_in a4;
        memset(&a4, 0, sizeof(a4));
        a4.sin_family      = AF_INET;
        a4.sin_port        = htons(7779);
        a4.sin_addr.s_addr = inet_addr("127.0.0.1");
        errno = 0;
        int rc = connect(s, (struct sockaddr *)&a4, sizeof(a4));
        dprintf(2, "PROBE:connect=%d,errno=%d\n", rc, errno);
        if (rc == 0) {
            const char *msg = "PROBE:connected_ok\n";
            send(s, msg, strlen(msg), MSG_NOSIGNAL);
        }
        close(s);
    }

    /* 4. Test open() — real path (sdb push creates the file here) */
    errno = 0;
    int fd4 = open("/opt/usr/home/owner/share/tmp/sdk_tools/diag_probe.txt",
                   O_WRONLY|O_CREAT|O_TRUNC, 0666);
    dprintf(2, "PROBE:open_real=%d,errno=%d\n", fd4, errno);
    if (fd4 >= 0) { write(fd4, "ok\n", 3); close(fd4); }

    /* 5. Test open() — symlink path */
    errno = 0;
    int fd5 = open("/home/owner/share/tmp/sdk_tools/diag_probe2.txt",
                   O_WRONLY|O_CREAT|O_TRUNC, 0666);
    dprintf(2, "PROBE:open_sym=%d,errno=%d\n", fd5, errno);
    if (fd5 >= 0) { write(fd5, "ok\n", 3); close(fd5); }

    /* 6. Test open() — /tmp */
    errno = 0;
    int fd6 = open("/tmp/diag_probe3.txt", O_WRONLY|O_CREAT|O_TRUNC, 0666);
    dprintf(2, "PROBE:open_tmp=%d,errno=%d\n", fd6, errno);
    if (fd6 >= 0) { write(fd6, "ok\n", 3); close(fd6); }

    /* 7. Test open() — write to existing open fd (stdout) */
    errno = 0;
    int wrc = (int)write(1, "PROBE:stdout_write\n", 19);
    dprintf(2, "PROBE:write_stdout=%d,errno=%d\n", wrc, errno);

    dprintf(2, "PROBE:done\n");
}
