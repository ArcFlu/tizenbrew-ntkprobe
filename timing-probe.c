/*
 * timing-probe.c — timing channel diagnostic
 *
 * Encodes glibc function results as sleep duration:
 *   socket() fail: sleep errno * 10ms  (measurable by JS)
 *   socket() ok: sleep 2000ms + connect data
 *   glibc broken: returns instantly (<5ms)
 *
 * JS measures require() wall-clock time and decodes the result.
 */
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <errno.h>
#include <string.h>

void __attribute__((visibility("default")))
node_register_module_v46(void *a, void *b, void *c, void *d)
{
    (void)a; (void)b; (void)c; (void)d;

    /* Step 1: test usleep itself — if glibc is totally broken,
     * this returns instantly. If glibc works, this delays 50ms. */
    usleep(50000); /* 50ms baseline — if JS sees < 20ms, glibc is broken */

    /* Step 2: test getpid() — encode result as 100ms * (pid % 10)
     * If getpid() returns valid PID (> 0), we sleep 100-900ms extra.
     * If broken (returns 0), we sleep 0 extra. */
    int pid = (int)getpid();
    int digit = pid % 10;  /* 0-9 */
    usleep((unsigned int)(digit * 100000)); /* 0-900ms */

    /* Step 3: test socket() */
    errno = 0;
    int s = socket(AF_INET, SOCK_STREAM, 0);
    int sock_errno = errno;

    if (s < 0) {
        /* socket failed: encode errno as 1000ms + errno*10ms
         * errno 1 (EPERM)=1010ms, 13 (EACCES)=1130ms, 111 (ECONNREFUSED)=2110ms */
        usleep(1000000 + (unsigned int)(sock_errno * 10000));
    } else {
        /* socket succeeded: sleep 3000ms, then try connect */
        usleep(3000000); /* 3s = socket OK marker */

        struct sockaddr_in addr;
        memset(&addr, 0, sizeof(addr));
        addr.sin_family = AF_INET;
        addr.sin_port   = htons(7779);
        addr.sin_addr.s_addr = inet_addr("127.0.0.1");

        errno = 0;
        int rc = connect(s, (struct sockaddr *)&addr, sizeof(addr));
        if (rc == 0) {
            const char *msg = "TIMING_PROBE:socket_ok,connect_ok\n";
            send(s, msg, strlen(msg), 0);
        }
        close(s);
    }
}
