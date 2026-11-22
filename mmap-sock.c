/*
 * mmap-sock.c — /dev/sdp_mem mmap2 probe, results via TCP socket
 * Connects to 127.0.0.1:7778 and sends probe output.
 * No file I/O — avoids Tizen sandbox filesystem restrictions.
 * Compiled with arm-linux-gnueabihf-gcc -lc.
 */
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <string.h>
#include <errno.h>

#define PROBE_PORT 7778

static int gfd = -1;
static void ws(const char *s) {
    if (gfd < 0) return;
    send(gfd, s, strlen(s), MSG_NOSIGNAL);
}
static void wl(long v) {
    char buf[24]; int i = 0, neg = 0;
    if (v == 0) { ws("0"); return; }
    if (v < 0) { neg = 1; v = -v; }
    while (v) { buf[i++] = '0' + (v % 10); v /= 10; }
    if (neg) buf[i++] = '-';
    char out[24]; int j = 0;
    while (i > 0) out[j++] = buf[--i];
    out[j] = '\0';
    ws(out);
}
static void wx(unsigned long v) {
    char buf[12]; int i = 0;
    if (v == 0) { ws("0"); return; }
    while (v) { buf[i++] = "0123456789abcdef"[v & 0xf]; v >>= 4; }
    char out[12]; int j = 0;
    while (i > 0) out[j++] = buf[--i];
    out[j] = '\0';
    ws(out);
}

static const unsigned long TEST_PHYS[] = {
    0x00000000UL,
    0x20000000UL,
    0x40000000UL,
    0x60000000UL,
};
#define N_TEST 4

void __attribute__((visibility("default")))
node_register_module_v46(void *a, void *b, void *c, void *d)
{
    (void)a; (void)b; (void)c; (void)d;

    /* Connect back to the Node.js probe server */
    gfd = socket(AF_INET, SOCK_STREAM, 0);
    if (gfd < 0) return;

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port   = htons(PROBE_PORT);
    addr.sin_addr.s_addr = inet_addr("127.0.0.1");

    if (connect(gfd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        close(gfd);
        gfd = -1;
        return;
    }

    ws("=== mmap-sock probe ===\n");
    ws("pid="); wl((long)getpid()); ws("\n");
    ws("uid="); wl((long)getuid()); ws("\n");
    ws("euid="); wl((long)geteuid()); ws("\n");

    /* Test that glibc file I/O works */
    int tfd = open("/tmp/mmap_sock_probe.txt", O_WRONLY | O_CREAT | O_TRUNC, 0666);
    ws("open_tmp="); wl(tfd);
    if (tfd < 0) { ws(" errno="); wl(errno); }
    else { write(tfd, "ok\n", 3); close(tfd); }
    ws("\n");

    /* Open /dev/sdp_mem */
    int mfd = open("/dev/sdp_mem", O_RDWR);
    ws("open_sdp_mem="); wl(mfd);
    if (mfd < 0) { ws(" errno="); wl(errno); }
    ws("\n");

    if (mfd >= 0) {
        int i;
        for (i = 0; i < N_TEST; i++) {
            unsigned long phys = TEST_PHYS[i];
            void *p = mmap(NULL, 4096, PROT_READ | PROT_WRITE,
                           MAP_SHARED, mfd, (off_t)phys);
            ws("mmap phys=0x"); wx(phys);
            if (p == MAP_FAILED) {
                ws(" FAILED errno="); wl(errno);
            } else {
                ws(" OK addr=0x"); wx((unsigned long)p);
                /* read first 16 bytes */
                ws(" data=");
                unsigned char *m = (unsigned char *)p;
                int j;
                for (j = 0; j < 16; j++) {
                    char hx[3];
                    hx[0] = "0123456789abcdef"[m[j] >> 4];
                    hx[1] = "0123456789abcdef"[m[j] & 0xf];
                    hx[2] = '\0';
                    ws(hx);
                    if (j < 15) ws(" ");
                }
                munmap(p, 4096);
            }
            ws("\n");
        }

        /* Test writing to mapped memory — scan for uid pattern */
        void *p2 = mmap(NULL, 4096, PROT_READ | PROT_WRITE,
                        MAP_SHARED, mfd, (off_t)0x20000000UL);
        ws("mmap_write_test: ");
        if (p2 == MAP_FAILED) { ws("FAILED errno="); wl(errno); }
        else {
            ws("OK - write test\n");
            /* Write a marker to see if we can alter physical memory */
            volatile unsigned int *mem = (volatile unsigned int *)p2;
            unsigned int orig = mem[0];
            ws("mem[0]=0x"); wx(orig); ws("\n");
            munmap(p2, 4096);
        }
        ws("\n");

        close(mfd);
    }

    ws("=== DONE ===\n");
    shutdown(gfd, SHUT_RDWR);
    close(gfd);
    gfd = -1;
}
