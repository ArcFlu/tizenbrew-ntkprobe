/*
 * mmap-libc.c — /dev/sdp_mem mmap2 probe using glibc (not raw syscalls)
 * Compiled with arm-linux-gnueabihf-gcc -lc so libc wrappers are used.
 * Node.js v4 ABI: exports node_register_module_v46
 */
#include <fcntl.h>
#include <unistd.h>
#include <sys/mman.h>
#include <string.h>
#include <errno.h>

#define BASE "/home/owner/share/tmp/sdk_tools"
#define OUT  BASE "/mmap_libc.txt"
#define OUT2 "/tmp/mmap_libc.txt"

static int gfd = -1;
static void ws(const char *s) {
    if (gfd < 0) return;
    write(gfd, s, strlen(s));
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
    0x20000000UL,  /* sdp1701 DRAM start */
    0x40000000UL,
    0x60000000UL,
};
#define N_TEST 4

void __attribute__((visibility("default")))
node_register_module_v46(void *a, void *b, void *c, void *d)
{
    (void)a; (void)b; (void)c; (void)d;

    gfd = open(OUT, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (gfd < 0) gfd = open(OUT2, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (gfd < 0) return;

    ws("=== mmap-libc probe ===\n");
    ws("pid="); wl((long)getpid()); ws("\n");
    ws("uid="); wl((long)getuid()); ws("\n");

    int mfd = open("/dev/sdp_mem", O_RDWR);
    ws("open_sdp_mem="); wl(mfd);
    if (mfd < 0) { ws(" errno="); wl(errno); }
    ws("\n");

    if (mfd >= 0) {
        int i;
        for (i = 0; i < N_TEST; i++) {
            unsigned long phys = TEST_PHYS[i];
            off_t pgoff = (off_t)(phys >> 12);
            /* mmap2 on ARM32: offset arg is in pages, not bytes.
             * mmap() in glibc uses the mmap2 syscall on ARM32 and divides
             * the offset by PAGE_SIZE internally — so we pass phys directly. */
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

        /* Also try MAP_PRIVATE with offset 0 */
        void *p2 = mmap(NULL, 4096, PROT_READ, MAP_PRIVATE, mfd, 0);
        ws("mmap_private_0: ");
        if (p2 == MAP_FAILED) { ws("FAILED errno="); wl(errno); }
        else { ws("OK addr=0x"); wx((unsigned long)p2); munmap(p2, 4096); }
        ws("\n");

        close(mfd);
    }

    ws("=== DONE ===\n");
    close(gfd);
    gfd = -1;
}
