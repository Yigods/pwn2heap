#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <stddef.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <linux/audit.h>
#include <linux/filter.h>
#include <linux/seccomp.h>

#define LENS_MAGIC 0x706d616c6b726164ULL /* "darklamp" little-ish */
#define SEAL_MAGIC 0x0ddba11c0ffee123ULL
#define DREAM_MAGIC 0x647265616d6f7277ULL /* "dreamorw" */

struct lens {
    uint64_t magic;
    uint64_t seal;
    unsigned char *focus;
    size_t cursor;
    size_t budget;
    uint64_t mood;
};

static struct lens *g_lens;
static unsigned char *g_ash;
static size_t g_ash_cursor;
static void *g_moon[4];
static unsigned int g_phase;
static int lens_ok(void);

static int is_stackish(const void *p, size_t n) {
    uintptr_t a = (uintptr_t)p;
    uintptr_t b = a + n;
    uintptr_t sp = (uintptr_t)&sp;
    uintptr_t lo = sp > 0x200000 ? sp - 0x200000 : 0;
    uintptr_t hi = sp + 0x200000;
    return a < hi && b > lo;
}

static int write_allowed(const void *p, size_t n) {
    if (!p) return 0;
    if (is_stackish(p, n)) {
        puts("the lamp refuses the shadow on your hands");
        return 0;
    }
    return 1;
}

static void dream(void) {
    if (!lens_ok()) return;
    if (g_lens->mood != DREAM_MAGIC) return;
    if (!g_lens->focus || !g_lens->budget) return;
    void (*fn)(void *) = (void (*)(void *))g_lens->focus;
    fn((void *)g_lens->budget);
}

static void read_exact_ish(void *dst, size_t n) {
    size_t off = 0;
    while (off < n) {
        ssize_t r = read(STDIN_FILENO, (char *)dst + off, n - off);
        if (r <= 0) _exit(0);
        off += (size_t)r;
    }
}

static unsigned long read_ulong(void) {
    char tmp[0x40];
    memset(tmp, 0, sizeof(tmp));
    if (!fgets(tmp, sizeof(tmp), stdin)) _exit(0);
    return strtoull(tmp, NULL, 0);
}

static void install_seccomp(void) {
#define ALLOW_NR(nr) \
    BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, (nr), 0, 1), \
    BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW)
    struct sock_filter filter[] = {
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS, (uint32_t)offsetof(struct seccomp_data, arch)),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, AUDIT_ARCH_X86_64, 1, 0),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS),
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS, (uint32_t)offsetof(struct seccomp_data, nr)),
        ALLOW_NR(__NR_read),
        ALLOW_NR(__NR_write),
        ALLOW_NR(__NR_openat),
        ALLOW_NR(__NR_close),
        ALLOW_NR(__NR_brk),
        ALLOW_NR(__NR_mmap),
        ALLOW_NR(__NR_munmap),
        ALLOW_NR(__NR_mprotect),
        ALLOW_NR(__NR_futex),
        ALLOW_NR(__NR_exit),
        ALLOW_NR(__NR_exit_group),
        ALLOW_NR(__NR_rt_sigreturn),
        ALLOW_NR(__NR_rt_sigprocmask),
        ALLOW_NR(__NR_getrandom),
#ifdef __NR_newfstatat
        ALLOW_NR(__NR_newfstatat),
#endif
#ifdef __NR_lseek
        ALLOW_NR(__NR_lseek),
#endif
#ifdef __NR_madvise
        ALLOW_NR(__NR_madvise),
#endif
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS),
    };
#undef ALLOW_NR
    struct sock_fprog prog = {
        .len = (unsigned short)(sizeof(filter) / sizeof(filter[0])),
        .filter = filter,
    };
    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0) _exit(1);
    if (prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &prog) != 0) _exit(1);
}

static void setup(void) {
    setvbuf(stdin, NULL, _IONBF, 0);
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stderr, NULL, _IONBF, 0);

    /* A dead ember: looking before the lens exists reveals tcache residue. */
    g_ash = malloc(0x28);
    if (!g_ash) _exit(1);
    memset(g_ash, 'a', 0x28);
    free(g_ash);

    install_seccomp();
}

static int lens_ok(void) {
    return g_lens && g_lens->magic == LENS_MAGIC && g_lens->seal == SEAL_MAGIC;
}

static void menu(void) {
    puts("\n== darklamp ==");
    puts("1. light");
    puts("2. look");
    puts("3. aim");
    puts("4. whisper");
    puts("5. pray");
    puts("6. sleep");
    printf("> ");
}

static void light(void) {
    printf("oil: ");
    unsigned long sz = read_ulong();
    if (sz < 0x20 || sz > 0x500) {
        puts("the lamp refuses");
        return;
    }

    unsigned char *p = malloc(sz);
    if (!p) _exit(1);

    if (!g_lens) {
        g_lens = malloc(sizeof(*g_lens));
        if (!g_lens) _exit(1);
        g_lens->magic = 0x1111111111111111ULL;
        g_lens->seal = 0x2222222222222222ULL;
        g_lens->focus = g_ash;
        g_lens->cursor = 0;
        g_lens->budget = 0x20;
        g_lens->mood = 0;
    }

    printf("flame: ");
    unsigned long n = read_ulong();
    if (n > 0x800) {
        puts("too bright");
        _exit(0);
    }
    printf("spark: ");
    read_exact_ish(p, n); /* the lamp burns past its glass */
    puts("lit");
}

static void look(void) {
    unsigned char b;
    if (!g_lens) {
        b = g_ash[g_ash_cursor++ & 7];
    } else {
        if (!lens_ok()) {
            puts("the glass is cracked");
            return;
        }
        b = g_lens->focus[g_lens->cursor++];
    }

    static const char *names[] = {
        "black", "red", "green", "yellow", "blue", "purple", "cyan", "white"
    };
    printf("the flame is %-6s : %02x\n", names[b & 7], b);
}

static void aim(void) {
    if (!lens_ok()) {
        puts("no focus");
        return;
    }
    printf("star: ");
    unsigned long x = read_ulong();
    /* The forged glass can focus only on canonical userland stars. */
    if (x < 0x10000 || x >= 0x0000800000000000ULL) {
        puts("too far");
        return;
    }
    g_lens->focus = (unsigned char *)x;
    g_lens->cursor = 0;
    puts("aligned");
}

static void whisper(void) {
    if (!lens_ok()) {
        puts("only smoke answers");
        return;
    }
    printf("words: ");
    unsigned long n = read_ulong();
    if (n > 0x800) {
        puts("the lamp goes out");
        _exit(0);
    }
    if (!write_allowed(g_lens->focus + g_lens->cursor, n)) return;
    printf("murmur: ");
    read_exact_ish(g_lens->focus + g_lens->cursor, n);
    g_lens->cursor += n;
    puts("heard");
}

static void pray(void) {
    switch (g_phase++ % 5) {
    case 0:
        g_moon[0] = malloc(0x500);
        memset(g_moon[0], 'M', 0x500);
        puts("a new moon rises");
        break;
    case 1:
        g_moon[1] = malloc(0x30);
        memset(g_moon[1], 'G', 0x30);
        puts("a small star guards it");
        break;
    case 2:
        free(g_moon[0]);
        if (lens_ok()) {
            g_lens->focus = (unsigned char *)g_moon[0];
            g_lens->cursor = 0;
        }
        puts("smoke curls where the moon was");
        break;
    case 3:
        g_moon[2] = malloc(0x90);
        memset(g_moon[2], 'T', 0x90);
        puts("the wick twitches");
        break;
    default:
        g_moon[3] = malloc(0x420);
        memset(g_moon[3], 'R', 0x420);
        puts("the room grows quiet");
        break;
    }
}

int main(void) {
    setup();
    puts("The darker the lamp, the brighter the bug.");

    for (;;) {
        menu();
        unsigned long c = read_ulong();
        switch (c) {
        case 1: light(); break;
        case 2: look(); break;
        case 3: aim(); break;
        case 4: whisper(); break;
        case 5: pray(); break;
        case 6: puts("good night"); dream(); return 0;
        default: puts("?"); break;
        }
    }
}
