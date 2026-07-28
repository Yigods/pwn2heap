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

#define MAX_SLICES 16
#define MIN_SIZE 0x20
#define MAX_SIZE 0x1000

struct slice {
    size_t size;
    char *buf;
};

static struct slice slices[MAX_SLICES];

static int is_stackish(const void *p, size_t n) {
    uintptr_t a = (uintptr_t)p;
    uintptr_t b = a + n;
    uintptr_t sp = (uintptr_t)&sp;
    uintptr_t lo = sp > 0x400000 ? sp - 0x400000 : 0;
    uintptr_t hi = sp + 0x400000;
    return a < hi && b > lo;
}

static int ptr_allowed(const void *p, size_t n) {
    if (!p) return 0;
    if (is_stackish(p, n)) {
        puts("too close to the oven mitts");
        return 0;
    }
    return 1;
}

static long read_long(void) {
    char tmp[0x30];
    memset(tmp, 0, sizeof(tmp));
    if (!fgets(tmp, sizeof(tmp), stdin)) exit(0);
    return strtol(tmp, NULL, 0);
}

static void read_exact_ish(char *dst, size_t n) {
    size_t off = 0;
    while (off < n) {
        ssize_t r = read(STDIN_FILENO, dst + off, n - off);
        if (r <= 0) exit(0);
        off += (size_t)r;
    }
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

static void banner(void) {
    puts("=== Apple Pie Final ===");
    puts("No shell today. Bake the stream, pivot the context, read the flag.");
}

static int get_idx(void) {
    printf("idx: ");
    long idx = read_long();
    if (idx < 0 || idx >= MAX_SLICES) {
        puts("bad idx");
        exit(0);
    }
    return (int)idx;
}

static void add_slice(void) {
    int idx = get_idx();
    printf("size: ");
    long sz = read_long();
    if (sz < MIN_SIZE || sz > MAX_SIZE) {
        puts("bad size");
        return;
    }
    slices[idx].buf = malloc((size_t)sz);
    if (!slices[idx].buf) exit(1);
    slices[idx].size = (size_t)sz;
    puts("baked");
}

static void edit_slice(void) {
    int idx = get_idx();
    if (!slices[idx].buf) { puts("empty"); return; }
    if (!ptr_allowed(slices[idx].buf, slices[idx].size)) return;
    printf("len: ");
    long len = read_long();
    if (len < 0 || (size_t)len > slices[idx].size) {
        puts("too much");
        return;
    }
    printf("data: ");
    read_exact_ish(slices[idx].buf, (size_t)len);
    puts("seasoned");
}

static void show_slice(void) {
    int idx = get_idx();
    if (!slices[idx].buf) { puts("empty"); return; }
    if (!ptr_allowed(slices[idx].buf, slices[idx].size)) return;
    printf("crumbs: ");
    write(STDOUT_FILENO, slices[idx].buf, slices[idx].size);
    puts("");
}

static void resize_slice(void) {
    int idx = get_idx();
    if (!slices[idx].buf) { puts("empty"); return; }
    if (!ptr_allowed(slices[idx].buf, slices[idx].size)) return;
    printf("new size: ");
    long ns = read_long();
    if (ns < MIN_SIZE || ns > MAX_SIZE) { puts("bad size"); return; }
    char *nbuf = realloc(slices[idx].buf, (size_t)ns);
    if (!nbuf) exit(1);
    slices[idx].buf = nbuf;
    slices[idx].size = (size_t)ns;
    puts("rebaked");
}

static void delete_slice(void) {
    int idx = get_idx();
    if (!slices[idx].buf) { puts("empty"); return; }
    if (!ptr_allowed(slices[idx].buf, slices[idx].size)) return;
    free(slices[idx].buf);
    /* BUG: stale pointer and stale size survive after free. */
    puts("trashed");
}

static void menu(void) {
    puts("\n1. add");
    puts("2. edit");
    puts("3. show");
    puts("4. resize");
    puts("5. delete");
    puts("6. quit");
    printf("> ");
}

int main(void) {
    setbuf(stdin, NULL);
    setbuf(stdout, NULL);
    setbuf(stderr, NULL);
    banner();
    install_seccomp();
    for (;;) {
        menu();
        switch (read_long()) {
        case 1: add_slice(); break;
        case 2: edit_slice(); break;
        case 3: show_slice(); break;
        case 4: resize_slice(); break;
        case 5: delete_slice(); break;
        case 6:
            fflush(NULL);
            puts("bye");
            exit(0);
        default:
            puts("?");
            break;
        }
    }
}
