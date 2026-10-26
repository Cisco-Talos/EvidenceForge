/* Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
 * SPDX-License-Identifier: MIT
 * HUMAN ONLY. Agents may syntax-check this independently authored source, never run it.
 */
#include <errno.h>
#include <fcntl.h>
#include <libproc.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/proc_info.h>
#include <sys/stat.h>
#include <unistd.h>

#define CAPACITY 256

static int compare_fd(const void *a, const void *b) {
    const struct proc_fdinfo *left = a, *right = b;
    return (left->proc_fd > right->proc_fd) - (left->proc_fd < right->proc_fd);
}

static const char *kind(uint32_t type) {
    switch (type) {
        case PROX_FDTYPE_VNODE: return "VNODE";
        case PROX_FDTYPE_PIPE: return "PIPE";
        case PROX_FDTYPE_SOCKET: return "SOCKET";
        default: return "OTHER";
    }
}

static const char *access_mode(int fd) {
    int flags = fcntl(fd, F_GETFL);
    if (flags < 0) return "INCONCLUSIVE";
    switch (flags & O_ACCMODE) {
        case O_RDONLY: return "READ";
        case O_WRONLY: return "WRITE";
        case O_RDWR: return "READ_WRITE";
        default: return "INCONCLUSIVE";
    }
}

/* Compare opaque pipe objects only in memory. Never print or retain handles/stat values. */
static const char *relation(int left, int right, uint32_t type, const struct stat *stats) {
    if (type == PROX_FDTYPE_PIPE) {
        struct pipe_fdinfo a, b;
        memset(&a, 0, sizeof(a));
        memset(&b, 0, sizeof(b));
        if (proc_pidfdinfo(getpid(), left, PROC_PIDFDPIPEINFO, &a, sizeof(a)) != sizeof(a) ||
            proc_pidfdinfo(getpid(), right, PROC_PIDFDPIPEINFO, &b, sizeof(b)) != sizeof(b) ||
            !a.pipeinfo.pipe_handle || !b.pipeinfo.pipe_handle) return "INCONCLUSIVE";
        return a.pipeinfo.pipe_handle == b.pipeinfo.pipe_handle ? "SAME" : "DIFFERENT";
    }
    if (type == PROX_FDTYPE_VNODE) {
        return stats[left].st_dev == stats[right].st_dev &&
               stats[left].st_ino == stats[right].st_ino &&
               stats[left].st_rdev == stats[right].st_rdev ? "SAME" : "DIFFERENT";
    }
    return "INCONCLUSIVE";
}

int main(int argc, char **argv) {
    struct sigaction action;
    sigset_t mask;
    memset(&action, 0, sizeof(action));
    action.sa_handler = SIG_DFL;
    sigemptyset(&action.sa_mask);
    sigemptyset(&mask);
    sigaddset(&mask, SIGALRM);
    if (sigaction(SIGALRM, &action, NULL) != 0 ||
        sigprocmask(SIG_UNBLOCK, &mask, NULL) != 0) return 2;
    alarm(8);
    if (argc != 2 || getuid() == 0 || getuid() != geteuid()) return 2;
    char *end = NULL;
    long output = strtol(argv[1], &end, 10);
    if (!*argv[1] || *end || output < 3 || output > 1024) return 2;
    struct stat destination;
    if (fstat((int)output, &destination) != 0 || !S_ISREG(destination.st_mode) ||
        destination.st_uid != getuid() || destination.st_nlink != 1 ||
        (destination.st_mode & 0777) != 0600 || destination.st_size != 0) return 2;

    struct proc_fdinfo before[CAPACITY], after[CAPACITY];
    memset(before, 0, sizeof(before));
    memset(after, 0, sizeof(after));
    int amount = proc_pidinfo(getpid(), PROC_PIDLISTFDS, 0, before, sizeof(before));
    if (amount <= 0 || amount >= (int)sizeof(before) || amount % sizeof(before[0])) return 2;
    int count = amount / (int)sizeof(before[0]);
    qsort(before, (size_t)count, sizeof(before[0]), compare_fd);
    int found[3] = {0, 0, 0}, instrument = 0, additional = 0, clear = 1, agrees = 1;
    uint32_t types[3] = {0, 0, 0};
    struct stat stats[3];
    memset(stats, 0, sizeof(stats));
    for (int index = 0; index < count; index++) {
        int fd = before[index].proc_fd;
        if (fd == output) {
            if (before[index].proc_fdtype != PROX_FDTYPE_VNODE) return 2;
            instrument++;
        } else if (fd >= 0 && fd <= 2) {
            found[fd]++;
            types[fd] = before[index].proc_fdtype;
            if (fstat(fd, &stats[fd]) != 0) return 2;
            int flags = fcntl(fd, F_GETFD);
            if (flags < 0) return 2;
            if (flags & FD_CLOEXEC) clear = 0;
            agrees &= types[fd] == PROX_FDTYPE_PIPE ? S_ISFIFO(stats[fd].st_mode) :
                      types[fd] == PROX_FDTYPE_SOCKET ? S_ISSOCK(stats[fd].st_mode) :
                      types[fd] == PROX_FDTYPE_VNODE ?
                          (S_ISCHR(stats[fd].st_mode) || S_ISREG(stats[fd].st_mode)) : 0;
        } else {
            additional++;
        }
    }
    if (instrument != 1 || found[0] != 1 || found[1] != 1 || found[2] != 1) return 2;
    int second = proc_pidinfo(getpid(), PROC_PIDLISTFDS, 0, after, sizeof(after));
    if (second != amount) return 2;
    qsort(after, (size_t)count, sizeof(after[0]), compare_fd);
    if (memcmp(before, after, (size_t)amount) != 0) return 2;
    int tty_count = !!isatty(0) + !!isatty(1) + !!isatty(2);
    const char *tty = tty_count == 3 ? "ALL" : tty_count == 0 ? "NONE" : "MIXED";
    const char *out_err = types[1] == types[2] ? relation(1, 2, types[1], stats) : "DIFFERENT";
    const char *in_out = types[0] == types[1] ? relation(0, 1, types[0], stats) : "DIFFERENT";
    int written = dprintf((int)output,
        "{\"inventory_complete\":\"PASS\",\"instrument_verified\":\"PASS\","
        "\"only_standard_descriptors\":\"%s\",\"stdio_open\":\"PASS\","
        "\"stat_type_agreement\":\"%s\",\"stdio_close_on_exec_clear\":\"%s\","
        "\"stdin_kind\":\"%s\",\"stdout_kind\":\"%s\",\"stderr_kind\":\"%s\","
        "\"stdin_access\":\"%s\",\"stdout_access\":\"%s\",\"stderr_access\":\"%s\","
        "\"tty_streams\":\"%s\",\"stdout_stderr_object\":\"%s\","
        "\"stdin_stdout_object\":\"%s\"}\n",
        additional == 0 ? "PASS" : "FAIL", agrees ? "PASS" : "FAIL", clear ? "PASS" : "FAIL",
        kind(types[0]), kind(types[1]), kind(types[2]),
        access_mode(0), access_mode(1), access_mode(2), tty, out_err, in_out);
    if (written <= 0 || fsync((int)output) != 0 || close((int)output) != 0) return 2;
    puts("SAMPLE_SAVED_PRIVATELY");
    return 0;
}
