/* Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
 * SPDX-License-Identifier: MIT
 * Unit simulation: EVERY OS-facing guard API below is replaced with a stub.
 * This binary never launches a child, calls launchctl, changes signals, reads
 * host identities, or opens/modifies the real filesystem.
 */
#define _POSIX_C_SOURCE 200809L
#define _DARWIN_C_SOURCE 1
#define _DEFAULT_SOURCE 1
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

static int scenario, forks, terms, kills, removed_files, removed_dir, waits, existing;
static int lease_valid = 1;
static double elapsed;
static char content[4096], labels[512];
static size_t extent;
static uid_t fake_geteuid(void) { return scenario == 9 ? 501 : 0; }
static int fake_sigemptyset(sigset_t *set) { (void)set; return 0; }
static int fake_sigaddset(sigset_t *set, int value) { (void)set; (void)value; return 0; }
static int fake_sigprocmask(int how, const sigset_t *set, sigset_t *old) {
    (void)how; (void)set; (void)old; return 0;
}
static int fake_sigaction(int number, const struct sigaction *action, struct sigaction *old) {
    (void)number; (void)action; (void)old; return 0;
}
static void (*fake_signal(int number, void (*handler)(int)))(int) {
    assert(number == SIGPIPE && handler == SIG_IGN); return SIG_DFL;
}
static unsigned fake_alarm(unsigned seconds) { assert(seconds == 0 || seconds == 22); return 0; }
static mode_t fake_umask(mode_t mode) { assert(mode == 077); return 0; }
static int fake_mkdir(const char *path, mode_t mode) {
    const char prefix[] = "/private/var/tmp/eforge-launchd-reference-";
    assert(!strncmp(path, prefix, sizeof(prefix) - 1));
    assert(mode == 0700);
    if (existing || scenario == 6) { errno = EEXIST; return -1; }
    existing = 1; return 0;
}
static int fake_open(const char *path, int flags, ...) {
    assert(flags & O_DIRECTORY); assert(flags & O_NOFOLLOW); assert(flags & O_CLOEXEC);
    assert(strstr(path, "eforge-launchd-reference-")); return existing ? 30 : -1;
}
static int fake_openat(int dir, const char *path, int flags, ...) {
    assert(dir == 30 && !strcmp(path, "job.plist"));
    assert(flags & O_NOFOLLOW); assert(flags & O_CLOEXEC);
    if (flags & O_CREAT) assert(flags & O_EXCL);
    return 31;
}
static int fake_fstat(int fd, struct stat *info) {
    assert(fd == 30 || fd == 31);
    memset(info, 0, sizeof(*info));
    info->st_mode = fd == 30 ? S_IFDIR | 0700 : S_IFREG | (lease_valid ? 0600 : 0644);
    info->st_uid = 0; info->st_nlink = 1; return 0;
}
static ssize_t fake_write(int fd, const void *bytes, size_t count) {
    assert(fd == 31 && count < sizeof(content));
    memcpy(content, bytes, count); extent = count;
    return scenario == 7 ? (ssize_t)count - 1 : (ssize_t)count;
}
static ssize_t fake_read(int fd, void *bytes, size_t count) {
    assert(fd == 31 && count >= extent); memcpy(bytes, content, extent); return (ssize_t)extent;
}
static int fake_close(int fd) { assert(fd == 30 || fd == 31); return 0; }
static int fake_unlinkat(int dir, const char *path, int flags) {
    assert(dir == 30 && !strcmp(path, "job.plist") && flags == 0);
    ++removed_files; return 0;
}
static int fake_rmdir(const char *path) {
    assert(strstr(path, "eforge-launchd-reference-")); ++removed_dir; existing = 0; return 0;
}
static int fake_puts(const char *text) {
    assert(strlen(labels) + strlen(text) + 2 < sizeof(labels));
    strcat(labels, text); strcat(labels, "\n"); return 0;
}
static int fake_fflush(FILE *stream) { assert(stream == stdout); return 0; }
static int fake_clock_gettime(clockid_t id, struct timespec *value) {
    assert(id == CLOCK_MONOTONIC);
    elapsed += scenario == 4 ? 2.0 : 0.1;
    value->tv_sec = (time_t)elapsed;
    value->tv_nsec = (long)((elapsed - (double)value->tv_sec) * 1000000000.0); return 0;
}
static int fake_nanosleep(const struct timespec *value, struct timespec *left) {
    (void)left; elapsed += value->tv_sec + value->tv_nsec / 1000000000.0; return 0;
}
static pid_t fake_fork(void) { ++forks; waits = 0; return 42; }
static pid_t fake_waitpid(pid_t pid, int *status, int flags) {
    assert(pid == 42 && flags == WNOHANG);
    ++waits;
    if ((scenario == 3 || scenario == 4) && forks == 1 && !terms) return 0;
    *status = ((scenario == 1 && forks == 1) || (scenario == 2 && forks == 2) ||
        (scenario == 5 && forks == 3) || (scenario == 8 && forks == 1)) ? 2 << 8 : 0;
    return 42;
}
static int fake_poll(struct pollfd *fds, nfds_t count, int timeout) {
    assert(count == 1 && timeout == 0 && fds[0].fd == STDIN_FILENO);
    fds[0].revents = scenario == 3 && forks == 1 ? POLLHUP : 0;
    return fds[0].revents ? 1 : 0;
}
static int fake_kill(pid_t pid, int number) {
    assert(pid == -42);
    if (number == SIGTERM) ++terms; else { assert(number == SIGKILL); ++kills; }
    return 0;
}
/* The fake fork never enters the child. Stubs make accidental execution fatal. */
static int fake_setpgid(pid_t a, pid_t b) { assert(a == 42 && b == 42); return 0; }
static int fake_dup2(int a, int b) { (void)a; (void)b; abort(); }
static int fake_execve(const char *path, char *const args[], char *const env[]) {
    (void)path; (void)args; (void)env; abort();
}
static void fake_exit(int code) { (void)code; abort(); }

#define geteuid() fake_geteuid()
#undef sigemptyset
#undef sigaddset
#define sigemptyset(...) fake_sigemptyset(__VA_ARGS__)
#define sigaddset(...) fake_sigaddset(__VA_ARGS__)
#define sigprocmask(...) fake_sigprocmask(__VA_ARGS__)
#define sigaction(...) fake_sigaction(__VA_ARGS__)
#define signal(...) fake_signal(__VA_ARGS__)
#define alarm(...) fake_alarm(__VA_ARGS__)
#define umask(...) fake_umask(__VA_ARGS__)
#define mkdir(...) fake_mkdir(__VA_ARGS__)
#define open(...) fake_open(__VA_ARGS__)
#define openat(...) fake_openat(__VA_ARGS__)
#define fstat(...) fake_fstat(__VA_ARGS__)
#define write(...) fake_write(__VA_ARGS__)
#define read(...) fake_read(__VA_ARGS__)
#define close(...) fake_close(__VA_ARGS__)
#define unlinkat(...) fake_unlinkat(__VA_ARGS__)
#define rmdir(...) fake_rmdir(__VA_ARGS__)
#define puts(...) fake_puts(__VA_ARGS__)
#define fflush(...) fake_fflush(__VA_ARGS__)
#define clock_gettime(...) fake_clock_gettime(__VA_ARGS__)
#define nanosleep(...) fake_nanosleep(__VA_ARGS__)
#define fork() fake_fork()
#define waitpid(...) fake_waitpid(__VA_ARGS__)
#define poll(...) fake_poll(__VA_ARGS__)
#define kill(...) fake_kill(__VA_ARGS__)
#define setpgid(...) fake_setpgid(__VA_ARGS__)
#define dup2(...) fake_dup2(__VA_ARGS__)
#define execve(...) fake_execve(__VA_ARGS__)
#define _exit(...) fake_exit(__VA_ARGS__)
#define main guarded_main
#include "../../docs/design/macos-workstation-feasibility/launchd-reference/job_guard.c"
#undef main
#undef puts

static void reset(int selected) {
    scenario = selected; forks = terms = kills = removed_files = removed_dir = waits = 0;
    existing = 0; elapsed = 0; extent = 0; lease_valid = 1; stopping = 0; labels[0] = 0;
}

int main(void) {
    char *args[] = {"guard", "run", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", NULL};
    reset(0);
    assert(guarded_main(3, args) == 0 && forks == 3 && removed_files == 1 && removed_dir == 1);
    assert(!strcmp(labels, "REGISTERED\nACTIVATED\nREMOVED\nFILES_REMOVED\n"));
    for (int selected = 1; selected <= 4; ++selected) {
        reset(selected);
        assert(guarded_main(3, args) == 2);
        assert(strstr(labels, "REMOVED\nFILES_REMOVED\n"));
        assert(removed_files == 1 && removed_dir == 1);
        assert(forks == (selected == 2 ? 3 : 2));
        assert(terms == (selected >= 3 ? 1 : 0));
    }
    reset(5);
    assert(guarded_main(3, args) == 2 && existing && !removed_files && !removed_dir);
    assert(strstr(labels, "REMOVAL_FAIL"));
    /* Recover the exact simulated lease without reactivating the program. */
    scenario = 0; forks = 0; labels[0] = 0; args[1] = "cleanup";
    assert(guarded_main(3, args) == 0 && forks == 1 && !existing);
    assert(!strcmp(labels, "REMOVED\nFILES_REMOVED\n"));
    reset(0); existing = 1; extent = 1; content[0] = 'x';
    assert(guarded_main(3, args) == 2 && !forks && !removed_files && existing);
    reset(0); existing = 1; lease_valid = 0;
    assert(guarded_main(3, args) == 2 && !forks && !removed_files);
    args[1] = "run";
    for (int selected = 6; selected <= 9; ++selected) {
        reset(selected);
        assert(guarded_main(3, args) == 2);
        if (selected != 8) assert(!forks);
    }
    reset(0); args[2] = "../../arbitrary";
    assert(guarded_main(3, args) == 2 && !forks && !existing);
    args[2] = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
    assert(guarded_main(3, args) == 2 && !forks && !existing);
    args[2] = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"; args[1] = "arbitrary";
    assert(guarded_main(3, args) == 2 && !forks && !existing);
    assert(guarded_main(2, args) == 2 && !forks && !existing);
    puts("launchd guard simulations passed");
    return 0;
}
