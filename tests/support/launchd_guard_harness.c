/* Synthetic-files-only harness. No root identity, native commands or processes.
 * Every job/process/clock primitive is replaced before including the real guard.
 * The only filesystem path constructed by the guard is redirected into pytest.
 */
#define _POSIX_C_SOURCE 200809L
#define _DARWIN_C_SOURCE 1
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

static const char *test_directory;
static const char *test_fault;
static int command_number, waits, polls, clocks, lease_fd = -1, close_failed;

static int is_fault(const char *value) { return !strcmp(test_fault, value); }
static uid_t fake_geteuid(void) { return 0; }
static int fake_snprintf(char *destination, size_t size, const char *format, ...) {
    if (!strcmp(format, "/private/var/tmp/eforge-launchd-reference-%s"))
        return snprintf(destination, size, "%s", test_directory);
    va_list args;
    va_start(args, format);
    int result = vsnprintf(destination, size, format, args);
    va_end(args);
    return result;
}
static int fake_mkdir(const char *path, mode_t mode) {
    if (strcmp(path, test_directory)) _exit(99);
    if (is_fault("directory_create")) { errno = EACCES; return -1; }
    return mkdir(path, mode);
}
static int fake_open(const char *path, int flags, ...) {
    if (!strcmp(path, test_directory) && is_fault("directory_open")) {
        errno = EACCES; return -1;
    }
    if (strcmp(path, test_directory) && strcmp(path, "/dev/null")) _exit(99);
    return open(path, flags);
}
static int fake_openat(int dir, const char *path, int flags, ...) {
    if (strcmp(path, "job.plist")) _exit(99);
    if (is_fault("lease_create")) { errno = EACCES; return -1; }
    if (flags & O_CREAT) {
        va_list args;
        va_start(args, flags);
        mode_t mode = (mode_t)va_arg(args, int);
        va_end(args);
        lease_fd = openat(dir, path, flags, mode);
    } else lease_fd = openat(dir, path, flags);
    return lease_fd;
}
static int fake_fstat(int fd, struct stat *info) {
    int result = fstat(fd, info);
    if (!result) {
        info->st_uid = 0;
        if (S_ISDIR(info->st_mode) && is_fault("directory_stat")) { errno = EIO; return -1; }
        if (S_ISDIR(info->st_mode) && is_fault("directory_metadata")) info->st_uid = 1;
    }
    return result;
}
static ssize_t fake_write(int fd, const void *bytes, size_t count) {
    if (fd == lease_fd && is_fault("lease_write")) { errno = ENOSPC; return -1; }
    if (fd == lease_fd && is_fault("short_write")) return write(fd, bytes, count - 1);
    return write(fd, bytes, count);
}
static int fake_close(int fd) {
    int result = close(fd);
    if (fd == lease_fd && is_fault("lease_close") && !close_failed) {
        close_failed = 1; errno = EIO; return -1;
    }
    return result;
}
static int fake_unlinkat(int dir, const char *path, int flags) {
    if (strcmp(path, "job.plist")) _exit(99);
    if (is_fault("file_removal")) { errno = EACCES; return -1; }
    return unlinkat(dir, path, flags);
}
static pid_t fake_fork(void) {
    ++command_number;
    waits = 0;
    if (command_number == 1 && is_fault("spawn")) { errno = EAGAIN; return -1; }
    return 12345; /* Never create or act on an actual process. */
}
static pid_t fake_waitpid(pid_t child, int *status, int options) {
    (void)options;
    ++waits;
    if (command_number == 1 && is_fault("timeout") && waits == 1) return 0;
    *status = 0;
    if ((command_number == 1 && is_fault("registration")) ||
        (command_number == 2 && is_fault("activation")) ||
        (command_number == 3 && is_fault("removal"))) *status = 5 << 8;
    if (command_number == 1 && is_fault("signal")) *status = 9;
    return child;
}
static int fake_setpgid(pid_t pid, pid_t group) { (void)pid; (void)group; return 0; }
static int fake_kill(pid_t pid, int signum) { (void)pid; (void)signum; return 0; }
static int fake_clock_gettime(clockid_t clock, struct timespec *value) {
    (void)clock;
    ++clocks;
    if (clocks == 1 && is_fault("clock")) return -1;
    value->tv_sec = clocks * 10;
    value->tv_nsec = 0;
    return 0;
}
static int fake_poll(struct pollfd *fds, nfds_t count, int timeout) {
    (void)count; (void)timeout;
    if (polls++ == 0 && is_fault("cancel")) { fds[0].revents = POLLHUP; return 1; }
    return 0;
}
static int fake_nanosleep(const struct timespec *request, struct timespec *remain) {
    (void)request; (void)remain; return 0;
}
static int fake_execve(const char *path, char *const argv[], char *const env[]) {
    (void)path; (void)argv; (void)env;
    (void)fprintf(stderr, "NATIVE_COMMAND_ATTEMPTED\n");
    errno = EACCES; return -1;
}

#define geteuid fake_geteuid
#undef snprintf
#define snprintf fake_snprintf
#define mkdir fake_mkdir
#define open fake_open
#define openat fake_openat
#define fstat fake_fstat
#define write fake_write
#define close fake_close
#define unlinkat fake_unlinkat
#define fork fake_fork
#define waitpid fake_waitpid
#define setpgid fake_setpgid
#define kill fake_kill
#define clock_gettime fake_clock_gettime
#define poll fake_poll
#define nanosleep fake_nanosleep
#define execve fake_execve
#define main original_guard_main
#include EFORGE_GUARD_SOURCE
#undef main

int main(int argc, char **argv) {
    if (argc != 5) return 99;
    test_directory = argv[1];
    test_fault = argv[2];
    char *guard_args[] = {argv[0], argv[3], argv[4], NULL};
    return original_guard_main(3, guard_args);
}
