/* Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
 * SPDX-License-Identifier: MIT
 * HUMAN ONLY. One transient system job, with a fixed Apple executable.
 * No arbitrary paths/programs/plists; only a 32-character lowercase hex nonce.
 * No enable/disable, persistent installation, domain-wide bootout or job queries.
 */
#define _POSIX_C_SOURCE 200809L
#define _DARWIN_C_SOURCE 1
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

static volatile sig_atomic_t stopping;
static void stop(int ignored) { (void)ignored; stopping = 1; }

static double now(void) {
    struct timespec value;
    if (clock_gettime(CLOCK_MONOTONIC, &value)) return -1;
    return (double)value.tv_sec + (double)value.tv_nsec / 1000000000.0;
}

static int cancelled(void) {
    struct pollfd input = {.fd=STDIN_FILENO, .events=POLLIN | POLLHUP};
    int result = poll(&input, 1, 0);
    return stopping || (result < 0 && errno != EINTR) ||
        (result > 0 && input.revents & (POLLIN | POLLHUP | POLLERR | POLLNVAL));
}

static int reap(pid_t child) {
    int status;
    (void)kill(-child, SIGTERM);
    const struct timespec pause = {0, 50000000};
    for (int i = 0; i < 20; ++i) {
        pid_t result = waitpid(child, &status, WNOHANG);
        if (result == child) return 0;
        if (result < 0 && errno != EINTR) return -1;
        (void)nanosleep(&pause, NULL);
    }
    (void)kill(-child, SIGKILL);
    while (waitpid(child, &status, 0) < 0) if (errno != EINTR) return -1;
    return 0;
}

/* Only the four callers below supply argv; each command has a separate deadline. */
static int command(char *const args[], int cleanup) {
    double start = now();
    if (start < 0 || (!cleanup && cancelled())) return -1;
    pid_t child = fork();
    if (child < 0) return -1;
    if (child == 0) {
        if (setpgid(0, 0)) _exit(2);
        int null = open("/dev/null", O_RDWR);
        if (null < 0) _exit(2);
        for (int fd = 0; fd < 3; ++fd) if (dup2(null, fd) < 0) _exit(2);
        if (null > 2) close(null);
        char *const env[] = {"PATH=/usr/bin:/bin", "LANG=C", "LC_ALL=C", NULL};
        execve("/bin/launchctl", args, env);
        _exit(2);
    }
    (void)setpgid(child, child);
    const struct timespec pause = {0, 50000000};
    for (;;) {
        int status;
        pid_t result = waitpid(child, &status, WNOHANG);
        if (result == child) return WIFEXITED(status) && WEXITSTATUS(status) == 0 ? 0 : -1;
        if (result < 0 && errno != EINTR) return -1;
        double current = now();
        if (current < 0 || current - start > 5 || (!cleanup && cancelled())) {
            (void)reap(child);
            return -1;
        }
        (void)nanosleep(&pause, NULL);
    }
}

static void label(const char *value) {
    /* All callers pass literals; no native text is ever printed. */
    puts(value);
    (void)fflush(stdout);
}

/* Read only the exact control directory and lease; never enumerate other files. */
static int inspect(const char *directory, const char *plist, int plen) {
    int dir = open(directory, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (dir < 0) {
        label(errno == ENOENT ? "DIRECTORY_ABSENT" :
            (errno == EACCES || errno == EPERM) ? "DIRECTORY_ACCESS_DENIED" :
            (errno == ELOOP || errno == ENOTDIR) ? "DIRECTORY_UNSAFE_PATH" :
            "DIRECTORY_OPEN_FAIL");
        return 0;
    }
    struct stat info;
    if (fstat(dir, &info)) { close(dir); label("DIRECTORY_STAT_FAIL"); return 0; }
    int owner = info.st_uid == 0;
    int mode = (info.st_mode & 0777) == 0700;
    int kind = S_ISDIR(info.st_mode);
    label("DIRECTORY_PRESENT");
    label(owner ? "DIRECTORY_OWNER_MATCH" : "DIRECTORY_OWNER_MISMATCH");
    label(mode ? "DIRECTORY_MODE_MATCH" : "DIRECTORY_MODE_MISMATCH");
    label(kind ? "DIRECTORY_KIND_MATCH" : "DIRECTORY_KIND_MISMATCH");
    if (!owner || !mode || !kind) { close(dir); return 0; }
    int file = openat(dir, "job.plist", O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC);
    int failure = errno;
    close(dir);
    if (file < 0) {
        label(failure == ENOENT ? "LEASE_ABSENT" :
            (failure == EACCES || failure == EPERM) ? "LEASE_ACCESS_DENIED" :
            (failure == ELOOP || failure == ENOTDIR) ? "LEASE_UNSAFE_PATH" : "LEASE_OPEN_FAIL");
        return 0;
    }
    if (fstat(file, &info)) { close(file); label("LEASE_STAT_FAIL"); return 0; }
    owner = info.st_uid == 0;
    mode = (info.st_mode & 0777) == 0600;
    kind = S_ISREG(info.st_mode);
    int links = info.st_nlink == 1;
    int size = info.st_size == plen;
    label("LEASE_PRESENT");
    label(owner ? "LEASE_OWNER_MATCH" : "LEASE_OWNER_MISMATCH");
    label(mode ? "LEASE_MODE_MATCH" : "LEASE_MODE_MISMATCH");
    label(kind ? "LEASE_KIND_MATCH" : "LEASE_KIND_MISMATCH");
    label(links ? "LEASE_LINKS_MATCH" : "LEASE_LINKS_MISMATCH");
    label(size ? "LEASE_SIZE_MATCH" : "LEASE_SIZE_MISMATCH");
    if (owner && mode && kind && links && size) {
        char bytes[4096];
        ssize_t count = read(file, bytes, sizeof(bytes));
        label(count == plen && !memcmp(bytes, plist, (size_t)plen) ?
            "LEASE_CONTENT_MATCH" : "LEASE_CONTENT_MISMATCH");
    }
    close(file);
    return 0;
}

int main(int argc, char **argv) {
    if (argc != 3 || geteuid() != 0 ||
        (strcmp(argv[1], "run") && strcmp(argv[1], "cleanup") && strcmp(argv[1], "inspect")) ||
        strlen(argv[2]) != 32)
        return 2;
    for (int i = 0; i < 32; ++i)
        if (!((argv[2][i] >= '0' && argv[2][i] <= '9') ||
              (argv[2][i] >= 'a' && argv[2][i] <= 'f'))) return 2;
    struct sigaction action = {0};
    action.sa_handler = stop;
    sigemptyset(&action.sa_mask);
    sigset_t mask;
    sigemptyset(&mask);
    sigaddset(&mask, SIGALRM);
    if (sigprocmask(SIG_UNBLOCK, &mask, NULL) ||
        sigaction(SIGINT, &action, NULL) || sigaction(SIGTERM, &action, NULL) ||
        sigaction(SIGHUP, &action, NULL) ||
        sigaction(SIGALRM, &action, NULL)) return 2;
    /* A closed Python output pipe must not prevent the root cleanup attempt. */
    if (signal(SIGPIPE, SIG_IGN) == SIG_ERR) return 2;
    alarm(22);
    umask(077);
    char directory[160], service[160], plist[4096];
    int dlen = snprintf(directory, sizeof(directory),
        "/private/var/tmp/eforge-launchd-reference-%s", argv[2]);
    int slen = snprintf(service, sizeof(service),
        "system/org.evidenceforge.reference.launchd.%s", argv[2]);
    int plen = snprintf(plist, sizeof(plist),
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"
        "<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" "
        "\"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n"
        "<plist version=\"1.0\"><dict>"
        "<key>Label</key><string>org.evidenceforge.reference.launchd.%s</string>"
        "<key>ProgramArguments</key><array><string>/usr/bin/true</string>"
        "<string>--eforge-launchd-reference</string><string>%s</string></array>"
        "<key>RunAtLoad</key><false/><key>KeepAlive</key><false/>"
        "<key>WorkingDirectory</key><string>/</string>"
        "<key>StandardInPath</key><string>/dev/null</string>"
        "<key>StandardOutPath</key><string>/dev/null</string>"
        "<key>StandardErrorPath</key><string>/dev/null</string>"
        "<key>EnvironmentVariables</key><dict>"
        "<key>PATH</key><string>/usr/bin:/bin</string>"
        "<key>LANG</key><string>C</string><key>LC_ALL</key><string>C</string>"
        "<key>EFORGE_LAUNCHD_REFERENCE_TOKEN</key><string>%s</string>"
        "</dict></dict></plist>\n", argv[2], argv[2], argv[2]);
    if (dlen < 0 || (size_t)dlen >= sizeof(directory) || slen < 0 ||
        (size_t)slen >= sizeof(service) || plen < 0 || (size_t)plen >= sizeof(plist)) return 2;
    if (!strcmp(argv[1], "inspect")) return inspect(directory, plist, plen);
    int recovery = !strcmp(argv[1], "cleanup");
    if (!recovery && mkdir(directory, 0700)) { label("LOCATION_FAIL"); return 2; }
    int dir = open(directory, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    struct stat info;
    if (dir < 0 || fstat(dir, &info) || info.st_uid != 0 ||
        !S_ISDIR(info.st_mode) || (info.st_mode & 0777) != 0700) {
        if (dir >= 0) close(dir);
        label("LOCATION_FAIL"); return 2;
    }
    char path[200];
    int pathlen = snprintf(path, sizeof(path), "%s/job.plist", directory);
    if (pathlen < 0 || (size_t)pathlen >= sizeof(path)) { close(dir); return 2; }
    if (recovery) {
        int file = openat(dir, "job.plist", O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC);
        char bytes[4096];
        ssize_t count = -1;
        if (file >= 0 && !fstat(file, &info) && S_ISREG(info.st_mode) &&
            info.st_uid == 0 && info.st_nlink == 1 && (info.st_mode & 0777) == 0600)
            count = read(file, bytes, sizeof(bytes));
        if (file >= 0) close(file);
        if (count != plen || memcmp(bytes, plist, (size_t)plen)) {
            close(dir); label("LOCATION_FAIL"); return 2;
        }
    } else {
        int file = openat(dir, "job.plist",
            O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600);
        if (file < 0) { close(dir); label("LOCATION_FAIL"); return 2; }
        ssize_t written = write(file, plist, (size_t)plen);
        int closed = close(file);
        if (written != plen || closed) {
            (void)unlinkat(dir, "job.plist", 0); close(dir); (void)rmdir(directory);
            label("LOCATION_FAIL"); return 2;
        }
    }
    int activated = 0;
    if (!recovery) {
        char *const bootstrap[] = {"/bin/launchctl", "bootstrap", "system", path, NULL};
        if (command(bootstrap, 0) == 0) {
            label("REGISTERED");
            char *const kickstart[] = {"/bin/launchctl", "kickstart", service, NULL};
            if (command(kickstart, 0) == 0) { label("ACTIVATED"); activated = 1; }
            else label("ACTIVATION_FAIL");
        } else label("REGISTRATION_FAIL");
        double start = now();
        const struct timespec pause = {0, 100000000};
        while (activated && !cancelled()) {
            double current = now();
            if (start < 0 || current < 0 || current - start >= 4) break;
            (void)nanosleep(&pause, NULL);
        }
    }
    /* Even a bootstrap timeout/lost return gets an exact-label cleanup attempt. */
    char *const bootout[] = {"/bin/launchctl", "bootout", service, NULL};
    int removed = command(bootout, 1) == 0;
    label(removed ? "REMOVED" : "REMOVAL_FAIL");
    int files_removed = 0;
    if (removed) {
        files_removed = unlinkat(dir, "job.plist", 0) == 0;
        close(dir);
        if (rmdir(directory)) files_removed = 0;
        label(files_removed ? "FILES_REMOVED" : "FILES_FAIL");
    } else close(dir);  /* Retain the root-owned exact-content recovery lease. */
    alarm(0);
    return removed && files_removed && (recovery || activated) ? 0 : 2;
}
