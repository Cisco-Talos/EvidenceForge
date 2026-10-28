/* Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
 * SPDX-License-Identifier: MIT
 * HUMAN ONLY. Agents may compile without executing. No process enumeration,
 * network, personal-file reads or logging calls. --classify accepts only an
 * exact audit token and emits a fixed role, never the resolved native path.
 */
#import <AppKit/AppKit.h>
#include <errno.h>
#include <fcntl.h>
#include <libproc.h>
#include <mach/mach.h>
#include <mach/task_info.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/proc_info.h>
#include <sys/stat.h>
#include <unistd.h>

#define CAPACITY 256
#define MAX_VECTOR 512
#define MAX_TOKEN 8192
extern char **environ;

struct own_fd { int fd, flags, access; uint32_t kind; int tty; };
struct observation {
    audit_token_t token;
    struct proc_bsdinfo bsd;
    struct own_fd fds[CAPACITY];
    int count, complete;
    uint32_t ppid, sid, pgid;
};

static int compare_fd(const void *a, const void *b) {
    const struct proc_fdinfo *x = a, *y = b;
    return (x->proc_fd > y->proc_fd) - (x->proc_fd < y->proc_fd);
}

static int observe(struct observation *out) {
    memset(out, 0, sizeof(*out));
    pid_t sid = getsid(0), pgid = getpgrp();
    if (sid <= 0 || pgid <= 0) return -1;
    out->ppid = (uint32_t)getppid(); out->sid = (uint32_t)sid; out->pgid = (uint32_t)pgid;
    mach_msg_type_number_t words = TASK_AUDIT_TOKEN_COUNT;
    if (task_info(mach_task_self(), TASK_AUDIT_TOKEN, (task_info_t)&out->token, &words)
            != KERN_SUCCESS || words != TASK_AUDIT_TOKEN_COUNT ||
        proc_pidinfo(getpid(), PROC_PIDTBSDINFO, 0, &out->bsd, sizeof(out->bsd))
            != sizeof(out->bsd)) return -1;
    struct proc_fdinfo before[CAPACITY], after[CAPACITY];
    memset(before, 0, sizeof(before)); memset(after, 0, sizeof(after));
    int size = proc_pidinfo(getpid(), PROC_PIDLISTFDS, 0, before, sizeof(before));
    if (size < 0 || size >= (int)sizeof(before) || size % sizeof(before[0])) return -1;
    out->count = size / (int)sizeof(before[0]);
    qsort(before, (size_t)out->count, sizeof(before[0]), compare_fd);
    for (int i = 0; i < out->count; ++i) {
        int fd = before[i].proc_fd, flags = fcntl(fd, F_GETFD), mode = fcntl(fd, F_GETFL);
        if (flags < 0 || mode < 0) return -1;
        out->fds[i] = (struct own_fd){fd, flags, mode & O_ACCMODE,
                                     before[i].proc_fdtype, !!isatty(fd)};
    }
    int second = proc_pidinfo(getpid(), PROC_PIDLISTFDS, 0, after, sizeof(after));
    if (second != size) return -1;
    qsort(after, (size_t)out->count, sizeof(after[0]), compare_fd);
    out->complete = memcmp(before, after, (size_t)size) == 0;
    return 0;
}

static int private_dir(int fd) {
    struct stat st;
    return fstat(fd, &st) == 0 && S_ISDIR(st.st_mode) && st.st_uid == getuid() &&
           (st.st_mode & 0777) == 0700;
}

/* Resolve only this executable's fixed bundle layout and its owner-only kit. */
static int run_directory(int *finder) {
    char path[PROC_PIDPATHINFO_MAXSIZE];
    if (proc_pidpath(getpid(), path, sizeof(path)) <= 0) return -1;
    const char *suffix = "/GUIProbe.app/Contents/MacOS/Probe";
    size_t length = strlen(path);
    size_t tail = strlen(suffix);
    if (length <= tail || strcmp(path + length - tail, suffix)) return -1;
    path[length - tail] = '\0';
    int root = open(path, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (root < 0 || !private_dir(root)) { if (root >= 0) close(root); return -1; }
    int input = openat(root, "ACTIVE-RUN", O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
    struct stat st;
    char run[40] = {0};
    int valid = input >= 0 && fstat(input, &st) == 0 && S_ISREG(st.st_mode) &&
                st.st_uid == getuid() && st.st_nlink == 1 && (st.st_mode & 0777) == 0600 &&
                st.st_size == 37 && read(input, run, sizeof(run)) == 37;
    if (input >= 0) close(input);
    if (!valid || strncmp(run, "run-", 4) || run[36] != '\n') { close(root); return -1; }
    for (int i = 4; i < 36; ++i) {
        if (!run[i] || !strchr("0123456789abcdef", run[i])) { close(root); return -1; }
    }
    run[36] = '\0';
    int result = openat(root, run, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    close(root);
    if (result < 0 || !private_dir(result)) {
        if (result >= 0) close(result);
        return -1;
    }
    int phase = openat(result, "ACTIVE-CASE", O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
    char value[10] = {0};
    valid = phase >= 0 && fstat(phase, &st) == 0 && S_ISREG(st.st_mode) &&
            st.st_uid == getuid() && st.st_nlink == 1 && (st.st_mode & 0777) == 0600 &&
            (st.st_size == 7 || st.st_size == 8) && read(phase, value, sizeof(value)) == st.st_size;
    if (phase >= 0) close(phase);
    if (!valid || (strcmp(value, "control\n") && strcmp(value, "finder\n"))) {
        close(result); return -1;
    }
    *finder = strcmp(value, "finder\n") == 0;
    return result;
}

static int vector(FILE *out, char *const *values) {
    if (fputc('[', out) == EOF) return -1;
    size_t total = 0;
    for (int i = 0; values[i]; ++i) {
        size_t n = strnlen(values[i], MAX_TOKEN + 1);
        if (i >= MAX_VECTOR || n > MAX_TOKEN || (total += n) > 131072) return -1;
        if (fprintf(out, "%s\"", i ? "," : "") < 0) return -1;
        for (size_t j = 0; j < n; ++j)
            if (fprintf(out, "%02x", (unsigned char)values[i][j]) < 0) return -1;
        if (fputc('"', out) == EOF) return -1;
    }
    return fputc(']', out) == EOF ? -1 : 0;
}

static int save(int run, int finder, const struct observation *v, char **argv) {
    int fd = openat(run, finder ? "finder-self.json" : "control-self.json",
                    O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600);
    if (fd < 0) return -1;
    FILE *out = fdopen(fd, "w");
    if (!out) { close(fd); return -1; }
    int ok = fprintf(out, "{\"phase\":\"MAIN_ENTRY\",\"token\":[") > 0;
    for (int i = 0; i < 8; ++i)
        ok &= fprintf(out, "%s%u", i ? "," : "", v->token.val[i]) > 0;
    ok &= fprintf(out, "],\"ppid\":%u,\"sid\":%u,\"pgid\":%u,"
                  "\"start_seconds\":%llu,\"start_microseconds\":%llu,"
                  "\"inventory_complete\":%s,\"fds\":[",
                  v->ppid, v->sid, v->pgid,
                  (unsigned long long)v->bsd.pbi_start_tvsec,
                  (unsigned long long)v->bsd.pbi_start_tvusec,
                  v->complete ? "true" : "false") > 0;
    for (int i = 0; i < v->count; ++i) {
        const struct own_fd *f = &v->fds[i];
        ok &= fprintf(out, "%s{\"fd\":%d,\"kind\":%u,\"flags\":%d,"
                      "\"access\":%d,\"tty\":%s}", i ? "," : "", f->fd, f->kind,
                      f->flags, f->access, f->tty ? "true" : "false") > 0;
    }
    ok &= fprintf(out, "],\"arguments_hex\":") > 0;
    ok &= vector(out, argv) == 0;
    ok &= fprintf(out, ",\"environment_hex\":") > 0;
    ok &= vector(out, environ) == 0;
    ok &= fprintf(out, "}\n") > 0;
    if (fclose(out) != 0) ok = 0;
    return ok ? 0 : -1;
}

static int classify(void) {
    audit_token_t token;
    size_t received = 0;
    while (received < sizeof(token)) {
        ssize_t n = read(STDIN_FILENO, (char *)&token + received, sizeof(token) - received);
        if (n < 0 && errno == EINTR) continue;
        if (n <= 0) return 2;
        received += (size_t)n;
    }
    char path[PROC_PIDPATHINFO_MAXSIZE] = {0};
    const char *role = "UNAVAILABLE";
    if (proc_pidpath_audittoken(&token, path, sizeof(path)) > 0) {
        role = "OTHER";
        if (!strcmp(path, "/sbin/launchd")) role = "LAUNCHD";
        else if (!strcmp(path, "/System/Library/CoreServices/Finder.app/Contents/MacOS/Finder")) role = "FINDER";
        else if (!strcmp(path, "/System/Library/CoreServices/Dock.app/Contents/MacOS/Dock")) role = "DOCK";
        else if (!strcmp(path, "/System/Library/CoreServices/Spotlight.app/Contents/MacOS/Spotlight")) role = "SPOTLIGHT";
        else if (!strcmp(path, "/System/Applications/Utilities/Terminal.app/Contents/MacOS/Terminal")) role = "TERMINAL";
    }
    return printf("%s\n", role) > 0 ? 0 : 2;
}

int main(int argc, char **argv) {
    sigset_t mask; sigemptyset(&mask); sigaddset(&mask, SIGALRM);
    if (sigprocmask(SIG_UNBLOCK, &mask, NULL)) return 2;
    signal(SIGALRM, SIG_DFL); alarm(8);
    if (getuid() == 0 || getuid() != geteuid()) return 2;
    if (argc == 2 && strcmp(argv[1], "--ready") == 0) return 0;
    if (argc == 2 && strcmp(argv[1], "--classify") == 0) return classify();
    struct observation own;
    if (observe(&own) != 0) return 2;
    int finder = 0, run = run_directory(&finder);
    if (run < 0 || save(run, finder, &own, argv) != 0) { if (run >= 0) close(run); return 2; }
    @autoreleasepool {
        @try {
            [NSApplication sharedApplication];
            [NSApp setActivationPolicy:NSApplicationActivationPolicyRegular];
            NSWindow *window = [[NSWindow alloc]
                initWithContentRect:NSMakeRect(0, 0, 420, 110)
                styleMask:NSWindowStyleMaskTitled backing:NSBackingStoreBuffered defer:NO];
            window.title = @"EvidenceForge GUI launch reference";
            NSTextField *label = [NSTextField labelWithString:
                @"Controlled test app. This window closes automatically."];
            label.frame = NSMakeRect(20, 35, 390, 35);
            [window.contentView addSubview:label]; [window center]; [window makeKeyAndOrderFront:nil];
            [NSApp activateIgnoringOtherApps:YES];
            dispatch_after(dispatch_time(DISPATCH_TIME_NOW, 2 * NSEC_PER_SEC), dispatch_get_main_queue(), ^{
                [NSApp stop:nil];
                [NSApp postEvent:[NSEvent otherEventWithType:NSEventTypeApplicationDefined
                    location:NSZeroPoint modifierFlags:0 timestamp:0 windowNumber:0
                    context:nil subtype:0 data1:0 data2:0] atStart:YES];
            });
            [NSApp run];
            [window orderOut:nil];
        } @catch (NSException *unused) { (void)unused; close(run); return 3; }
    }
    int done = openat(run, finder ? "finder-complete" : "control-complete",
                      O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600);
    int ok = done >= 0 && write(done, "RETURN_ZERO\n", 12) == 12;
    if (done >= 0) close(done);
    close(run);
    return ok ? 0 : 3;
}
