/* Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
 * SPDX-License-Identifier: MIT
 * Second-host experiment: own identity and fixed files in a fresh private cwd.
 * All stdout is private control evidence consumed by the remote runner.
 */
#include <EndpointSecurity/ESTypes.h>
#include <fcntl.h>
#include <inttypes.h>
#include <libproc.h>
#include <mach/mach.h>
#include <mach/mach_time.h>
#include <mach/task_info.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

_Static_assert(ES_EVENT_TYPE_NOTIFY_CLOSE == 12, "close discriminant");
_Static_assert(ES_EVENT_TYPE_NOTIFY_CREATE == 13, "create discriminant");
_Static_assert(ES_EVENT_TYPE_NOTIFY_RENAME == 25, "rename discriminant");
_Static_assert(ES_EVENT_TYPE_NOTIFY_UNLINK == 32, "unlink discriminant");

static void print_stat(const struct stat *value) {
    printf("{\"dev\":%d,\"ino\":%" PRIu64 ",\"size\":%" PRId64
           ",\"nlink\":%u,\"mode\":%u,\"uid\":%u,\"gid\":%u"
           ",\"mtime_sec\":%" PRId64 ",\"mtime_nsec\":%ld,\"ctime_sec\":%" PRId64 ",\"ctime_nsec\":%ld}",
           value->st_dev, (uint64_t)value->st_ino, (int64_t)value->st_size,
           value->st_nlink, value->st_mode, value->st_uid, value->st_gid,
           (int64_t)value->st_mtimespec.tv_sec, value->st_mtimespec.tv_nsec,
           (int64_t)value->st_ctimespec.tv_sec, value->st_ctimespec.tv_nsec);
}

static void print_parent_stat(const struct stat *value) {
    printf("{\"dev\":%d,\"ino\":%" PRIu64 ",\"size\":%" PRId64
           ",\"mtime_sec\":%" PRId64 ",\"mtime_nsec\":%ld,\"ctime_sec\":%" PRId64 ",\"ctime_nsec\":%ld}",
           value->st_dev, (uint64_t)value->st_ino, (int64_t)value->st_size,
           (int64_t)value->st_mtimespec.tv_sec, value->st_mtimespec.tv_nsec,
           (int64_t)value->st_ctimespec.tv_sec, value->st_ctimespec.tv_nsec);
}

static int write_file(const char *name, int exclusive) {
    int flags = O_WRONLY | O_CREAT | (exclusive ? O_EXCL : O_TRUNC) | O_NOFOLLOW;
    int fd = open(name, flags, 0600);
    if (fd < 0) return -1;
    int result = write(fd, "abc", 3) == 3 && fsync(fd) == 0 ? 0 : -1;
    if (close(fd) != 0) result = -1;
    return result;
}

int main(int argc, char **argv) {
    if (argc != 1 || argv[0][0] != '/' || getuid() == 0 || getuid() != geteuid()) return 2;
    alarm(25);
    struct stat root, image;
    struct proc_bsdinfo bsd;
    audit_token_t token;
    mach_msg_type_number_t count = TASK_AUDIT_TOKEN_COUNT;
    if (stat(".", &root) || root.st_uid != getuid() || (root.st_mode & 0777) != 0700 ||
        stat(argv[0], &image) ||
        task_info(mach_task_self(), TASK_AUDIT_TOKEN, (task_info_t)&token, &count) != KERN_SUCCESS ||
        count != TASK_AUDIT_TOKEN_COUNT ||
        proc_pidinfo(getpid(), PROC_PIDTBSDINFO, 0, &bsd, sizeof(bsd)) != sizeof(bsd)) return 2;
    printf("{\"kind\":\"ready\",\"token\":[");
    for (int index = 0; index < 8; ++index) printf("%s%u", index ? "," : "", token.val[index]);
    printf("],\"start_sec\":%" PRIu64 ",\"start_usec\":%" PRIu64 ",\"image\":",
           bsd.pbi_start_tvsec, bsd.pbi_start_tvusec);
    print_stat(&image);
    printf(",\"root\":"); print_stat(&root); printf("}\n"); fflush(stdout);
    int next_step = 0;
    for (;;) {
        char command;
        if (read(STDIN_FILENO, &command, 1) != 1) return 2;
        if (command == 'R') {
            int result = write_file("ready", 0);
            printf("{\"kind\":\"warmup\",\"ok\":%s}\n", result ? "false" : "true");
            fflush(stdout);
            if (result) return 2;
            continue;
        }
        if (command == 'Q' && next_step == 8) {
            printf("{\"kind\":\"done\"}\n"); fflush(stdout); return 0;
        }
        if (command != '0' + next_step || next_step >= 8) return 2;
        const char *source[] = {"alpha", "alpha", "alpha", "victim", "candidate", "candidate",
                                "fresh", "victim"};
        const char *destination[] = {"alpha", "alpha", "fresh", "victim", "candidate", "victim",
                                     "fresh", "victim"};
        struct stat before, replaced, after, parent_before, parent_after;
        if (stat(".", &parent_before)) return 2;
        int before_ok = lstat(source[next_step], &before) == 0;
        int replaced_ok = lstat(destination[next_step], &replaced) == 0;
        uint64_t begin = mach_absolute_time();
        int result = -1;
        if (next_step == 0 || next_step == 3 || next_step == 4) {
            result = write_file(source[next_step], 1);
        } else if (next_step == 1) {
            int fd = open("alpha", O_RDONLY | O_NOFOLLOW);
            char content[3];
            if (fd >= 0) {
                result = read(fd, content, sizeof(content)) == 3 ? 0 : -1;
                if (close(fd)) result = -1;
            }
        } else if (next_step == 2 || next_step == 5) {
            result = rename(source[next_step], destination[next_step]);
        } else {
            result = unlink(source[next_step]);
        }
        uint64_t end = mach_absolute_time();
        int after_ok = lstat(destination[next_step], &after) == 0;
        if (stat(".", &parent_after)) return 2;
        printf("{\"kind\":\"step\",\"step\":%d,\"ok\":%s,\"begin\":%" PRIu64
               ",\"end\":%" PRIu64 ",\"before\":", next_step, result ? "false" : "true", begin, end);
        if (before_ok) print_stat(&before); else printf("null");
        printf(",\"replaced\":");
        if (replaced_ok) print_stat(&replaced); else printf("null");
        printf(",\"after\":");
        if (after_ok) print_stat(&after); else printf("null");
        printf(",\"parent_before\":"); print_parent_stat(&parent_before);
        printf(",\"parent_after\":"); print_parent_stat(&parent_after);
        printf("}\n"); fflush(stdout);
        if (result) return 2;
        ++next_step;
    }
}
