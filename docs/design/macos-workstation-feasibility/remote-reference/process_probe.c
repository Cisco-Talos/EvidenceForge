/* Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
 * SPDX-License-Identifier: MIT
 * Own-process identity and bounded fork/exit readiness on the second host only.
 * All stdout is private control evidence consumed by the remote runner.
 */
#include <inttypes.h>
#include <libproc.h>
#include <mach/mach.h>
#include <mach/task_info.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

#ifndef EFORGE_PROCESS_PROBE_LIMIT
#define EFORGE_PROCESS_PROBE_LIMIT 100
#endif

int main(int argc, char **argv) {
    if (argc != 1 || argv[0][0] != '/' || getuid() == 0 || getuid() != geteuid()) return 2;
    alarm(EFORGE_PROCESS_PROBE_LIMIT);
    audit_token_t token;
    mach_msg_type_number_t count = TASK_AUDIT_TOKEN_COUNT;
    struct proc_bsdinfo bsd;
    struct stat image, root;
    if (stat(".", &root) || root.st_uid != getuid() || (root.st_mode & 0777) != 0700 ||
        stat(argv[0], &image) ||
        task_info(mach_task_self(), TASK_AUDIT_TOKEN, (task_info_t)&token, &count) != KERN_SUCCESS ||
        count != TASK_AUDIT_TOKEN_COUNT ||
        proc_pidinfo(getpid(), PROC_PIDTBSDINFO, 0, &bsd, sizeof(bsd)) != sizeof(bsd)) return 2;
    printf("{\"kind\":\"ready\",\"token\":[");
    for (int index = 0; index < 8; ++index) printf("%s%u", index ? "," : "", token.val[index]);
    printf("],\"start_sec\":%" PRIu64 ",\"start_usec\":%" PRIu64
           ",\"image\":{\"dev\":%d,\"ino\":%" PRIu64 "},"
           "\"root\":{\"dev\":%d,\"ino\":%" PRIu64 "}}\n",
           bsd.pbi_start_tvsec, bsd.pbi_start_tvusec, image.st_dev, (uint64_t)image.st_ino,
           root.st_dev, (uint64_t)root.st_ino);
    fflush(stdout);
    for (;;) {
        char command;
        if (read(STDIN_FILENO, &command, 1) != 1) return 0;
        if (command == 'Q') return 0;
        if (command != 'R') return 2;
        pid_t child = fork();
        if (child < 0) return 2;
        if (child == 0) _exit(0);
        int status;
        if (waitpid(child, &status, 0) != child || status != 0) return 2;
    }
}
