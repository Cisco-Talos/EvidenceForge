/* Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
 * SPDX-License-Identifier: MIT
 * Independently authored. HUMAN private runs only; agents may syntax-check, never run.
 */
#include <bsm/libbsm.h>
#include <errno.h>
#include <inttypes.h>
#include <mach/mach.h>
#include <mach/task_info.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

struct snapshot {
    uint32_t pid, ppid, sid, pgid;
    uint32_t uid, euid, gid, egid;
    uint32_t auid, asid, token_pid, token_uid, token_euid, token_gid, token_egid;
};

static int observe(struct snapshot *value) {
    audit_token_t token;
    mach_msg_type_number_t count = TASK_AUDIT_TOKEN_COUNT;
    memset(value, 0, sizeof(*value));
    if (task_info(mach_task_self(), TASK_AUDIT_TOKEN, (task_info_t)&token, &count) != KERN_SUCCESS ||
        count != TASK_AUDIT_TOKEN_COUNT) {
        return -1;
    }
    pid_t sid = getsid(0);
    pid_t pgid = getpgrp();
    if (sid <= 0 || pgid <= 0) {
        return -1;
    }
    value->pid = (uint32_t)getpid();
    value->ppid = (uint32_t)getppid();
    value->sid = (uint32_t)sid;
    value->pgid = (uint32_t)pgid;
    value->uid = (uint32_t)getuid();
    value->euid = (uint32_t)geteuid();
    value->gid = (uint32_t)getgid();
    value->egid = (uint32_t)getegid();
    value->auid = (uint32_t)audit_token_to_auid(token);
    value->asid = (uint32_t)audit_token_to_asid(token);
    value->token_pid = (uint32_t)audit_token_to_pid(token);
    value->token_uid = (uint32_t)audit_token_to_ruid(token);
    value->token_euid = (uint32_t)audit_token_to_euid(token);
    value->token_gid = (uint32_t)audit_token_to_rgid(token);
    value->token_egid = (uint32_t)audit_token_to_egid(token);
    return 0;
}

static int transfer(int fd, void *buffer, size_t length, int writing) {
    char *cursor = buffer;
    while (length) {
        ssize_t amount = writing ? write(fd, cursor, length) : read(fd, cursor, length);
        if (amount < 0 && errno == EINTR) {
            continue;
        }
        if (amount <= 0) {
            return -1;
        }
        cursor += amount;
        length -= (size_t)amount;
    }
    return 0;
}

static void print_snapshot(const struct snapshot *v) {
    printf("{\"pid\":%" PRIu32 ",\"ppid\":%" PRIu32 ",\"sid\":%" PRIu32
           ",\"pgid\":%" PRIu32 ",\"uid\":%" PRIu32 ",\"euid\":%" PRIu32
           ",\"gid\":%" PRIu32 ",\"egid\":%" PRIu32 ",\"auid\":%" PRIu32
           ",\"asid\":%" PRIu32 ",\"token_pid\":%" PRIu32 ",\"token_uid\":%" PRIu32
           ",\"token_euid\":%" PRIu32 ",\"token_gid\":%" PRIu32 ",\"token_egid\":%" PRIu32 "}",
           v->pid, v->ppid, v->sid, v->pgid, v->uid, v->euid, v->gid, v->egid,
           v->auid, v->asid, v->token_pid, v->token_uid, v->token_euid,
           v->token_gid, v->token_egid);
}

int main(int argc, char **argv) {
    struct sigaction alarm_action;
    sigset_t alarm_mask;
    memset(&alarm_action, 0, sizeof(alarm_action));
    alarm_action.sa_handler = SIG_DFL;
    sigemptyset(&alarm_action.sa_mask);
    sigemptyset(&alarm_mask);
    sigaddset(&alarm_mask, SIGALRM);
    if (sigaction(SIGALRM, &alarm_action, NULL) != 0 ||
        sigprocmask(SIG_UNBLOCK, &alarm_mask, NULL) != 0) {
        return 2;
    }
    alarm(8);
    if (argc == 3 && strcmp(argv[1], "--leaf") == 0) {
        char *end = NULL;
        long descriptor = strtol(argv[2], &end, 10);
        struct snapshot after;
        if (*argv[2] == '\0' || *end != '\0' || descriptor < 3 || descriptor > 1024 ||
            observe(&after) != 0) {
            return 2;
        }
        return transfer((int)descriptor, &after, sizeof(after), 1) == 0 ? 0 : 2;
    }
    if (argc != 1 || argv[0][0] != '/' || getuid() == 0 || getuid() != geteuid()) {
        return 2;
    }
    struct snapshot root, forked, executed;
    int channel[2];
    if (observe(&root) != 0 || pipe(channel) != 0) {
        return 2;
    }
    pid_t child = fork();
    if (child < 0) {
        return 2;
    }
    if (child == 0) {
        alarm(5);
        close(channel[0]);
        if (observe(&forked) != 0 || transfer(channel[1], &forked, sizeof(forked), 1) != 0) {
            _exit(2);
        }
        char number[24];
        snprintf(number, sizeof(number), "%d", channel[1]);
        char *const args[] = {argv[0], "--leaf", number, NULL};
        char *const clean_env[] = {"PATH=/usr/bin:/bin", "LANG=C", "LC_ALL=C", NULL};
        execve(argv[0], args, clean_env);
        _exit(2);
    }
    close(channel[1]);
    int received = transfer(channel[0], &forked, sizeof(forked), 0) == 0 &&
                   transfer(channel[0], &executed, sizeof(executed), 0) == 0;
    close(channel[0]);
    int status = 0;
    pid_t waited;
    do {
        waited = waitpid(child, &status, 0);
    } while (waited < 0 && errno == EINTR);
    if (!received || waited != child || !WIFEXITED(status) || WEXITSTATUS(status) != 0 ||
        forked.pid != (uint32_t)child || executed.pid != (uint32_t)child) {
        return 2;
    }
    printf("{\"root\":");
    print_snapshot(&root);
    printf(",\"forked\":");
    print_snapshot(&forked);
    printf(",\"executed\":");
    print_snapshot(&executed);
    printf("}\n");
    return 0;
}
