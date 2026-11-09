/* Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
 * SPDX-License-Identifier: MIT
 * Bounded second-host collector. No workloads, shell, files or policy changes.
 * Root owns one fixed eslogger child; pipe closure cancels and reaps it.
 */
#define _POSIX_C_SOURCE 200809L
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <string.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#ifdef EFORGE_GUARD_TEST
#ifndef EFORGE_TEST_COLLECTOR
#error A test build requires an invented collector executable
#endif
#define COLLECTOR EFORGE_TEST_COLLECTOR
#else
#define COLLECTOR "/usr/bin/eslogger"
#endif

static volatile sig_atomic_t stopping;
static void stop(int ignored) { (void)ignored; stopping = 1; }

int main(int argc, char **argv) {
    if (argc != 2) return 2;
    int filesystem = strcmp(argv[1], "filesystem") == 0;
    int process = strcmp(argv[1], "process") == 0;
    if (!filesystem && !process) return 2;
#ifndef EFORGE_GUARD_TEST
    if (geteuid() != 0) return 2;
#endif
    struct sigaction action = {0};
    action.sa_handler = stop;
    sigemptyset(&action.sa_mask);
    sigset_t mask;
    sigemptyset(&mask);
    sigaddset(&mask, SIGALRM);
    sigaddset(&mask, SIGINT);
    sigaddset(&mask, SIGTERM);
    if (sigprocmask(SIG_UNBLOCK, &mask, NULL)) return 2;
    if (sigaction(SIGINT, &action, NULL) || sigaction(SIGTERM, &action, NULL) ||
        sigaction(SIGALRM, &action, NULL)) return 2;
#ifdef EFORGE_GUARD_TEST
    alarm(1);
#else
    alarm(filesystem ? 30 : 180);
#endif
    pid_t child = fork();
    if (child < 0) return 2;
    if (child == 0) {
        if (setpgid(0, 0)) _exit(2);
        int input = open("/dev/null", O_RDONLY);
        if (input < 0 || dup2(input, STDIN_FILENO) < 0) _exit(2);
        if (input != STDIN_FILENO) close(input);
        char *const files[] = {COLLECTOR, "fork", "exec", "exit", "create", "close",
                              "rename", "unlink", NULL};
        char *const processes[] = {COLLECTOR, "fork", "exec", "exit", NULL};
        char *const environment[] = {"PATH=/usr/bin:/bin", "LANG=C", "LC_ALL=C", NULL};
        execve(COLLECTOR, filesystem ? files : processes, environment);
        _exit(2);
    }
    (void)setpgid(child, child);
    struct pollfd input = {.fd=STDIN_FILENO, .events=POLLIN | POLLHUP};
    int status = 0;
    while (!stopping) {
        pid_t result = waitpid(child, &status, WNOHANG);
        if (result == child || (result < 0 && errno != EINTR)) return 2;
        int ready = poll(&input, 1, 100);
        if ((ready < 0 && errno != EINTR) ||
            (ready > 0 && input.revents & (POLLIN | POLLHUP | POLLERR | POLLNVAL))) break;
    }
    alarm(0);
    (void)kill(-child, SIGTERM);
    const struct timespec pause = {0, 50000000};
    for (int i = 0; i < 40; ++i) {
        pid_t result = waitpid(child, &status, WNOHANG);
        if (result == child) return 0;
        if (result < 0 && errno != EINTR) return 2;
        nanosleep(&pause, NULL);
    }
    (void)kill(-child, SIGKILL);
    while (waitpid(child, &status, 0) < 0) if (errno != EINTR) return 2;
    return 0;
}
