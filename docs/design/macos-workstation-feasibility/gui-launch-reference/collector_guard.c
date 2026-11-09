/* Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
 * SPDX-License-Identifier: MIT
 * HUMAN ONLY. Root owns one fixed eslogger child for at most 55 seconds.
 * Parent-pipe EOF cancels collection; the guard terminates and reaps its child.
 */
#define _POSIX_C_SOURCE 200809L
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

static volatile sig_atomic_t stopping;
static void stop(int ignored) { (void)ignored; stopping = 1; }

int main(int argc, char **argv) {
    (void)argv;
    if (argc != 1 || geteuid() != 0) return 2;
    struct sigaction action = {0};
    action.sa_handler = stop; sigemptyset(&action.sa_mask);
    sigset_t mask; sigemptyset(&mask); sigaddset(&mask, SIGALRM);
    if (sigprocmask(SIG_UNBLOCK, &mask, NULL)) return 2;
    if (sigaction(SIGINT, &action, NULL) || sigaction(SIGTERM, &action, NULL) ||
        sigaction(SIGALRM, &action, NULL)) return 2;
    alarm(55);
    pid_t child = fork();
    if (child < 0) return 2;
    if (child == 0) {
        if (setpgid(0, 0)) _exit(2);
        int input = open("/dev/null", O_RDONLY);
        if (input < 0 || dup2(input, STDIN_FILENO) < 0) _exit(2);
        if (input != STDIN_FILENO) close(input);
        char *const args[] = {"/usr/bin/eslogger", "fork", "exec", "exit", NULL};
        char *const env[] = {"PATH=/usr/bin:/bin", "LANG=C", "LC_ALL=C", NULL};
        execve(args[0], args, env); _exit(2);
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
