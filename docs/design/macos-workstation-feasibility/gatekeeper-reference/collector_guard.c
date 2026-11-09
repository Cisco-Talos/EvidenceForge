/* HUMAN ONLY. Root scope: one fixed eslogger child, private pipe, <=55 seconds.
 * No inputs, file reads, environment inheritance, logs or service changes.
 * A separate process group and root-owned cleanup prevent an orphan collector.
 */
#define _POSIX_C_SOURCE 200809L
#include <errno.h>
#include <signal.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

static volatile sig_atomic_t stopping = 0;
static void stop(int unused) { (void)unused; stopping = 1; }

int main(int argc, char **argv) {
    (void)argv;
    if (argc != 1 || geteuid() != 0) return 2;
    struct sigaction action = {0};
    action.sa_handler = stop;
    sigemptyset(&action.sa_mask);
    if (sigaction(SIGINT, &action, NULL) != 0 ||
        sigaction(SIGTERM, &action, NULL) != 0 ||
        sigaction(SIGALRM, &action, NULL) != 0) return 2;
    pid_t child = fork();
    if (child < 0) return 2;
    if (child == 0) {
        if (setpgid(0, 0) != 0) _exit(2);
        char *const args[] = {"/usr/bin/eslogger", "exec", "exit", NULL};
        char *const env[] = {"PATH=/usr/bin:/bin", "LANG=C", "LC_ALL=C", NULL};
        execve(args[0], args, env);
        _exit(2);
    }
    (void)setpgid(child, child);
    alarm(55);
    int status = 0;
    const struct timespec pause = {0, 50000000};
    while (!stopping) {
        pid_t result = waitpid(child, &status, WNOHANG);
        if (result == child) return 2; /* Unexpected source termination. */
        if (result < 0 && errno != EINTR) return 2;
        nanosleep(&pause, NULL);
    }
    alarm(0);
    (void)kill(-child, SIGTERM);
    for (int attempt = 0; attempt < 40; ++attempt) {
        pid_t result = waitpid(child, &status, WNOHANG);
        if (result == child) return 0;
        if (result < 0 && errno != EINTR) return 2;
        nanosleep(&pause, NULL);
    }
    (void)kill(-child, SIGKILL);
    while (waitpid(child, &status, 0) < 0) {
        if (errno != EINTR) return 2;
    }
    return 0;
}
