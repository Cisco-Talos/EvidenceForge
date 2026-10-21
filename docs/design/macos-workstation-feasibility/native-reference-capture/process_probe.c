/* Independently authored harmless macOS lab probe. Do not run before capture approval. */
#define _POSIX_C_SOURCE 200809L
#include <errno.h>
#include <mach/mach_time.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

static void mark(const char *label, long value) {
    struct timespec wall;
    if (clock_gettime(CLOCK_REALTIME, &wall) != 0) {
        perror("clock_gettime");
        exit(2);
    }
    printf("%s pid=%ld value=%ld wall=%lld.%09ld mach=%llu\n", label,
           (long)getpid(), value, (long long)wall.tv_sec, wall.tv_nsec,
           (unsigned long long)mach_absolute_time());
    fflush(stdout);
}

int main(int argc, char **argv) {
    if (argc == 2 && strcmp(argv[1], "exit7") == 0) {
        mark("exec_target_exit7", 7);
        return 7;
    }
    if (argc == 2 && strcmp(argv[1], "signal") == 0) {
        mark("exec_target_sigterm", SIGTERM);
        if (kill(getpid(), SIGTERM) != 0) {
            perror("kill");
        }
        return 99;
    }
    if (argc != 1) {
        fputs("Run without arguments for the three labeled cases.\n", stderr);
        return 2;
    }
    mach_timebase_info_data_t timebase;
    if (mach_timebase_info(&timebase) != KERN_SUCCESS) {
        fputs("mach_timebase_info failed\n", stderr);
        return 2;
    }
    printf("timebase numer=%u denom=%u\n", timebase.numer, timebase.denom);
    const char *cases[] = {"exit7", "signal", "failed_exec"};
    for (size_t index = 0; index < sizeof(cases) / sizeof(cases[0]); ++index) {
        mark("before_fork", (long)index);
        pid_t child = fork();
        if (child < 0) {
            perror("fork");
            return 2;
        }
        if (child == 0) {
            mark(cases[index], (long)getppid());
            if (index == 2) {
                execl("/nonexistent/eforge-reference-control", "eforge-missing", (char *)NULL);
                mark("exec_returned_errno", errno);
                _exit(3);
            }
            execl(argv[0], argv[0], cases[index], (char *)NULL);
            perror("execl");
            _exit(2);
        }
        int status = 0;
        pid_t waited;
        do {
            waited = waitpid(child, &status, 0);
        } while (waited < 0 && errno == EINTR);
        if (waited != child) {
            perror("waitpid");
            return 2;
        }
        mark("waited_child_pid", (long)child);
        mark("raw_wait_status", status);
    }
    return 0;
}
