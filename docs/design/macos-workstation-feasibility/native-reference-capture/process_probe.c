/* Independently authored harmless probe. HUMAN private runs only, never agent-run. */
#define _POSIX_C_SOURCE 200809L
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

static char *const clean_environment[] = {"PATH=/usr/bin:/bin", "LANG=C", "LC_ALL=C", NULL};

int main(int argc, char **argv) {
    if (argc == 2 && strcmp(argv[1], "exit7") == 0) {
        return 7;
    }
    if (argc == 2 && strcmp(argv[1], "signal") == 0) {
        sigset_t unblocked;
        if (sigemptyset(&unblocked) != 0 || sigaddset(&unblocked, SIGTERM) != 0 ||
            sigprocmask(SIG_UNBLOCK, &unblocked, NULL) != 0 ||
            signal(SIGTERM, SIG_DFL) == SIG_ERR || kill(getpid(), SIGTERM) != 0) {
            return 99;
        }
        return 99;
    }
    if (argc != 1) {
        return 2;
    }
    alarm(30);
    for (;;) {
        char command;
        if (read(STDIN_FILENO, &command, 1) != 1) {
            return 2;
        }
        if (command == 'G') {
            break;
        }
        if (command != 'R') {
            return 2;
        }
        /* A bounded harmless warm-up; no exec or control-output records. */
        pid_t warmup = fork();
        if (warmup < 0) {
            return 2;
        }
        if (warmup == 0) {
            _exit(0);
        }
        int status = 0;
        pid_t waited;
        do {
            waited = waitpid(warmup, &status, 0);
        } while (waited < 0 && errno == EINTR);
        if (waited != warmup || status != 0) {
            return 2;
        }
    }
    const char *cases[] = {"exit7", "signal", "failed_exec", "apple_true"};
    for (size_t index = 0; index < sizeof(cases) / sizeof(cases[0]); ++index) {
        pid_t child = fork();
        if (child < 0) {
            return 2;
        }
        if (child == 0) {
            if (index == 2) {
                char *const missing_argv[] = {"eforge-never-created", NULL};
                execve("./eforge-never-created", missing_argv, clean_environment);
                int result = errno;
                printf("{\"kind\":\"failed_return\",\"case\":\"failed_exec\",\"pid\":%ld,\"value\":%d}\n",
                       (long)getpid(), result);
                fflush(stdout);
                _exit(3);
            }
            if (index == 3) {
                char *const true_argv[] = {"/usr/bin/true", NULL};
                execve("/usr/bin/true", true_argv, clean_environment);
                _exit(2);
            }
            char *const target_argv[] = {argv[0], (char *)cases[index], NULL};
            execve(argv[0], target_argv, clean_environment);
            _exit(2);
        }
        int status = 0;
        pid_t waited;
        do {
            waited = waitpid(child, &status, 0);
        } while (waited < 0 && errno == EINTR);
        if (waited != child) {
            return 2;
        }
        printf("{\"kind\":\"wait\",\"case\":\"%s\",\"pid\":%ld,\"value\":%d}\n",
               cases[index], (long)child, status);
        fflush(stdout);
    }
    return 0;
}
