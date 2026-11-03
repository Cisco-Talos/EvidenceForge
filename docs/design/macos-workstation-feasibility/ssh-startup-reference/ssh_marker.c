/* Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
 * SPDX-License-Identifier: MIT
 * HUMAN ONLY. No files, environment reads or identity queries.
 * Only --ulf-ready writes its generated public nonce to Unified Log.
 */
#include <string.h>
#include <unistd.h>
#include <os/log.h>

int main(int argc, char **argv) {
    if (argc == 2 && !strcmp(argv[1], "--ready")) {
        usleep(250000);
        return 0;
    }
    if (argc != 3 ||
        (strcmp(argv[1], "--sample") && strcmp(argv[1], "--ulf-ready")) ||
        strlen(argv[2]) != 32) return 2;
    for (int i = 0; i < 32; ++i)
        if (!((argv[2][i] >= '0' && argv[2][i] <= '9') ||
              (argv[2][i] >= 'a' && argv[2][i] <= 'f'))) return 2;
    if (!strcmp(argv[1], "--ulf-ready")) {
        os_log(OS_LOG_DEFAULT, "EFORGE_SSH_ULF_READY %{public}s", argv[2]);
        return 0;
    }
    usleep(250000);
    return 0;
}
