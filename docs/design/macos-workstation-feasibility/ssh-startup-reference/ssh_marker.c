/* Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
 * SPDX-License-Identifier: MIT
 * HUMAN ONLY. No files, environment reads, identity queries or printed values.
 */
#include <string.h>
#include <unistd.h>

int main(int argc, char **argv) {
    if (argc == 2 && !strcmp(argv[1], "--ready")) {
        usleep(250000);
        return 0;
    }
    if (argc != 3 || strcmp(argv[1], "--sample") || strlen(argv[2]) != 32) return 2;
    for (int i = 0; i < 32; ++i)
        if (!((argv[2][i] >= '0' && argv[2][i] <= '9') ||
              (argv[2][i] >= 'a' && argv[2][i] <= 'f'))) return 2;
    usleep(250000);
    return 0;
}
