/* Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
 * SPDX-License-Identifier: MIT
 * HUMAN ONLY. No files, identity queries, environment reads or printed values.
 */
#include <string.h>
#include <unistd.h>

int main(int argc, char **argv) {
    if (argc != 2 || (strcmp(argv[1], "--ready") && strcmp(argv[1], "--sample"))) return 2;
    usleep(250000);
    return 0;
}
