#!/bin/bash
# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT
# HUMAN ONLY. Close agents first. An agent may syntax-check, never execute this script.
set -eu
task_kit=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd -P)
task_python=/Users/dabianco/projects/SURGe/EvidenceForge/.venv/bin/python
printf '%s\n' 'PRIVATE_STEP_SETUP'
"$task_python" -I -B "$task_kit/private_ssh_descriptors.py" setup --private-run
printf '%s\n' 'PRIVATE_STEP_LOCAL'
"$task_python" -I -B "$task_kit/private_ssh_descriptors.py" record local --private-run
task_ssh_options=(
    -F /dev/null -a -x
    -o ClearAllForwardings=yes -o PermitLocalCommand=no
    -o ControlMaster=no -o ControlPath=none
    -o "UserKnownHostsFile=$task_kit/known_hosts" -o GlobalKnownHostsFile=/dev/null
    -o UpdateHostKeys=no -o StrictHostKeyChecking=ask -o ConnectTimeout=10
    -o ConnectionAttempts=1 -o NumberOfPasswordPrompts=1
)
printf '%s\n' 'PRIVATE_STEP_SSH_NO_PTY'
/usr/bin/ssh "${task_ssh_options[@]}" -T 127.0.0.1 \
    "$task_python -I -B $task_kit/private_ssh_descriptors.py record no_pty --private-run --ssh-context"
printf '%s\n' 'PRIVATE_STEP_SSH_PTY'
/usr/bin/ssh "${task_ssh_options[@]}" -tt 127.0.0.1 \
    "$task_python -I -B $task_kit/private_ssh_descriptors.py record pty --private-run --ssh-context"
printf '%s\n' 'PRIVATE_STEP_REPORT'
"$task_python" -I -B "$task_kit/private_ssh_descriptors.py" report --private-run
