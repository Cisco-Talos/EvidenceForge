"""Verify and clean native interpreters behind Windows virtualenv launchers."""

from __future__ import annotations

import os
import sys
from pathlib import Path

import psutil

from evidenceforge.studio.bootstrap import ServiceDescriptor
from evidenceforge.studio.ownership import current_account, process_account


def verified_helper_child(launcher_pid: int, descriptor: ServiceDescriptor) -> psutil.Process:
    """Accept only the harness process or its direct Windows Python interpreter."""
    actual = psutil.Process(descriptor.pid)
    assert abs(actual.create_time() - descriptor.created_at) < 0.01
    assert process_account(actual) == current_account()
    assert Path(actual.exe()).resolve() == Path(descriptor.executable or sys.executable).resolve()
    if actual.pid != launcher_pid:
        assert os.name == "nt"
        assert actual.ppid() == launcher_pid
        assert Path(actual.exe()).resolve() == Path(sys._base_executable).resolve()
    return actual


def stop_helper_child(process: psutil.Process | None) -> None:
    """Stop only the previously verified helper; psutil checks against PID reuse."""
    if process is None:
        return
    try:
        process.terminate()
        try:
            process.wait(timeout=8)
        except psutil.TimeoutExpired:
            process.kill()
            process.wait(timeout=8)
    except psutil.NoSuchProcess:
        pass
