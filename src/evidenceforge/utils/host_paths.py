"""Host-specific conversion at portable file-reference boundaries."""

import os
from pathlib import PurePath


def logical_path(path: PurePath) -> str:
    """Use slash-separated references on Windows and retain POSIX string conversion."""
    if os.name == "nt":
        return path.as_posix()
    return str(path)
