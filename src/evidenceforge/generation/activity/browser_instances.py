"""Resolve modeled browser-instance ownership without consulting the host filesystem."""

import ntpath
import posixpath
import re
import shlex

from evidenceforge.config.schemas import BrowserProfileRoots
from evidenceforge.generation.activity.proxy_user_agents import (
    _browser_family_for_process,
    load_proxy_user_agents,
)


def _option_argument(arguments: list[str], flags: tuple[str, ...]) -> tuple[bool, str | None]:
    """Read one literal option, retaining malformed or ambiguous intent."""
    values: list[str | None] = []
    for index, argument in enumerate(arguments):
        for flag in flags:
            if argument == flag:
                value = arguments[index + 1] if index + 1 < len(arguments) else None
                values.append(value if value and not value.startswith("-") else None)
            elif argument.startswith(flag + "="):
                values.append(argument[len(flag) + 1 :] or None)
    return bool(values), values[0] if len(values) == 1 else None


def browser_main_intent(image: str, command_line: str) -> bool:
    """Recognize browser roots separately from helpers and independent-instance flags."""
    if not _browser_family_for_process(image) or "/helpers/" in image.casefold().replace("\\", "/"):
        return False
    command = f" {command_line.casefold()} "
    return not any(
        marker in command
        for marker in ("--type=", "--utility-sub-type=", "-contentproc", " -childid ")
    )


def browser_instance_key(
    image: str, command_line: str, os_category: str, username: str
) -> tuple[str, str] | None:
    """Return executable and resolved user-data identity for a reusable browser.

    Child processes and explicit independent instances are not reusable. Relative
    directories have no safe identity without an exact execution cwd, so they also
    remain explicit launches. Firefox named profiles stay distinct from its default.
    """
    family = _browser_family_for_process(image)
    if not browser_main_intent(image, command_line):
        return None
    command = f" {command_line.casefold()} "
    if any(
        marker in command
        for marker in (
            " -no-remote ",
            " --no-remote ",
            " --new-instance ",
            " -new-instance ",
        )
    ):
        return None
    paths = ntpath if os_category == "windows" else posixpath
    roots = load_proxy_user_agents().get("browser_profile_roots", {})
    profile = BrowserProfileRoots.model_validate(roots.get(family, {}))
    root = getattr(profile, os_category, None)
    if not isinstance(root, str) or not root:
        return None
    root = root.replace("{username}", username)
    flags = r"--user-data-dir" if family != "firefox" else r"--?profile"
    match = re.search(
        rf"(?:^|\s)(?:{flags})(?:=|\s+)(?:\"([^\"]+)\"|'([^']+)'|([^\s]+))",
        command_line,
        re.IGNORECASE,
    )
    found = bool(re.search(rf"(?:^|\s)(?:{flags})(?:=|\s|$)", command_line))
    explicit = (
        next((value for value in match.groups() if value is not None), None) if match else None
    )
    arguments: list[str] = []
    if os_category != "windows":
        try:
            arguments = shlex.split(command_line)
        except ValueError:
            return None
        found, explicit = _option_argument(
            arguments, ("--user-data-dir",) if family != "firefox" else ("-profile", "--profile")
        )
    if found:
        if not explicit:
            return None
        root = explicit
        if root.startswith("~/"):
            root = posixpath.join(
                "/Users" if os_category == "macos" else "/home", username, root[2:]
            )
        if not paths.isabs(root):
            return None
    elif family == "firefox":
        named = re.search(r"(?:^|\s)-P\s+(?:\"([^\"]+)\"|'([^']+)'|([^\s]+))", command_line)
        named_found = bool(named)
        name = (
            next((value for value in named.groups() if value is not None), None) if named else None
        )
        if os_category != "windows":
            named_found, name = _option_argument(arguments, ("-P",))
        if named_found and not name:
            return None
        root = paths.join(root, "named:" + name) if name else paths.join(root, "modeled-default")
    normalize = paths.normcase if os_category == "windows" else lambda value: value
    return normalize(paths.normpath(image)), normalize(paths.normpath(root))
