"""Validate release identity, verify installers, and publish complete GitHub releases.

Run as ``uv run python -m scripts.release_pipeline`` from the repository root.
Only the explicit ``publish`` subcommand writes to GitHub.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import subprocess
from pathlib import Path
from tempfile import TemporaryDirectory

from pydantic import BaseModel, ConfigDict
from scripts.sync_studio_version import studio_version, synchronize


class ReleasePlan(BaseModel):
    """Validated immutable identity shared by the build and publication jobs."""

    model_config = ConfigDict(extra="forbid", frozen=True)
    version: str
    tag: str
    sha: str
    prerelease: bool

    @property
    def dmg_name(self) -> str:
        """Return the current supported installer name."""
        return f"EvidenceForge-Studio-{self.version}-aarch64.dmg"

    @property
    def marker(self) -> str:
        """Bind recoverable release drafts to this exact source commit."""
        return f"<!-- EvidenceForge release commit: {self.sha} -->"


def run(root: Path, command: list[str]) -> str:
    """Run an argument-safe command; errors never imply a missing remote object."""
    return subprocess.run(
        command, cwd=root, capture_output=True, text=True, check=True
    ).stdout.strip()


def remote_tag(root: Path, tag: str) -> str | None:
    """Resolve an annotated remote tag to its commit without mutating local refs."""
    output = run(root, ["git", "ls-remote", "origin", f"refs/tags/{tag}", f"refs/tags/{tag}^{{}}"])
    refs = dict(line.split()[::-1] for line in output.splitlines())
    if not refs:
        return None
    peeled = refs.get(f"refs/tags/{tag}^{{}}")
    if peeled is None:
        raise ValueError(f"Release tag {tag} must be annotated; do not overwrite an existing tag.")
    return peeled


def changelog_notes(root: Path, version: str) -> str:
    """Require and extract this version's checked-in release notes."""
    content = (root / "CHANGELOG.md").read_text(encoding="utf-8")
    match = re.search(
        rf"^## v{re.escape(version)} \(\d{{4}}-\d{{2}}-\d{{2}}\)\n(.*?)(?=^## |\Z)",
        content,
        re.MULTILINE | re.DOTALL,
    )
    if match is None or not match[1].strip():
        raise ValueError(f"Add a nonempty ## v{version} (YYYY-MM-DD) section to CHANGELOG.md.")
    return match[1].strip()


def prepare(root: Path, event: str, ref: str) -> ReleasePlan:
    """Enforce stable-main and prerelease-dev entry points before any build or write."""
    version = synchronize(root, check=True)
    plan = ReleasePlan(
        version=version,
        tag=f"v{version}",
        sha=run(root, ["git", "rev-parse", "HEAD"]),
        prerelease="-" in studio_version(version),
    )
    changelog_notes(root, version)
    if run(root, ["git", "status", "--porcelain", "--untracked-files=normal"]):
        raise ValueError(
            "Release source must be a clean committed snapshot before building or publishing."
        )
    existing = remote_tag(root, plan.tag)
    if event == "pull_request":
        if plan.prerelease:
            raise ValueError("Prepare a stable version before opening the release PR to main.")
        if existing is not None:
            raise ValueError(f"Remote release tag {plan.tag} already exists; bump before merging.")
    elif event == "push" and ref == "refs/heads/main":
        if plan.prerelease:
            raise ValueError(
                "Prereleases must use an annotated tag on dev; main publishes stable versions."
            )
        if existing is not None and existing != plan.sha:
            raise ValueError(f"Remote tag {plan.tag} belongs to another commit; never move it.")
    elif event == "push" and ref.startswith("refs/tags/"):
        if not plan.prerelease or ref != f"refs/tags/{plan.tag}":
            raise ValueError(
                "Tag entry requires an alpha/beta/RC tag matching the product version."
            )
        if existing != plan.sha:
            raise ValueError(
                "The annotated remote release tag must point to the checked-out commit."
            )
        # The checkout fetches full history; refresh dev without changing the release HEAD.
        run(root, ["git", "fetch", "origin", "dev:refs/remotes/origin/dev"])
        result = subprocess.run(
            ["git", "merge-base", "--is-ancestor", plan.sha, "origin/dev"], cwd=root, check=False
        )
        if result.returncode != 0:
            raise ValueError("The prerelease commit must be reachable from origin/dev.")
    else:
        raise ValueError("Release entry must be a main push, release PR, or prerelease tag push.")
    return plan


def verify_assets(directory: Path, plan: ReleasePlan) -> list[Path]:
    """Require exactly the supported installer and its valid, filename-bound SHA256."""
    files = sorted(path for path in directory.rglob("*") if path.is_file())
    expected = {plan.dmg_name, f"{plan.dmg_name}.sha256"}
    if len(files) != len(expected) or {path.name for path in files} != expected:
        raise ValueError(f"Release artifacts must contain exactly {sorted(expected)}.")
    image = next(path for path in files if path.name == plan.dmg_name)
    checksum = next(path for path in files if path.name.endswith(".sha256"))
    if image.is_symlink() or checksum.is_symlink() or image.stat().st_size == 0:
        raise ValueError("Release assets must be nonempty regular files.")
    with image.open("rb") as stream:
        digest = hashlib.file_digest(stream, "sha256").hexdigest()
    if checksum.read_text(encoding="utf-8") != f"{digest}  {image.name}\n":
        raise ValueError(
            "DMG checksum or its recorded filename does not match the release installer."
        )
    return files


def publish(root: Path, directory: Path, plan: ReleasePlan, repository: str) -> None:
    """Resume owned drafts; verify uploaded bytes before publication; never alter published releases."""
    files = verify_assets(directory, plan)
    if not re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", repository):
        raise ValueError("GITHUB_REPOSITORY must be owner/repository.")
    existing = remote_tag(root, plan.tag)
    if existing is not None and existing != plan.sha:
        raise ValueError("Release tag changed after validation; refusing publication.")
    # List includes authenticated drafts. A network/auth failure aborts rather than being treated as 404.
    raw = run(
        root,
        [
            "gh",
            "api",
            "--paginate",
            f"repos/{repository}/releases",
            "--jq",
            f'.[] | select(.tag_name == "{plan.tag}")',
        ],
    )
    release = json.loads(raw) if raw else None
    if release is not None:
        if (
            plan.marker not in (release.get("body") or "")
            or release["prerelease"] != plan.prerelease
        ):
            raise ValueError(
                "Existing release is not an owned draft/publication for this exact commit."
            )
        if not release["draft"]:
            if existing != plan.sha:
                raise ValueError("Published release tag is missing; refusing to recreate it.")
            with TemporaryDirectory(prefix="eforge-published-") as temporary:
                run(
                    root,
                    [
                        "gh",
                        "release",
                        "download",
                        plan.tag,
                        "--repo",
                        repository,
                        "--dir",
                        temporary,
                    ],
                )
                verify_assets(Path(temporary), plan)
            print(f"Release {plan.tag} is already complete; left unchanged.")
            return
    if existing is None:
        if plan.prerelease:
            raise ValueError("The prerelease tag disappeared; refusing to recreate it.")
        run(
            root,
            [
                "git",
                "-c",
                "user.name=github-actions[bot]",
                "-c",
                "user.email=41898282+github-actions[bot]@users.noreply.github.com",
                "tag",
                "-a",
                plan.tag,
                plan.sha,
                "-m",
                f"EvidenceForge {plan.tag}",
            ],
        )
        run(root, ["git", "push", "origin", f"refs/tags/{plan.tag}"])
    if release is None:
        notes = (
            f"{plan.marker}\n\n{changelog_notes(root, plan.version)}\n\n"
            "### macOS installer\n\n"
            "Apple Silicon only. Includes Python and the EvidenceForge runtime. Codex is installed "
            "separately for authoring. This build has no Developer ID signature or notarization. "
            "See docs/studio.md in the tagged source for installation and "
            "tested-platform limitations. Verify the download using the companion SHA256 file.\n"
        )
        with TemporaryDirectory(prefix="eforge-release-notes-") as temporary:
            path = Path(temporary) / "notes.md"
            path.write_text(notes, encoding="utf-8")
            command = [
                "gh",
                "release",
                "create",
                plan.tag,
                "--repo",
                repository,
                "--draft",
                "--verify-tag",
                "--title",
                f"EvidenceForge {plan.tag}",
                "--notes-file",
                str(path),
            ]
            if plan.prerelease:
                command.extend(["--prerelease", "--latest=false"])
            run(root, command)
    # Download any existing draft assets and preserve them. Rerun failed jobs to reuse the
    # original build; rebuilding an installer may legitimately produce different bytes.
    with TemporaryDirectory(prefix="eforge-draft-assets-") as temporary:
        prior = Path(temporary)
        if release is not None and release.get("assets"):
            run(
                root,
                ["gh", "release", "download", plan.tag, "--repo", repository, "--dir", temporary],
            )
        for path in files:
            saved = prior / path.name
            if saved.exists():
                if saved.read_bytes() != path.read_bytes():
                    raise ValueError(
                        "Draft asset differs; rerun failed jobs using the original build artifacts."
                    )
            else:
                run(root, ["gh", "release", "upload", plan.tag, str(path), "--repo", repository])
        with TemporaryDirectory(prefix="eforge-release-verify-") as downloaded:
            run(
                root,
                ["gh", "release", "download", plan.tag, "--repo", repository, "--dir", downloaded],
            )
            verify_assets(Path(downloaded), plan)
            if any(
                path.read_bytes() != (Path(downloaded) / path.name).read_bytes() for path in files
            ):
                raise ValueError(
                    "Uploaded assets differ from the verified build; draft remains unpublished."
                )
    if remote_tag(root, plan.tag) != plan.sha:
        raise ValueError("Release tag changed during upload; draft remains unpublished.")
    run(
        root,
        [
            "gh",
            "release",
            "edit",
            plan.tag,
            "--repo",
            repository,
            "--draft=false",
            f"--prerelease={'true' if plan.prerelease else 'false'}",
            f"--latest={'false' if plan.prerelease else 'true'}",
        ],
    )


def main() -> None:
    """Expose read-only preparation/verification and explicitly requested publication."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=["prepare", "verify-assets", "publish"])
    parser.add_argument("--directory", type=Path, default=Path("dist/release"))
    args = parser.parse_args()
    root = Path.cwd().resolve()
    try:
        plan = prepare(root, os.environ["GITHUB_EVENT_NAME"], os.environ["GITHUB_REF"])
        if args.command == "prepare":
            output = os.environ.get("GITHUB_OUTPUT")
            if output:
                with Path(output).open("a", encoding="utf-8") as stream:
                    for key, value in {**plan.model_dump(), "dmg_name": plan.dmg_name}.items():
                        print(
                            f"{key}={str(value).lower() if isinstance(value, bool) else value}",
                            file=stream,
                        )
            print(plan.model_dump_json())
        elif args.command == "verify-assets":
            verify_assets(args.directory.resolve(), plan)
        else:
            publish(root, args.directory.resolve(), plan, os.environ["GITHUB_REPOSITORY"])
    except (ValueError, OSError, KeyError, subprocess.CalledProcessError) as error:
        parser.exit(1, f"Release pipeline failed: {error}\n")


if __name__ == "__main__":
    main()
