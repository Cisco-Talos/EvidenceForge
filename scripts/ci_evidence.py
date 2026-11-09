"""Reuse successful CI jobs only when tested inputs and execution profiles match."""

from __future__ import annotations

import argparse
import hashlib
import io
import json
import os
import platform
import re
import shutil
import subprocess
import sys
import zipfile
from datetime import UTC, datetime, timedelta
from email.message import Message
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import Any, BinaryIO, Literal
from urllib.parse import quote, urlsplit
from urllib.request import HTTPRedirectHandler, Request, build_opener

from pydantic import BaseModel, ConfigDict, Field, TypeAdapter
from scripts.ci_shards import ShardReport, json_report, validate_reports

ROOT = Path(__file__).resolve().parents[1]
IGNORED_DOCS = {"CHANGELOG.md", "TODO.md", "docs/releases.md"}
MAX_ARCHIVE_BYTES = 32 * 1024 * 1024
FRESHNESS = timedelta(days=7)
KINDS = Literal["routine", "slow", "studio", "recovery", "durability", "portability"]


class Evidence(BaseModel):
    """Immutable origin of an executed check; reuse preserves the original job ID."""

    model_config = ConfigDict(extra="forbid", frozen=True)
    schema_version: Literal[1] = 1
    repository: str
    check_id: str
    kind: KINDS
    fingerprint: str = Field(pattern=r"^[0-9a-f]{64}$")
    source_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    source_sha: str = Field(pattern=r"^[0-9a-f]{40}$")
    runner_label: str
    run_id: int = Field(gt=0)
    attempt: int = Field(gt=0)
    job_id: int = Field(gt=0)
    requirements: list[str]
    shard: ShardReport | None = None
    coverage_sha256: str | None = None


class ArtifactRun(BaseModel):
    """GitHub-authenticated provenance of the run that uploaded an artifact."""

    id: int = Field(gt=0)
    repository_id: int = Field(gt=0)
    head_repository_id: int = Field(gt=0)
    head_sha: str = Field(pattern=r"^[0-9a-f]{40}$")


class Artifact(BaseModel):
    """Only API-owned fields may authorize downloading a candidate result."""

    id: int = Field(gt=0)
    expired: bool
    digest: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    workflow_run: ArtifactRun


def git(*arguments: str) -> str:
    """Read committed repository metadata without executing candidate code."""
    return subprocess.check_output(["git", *arguments], cwd=ROOT, text=True).strip()


def source_digest(reference: str = "HEAD") -> str:
    """Hash tracked paths, modes and Git object identities with narrow doc exclusions."""
    raw = subprocess.check_output(["git", "ls-tree", "-rz", "--full-tree", reference], cwd=ROOT)
    entries: list[bytes] = []
    for entry in raw.split(b"\0"):
        if not entry:
            continue
        path = entry.split(b"\t", 1)[1].decode("utf-8")
        if path in IGNORED_DOCS or path.startswith("docs/worklog/"):
            continue
        entries.append(entry)
    return hashlib.sha256(b"\0".join(sorted(entries))).hexdigest()


class ArtifactRedirect(HTTPRedirectHandler):
    """Strip API credentials when GitHub redirects to its artifact storage host."""

    def redirect_request(
        self, req: Request, fp: BinaryIO, code: int, msg: str, headers: Message, newurl: str
    ) -> Request | None:
        redirected = super().redirect_request(req, fp, code, msg, headers, newurl)
        if redirected is not None:
            if urlsplit(newurl).scheme != "https":
                raise ValueError("CI artifact redirects must use HTTPS")
            if urlsplit(newurl).netloc != urlsplit(req.full_url).netloc:
                redirected.remove_header("Authorization")
        return redirected


def api(path: str, *, binary: bool = False) -> Any:
    """Read bounded GitHub responses with explicit timeouts and safe redirects."""
    request = Request(
        "https://api.github.com/" + path,
        headers={
            "Authorization": "Bearer " + os.environ["GH_TOKEN"],
            "Accept": "application/vnd.github+json",
            "User-Agent": "EvidenceForge-CI",
        },
    )
    with build_opener(ArtifactRedirect()).open(request, timeout=30) as response:
        data = response.read(MAX_ARCHIVE_BYTES + 1)
    if len(data) > MAX_ARCHIVE_BYTES:
        raise ValueError("CI evidence response exceeds its size limit")
    return data if binary else json.loads(data)


def repository() -> str:
    """Require an exact owner/repository identity before constructing API paths."""
    value = os.environ["GITHUB_REPOSITORY"]
    if not re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", value):
        raise ValueError("Invalid CI repository identity")
    return value


def output(name: str, value: str) -> None:
    """Append a single-line output to GitHub's explicit output file."""
    if "\n" in value or "\r" in value:
        raise ValueError("CI outputs must be single-line strings")
    with Path(os.environ["GITHUB_OUTPUT"]).open("a", encoding="utf-8") as stream:
        stream.write(f"{name}={value}\n")


def requirements(kind: KINDS, check_id: str) -> list[str]:
    """Return the actual successful execution steps required for each check owner."""
    if kind == "routine":
        return ["Run routine shard"]
    if kind == "slow":
        return ["Run slow shard"]
    if kind == "recovery":
        return ["Run native recovery check"]
    if kind == "durability":
        return ["Test simulated power-loss recovery"]
    if kind == "portability":
        return ["Verify Python 3.12 to 3.13 checkpoint portability"]
    names = [
        "Test local service and job lifecycle",
        "Verify native chat sandbox restrictions",
        "Check generated API types",
        "Test frontend interactions",
        "Build frontend",
        "Test Tauri shell contracts",
        "Build native Studio window",
    ]
    if "macos" in check_id:
        names.extend(
            [
                "Build standalone Apple Silicon test app",
                "Verify isolated packaged CLI and resources",
            ]
        )
    return names


def fingerprint(check_id: str, kind: KINDS) -> str:
    """Bind source, policy, platform, actual runner image and toolchain versions."""
    versions = {"python": sys.version, "machine": platform.machine()}
    if kind == "studio":
        for name, command in {
            "node": ["node", "--version"],
            "npm": ["npm", "--version"],
            "rust": ["rustc", "+stable", "--version"],
        }.items():
            versions[name] = subprocess.check_output(command, text=True, timeout=30).strip()
    payload = {
        "schema": 1,
        "source": source_digest(),
        "check": check_id,
        "kind": kind,
        "os": os.environ["RUNNER_OS"],
        "arch": os.environ["RUNNER_ARCH"],
        "runner": os.environ["CI_RUNNER"],
        "image_os": os.environ["ImageOS"],
        "image_version": os.environ["ImageVersion"],
        "versions": versions,
    }
    if os.environ["RUNNER_OS"] == "Linux":
        packages = subprocess.check_output(["dpkg-query", "-W"], timeout=30)
        payload["system_packages"] = hashlib.sha256(packages).hexdigest()
    return hashlib.sha256(json.dumps(payload, sort_keys=True).encode()).hexdigest()


def unpack_evidence(raw: bytes, destination: Path) -> Evidence:
    """Decode bounded data files without extracting arbitrary archive paths."""
    with zipfile.ZipFile(io.BytesIO(raw)) as archive:
        names = archive.namelist()
        if set(names) - {"evidence.json", "coverage.data"} or names.count("evidence.json") != 1:
            raise ValueError("CI evidence archive contains unexpected paths")
        if len(names) != len(set(names)) or any(
            info.file_size > MAX_ARCHIVE_BYTES for info in archive.infolist()
        ):
            raise ValueError("Invalid CI evidence archive sizes or duplicate entries")
        evidence = Evidence.model_validate_json(archive.read("evidence.json"))
        if evidence.coverage_sha256:
            coverage = archive.read("coverage.data")
            if hashlib.sha256(coverage).hexdigest() != evidence.coverage_sha256:
                raise ValueError("CI coverage bytes do not match the executed check")
            (destination / "coverage.data").write_bytes(coverage)
        elif "coverage.data" in names:
            raise ValueError("Unexpected coverage data in an uninstrumented check")
    return evidence


def verify_origin(evidence: Evidence, expected: str, check_id: str, kind: KINDS) -> None:
    """Verify the real producer job, source tree and required successful steps."""
    repo = repository()
    if evidence.repository != repo or evidence.check_id != check_id or evidence.kind != kind:
        raise ValueError("CI evidence belongs to a different check")
    if evidence.fingerprint != expected or evidence.source_digest != source_digest():
        raise ValueError("CI evidence inputs do not match")
    run = api(f"repos/{repo}/actions/runs/{evidence.run_id}")
    if not isinstance(run.get("repository"), dict) or not isinstance(
        run.get("head_repository"), dict
    ):
        raise ValueError("CI evidence is missing its repository identity")
    if run["repository"]["full_name"] != repo or run["head_repository"]["full_name"] != repo:
        raise ValueError("CI evidence is not from this repository")
    if run["path"].split("@", 1)[0] not in {
        ".github/workflows/ci.yml",
        ".github/workflows/release-slow.yml",
        ".github/workflows/release.yml",
        ".github/workflows/installers.yml",
        ".github/workflows/ci-recovery.yml",
    }:
        raise ValueError("CI evidence producer is not an approved workflow")
    if run["event"] not in {"push", "pull_request", "workflow_dispatch"}:
        raise ValueError("Unsupported CI evidence producer event")
    job = api(f"repos/{repo}/actions/jobs/{evidence.job_id}")
    if job["run_id"] != evidence.run_id or job["conclusion"] != "success":
        raise ValueError("CI evidence producer job did not succeed")
    if (
        evidence.runner_label != os.environ["CI_RUNNER"]
        or evidence.runner_label not in job["labels"]
    ):
        raise ValueError("CI evidence ran on a different runner")
    completed = datetime.fromisoformat(job["completed_at"].replace("Z", "+00:00"))
    age = datetime.now(UTC) - completed
    if age < timedelta(0) or age > FRESHNESS:
        raise ValueError("CI evidence is outside the freshness window")
    required = requirements(kind, check_id)
    steps = {step["name"]: step["conclusion"] for step in job["steps"]}
    if evidence.requirements != required or any(steps.get(name) != "success" for name in required):
        raise ValueError("CI evidence omits a required execution step")
    # Fetch only Git objects, never execute or check out producer-controlled files.
    subprocess.run(
        ["git", "fetch", "--no-tags", "origin", evidence.source_sha],
        cwd=ROOT,
        capture_output=True,
        check=True,
        timeout=45,
    )
    if run["event"] == "pull_request":
        parents = git("show", "-s", "--format=%P", evidence.source_sha).split()
        pull_requests = run.get("pull_requests", [])
        if (
            len(parents) != 2
            or parents[1] != run["head_sha"]
            or (
                pull_requests
                and not any(
                    request["head"]["sha"] == parents[1] and request["base"]["sha"] == parents[0]
                    for request in pull_requests
                )
            )
        ):
            raise ValueError("CI evidence does not identify this PR run's tested merge")
        # GitHub can clear pull_requests after merging. Require the authenticated
        # PR head's inputs to match as well; a merge containing extra base changes
        # conservatively executes fresh rather than trusting a claimed merge SHA.
        if source_digest(run["head_sha"]) != evidence.source_digest:
            raise ValueError("CI evidence differs from the authenticated PR head inputs")
    elif evidence.source_sha != run["head_sha"]:
        raise ValueError("CI evidence does not identify the run's checked-out commit")
    if source_digest(evidence.source_sha) != evidence.source_digest:
        raise ValueError("CI evidence source identity is incorrect")
    validate_shard(evidence)


def validate_shard(evidence: Evidence) -> None:
    """Reject absent or incomplete shard evidence before skipping any execution."""
    if evidence.kind not in {"routine", "slow"}:
        return
    report = evidence.shard
    if report is None or report.tier != evidence.kind:
        raise ValueError("CI evidence is missing the required shard tier")
    if (
        report.exit_code != 0
        or not report.selected
        or not 0 <= report.index < report.count
        or len(report.selected) != len(set(report.selected))
        or not set(report.selected) <= set(report.inventory)
        or set(report.outcomes) != set(report.selected)
        or any(outcome not in {"passed", "skipped"} for outcome in report.outcomes.values())
        or "passed" not in report.outcomes.values()
    ):
        raise ValueError("CI evidence contains an unsuccessful or incomplete shard")
    if "-cov-" in evidence.check_id and not evidence.coverage_sha256:
        raise ValueError("CI coverage evidence is missing its measured coverage data")


def resolve(check_id: str, kind: KINDS, destination: Path) -> bool:
    """Restore eligible successful evidence; unavailable evidence always executes fresh."""
    destination.mkdir(parents=True, exist_ok=True)
    expected = fingerprint(check_id, kind)
    artifact = f"ci-evidence-{check_id}-{expected}"
    output("artifact", artifact)
    output("fingerprint", expected)
    if os.environ.get("CI_FORCE_RUN", "false").lower() == "true":
        output("reused", "false")
        return False
    try:
        candidates = api(
            f"repos/{repository()}/actions/artifacts?name={quote(artifact)}&per_page=10"
        )
        for candidate in candidates["artifacts"]:
            try:
                artifact_record = Artifact.model_validate(candidate)
                if artifact_record.expired:
                    continue
                producer = artifact_record.workflow_run
                if producer.repository_id != producer.head_repository_id:
                    raise ValueError("CI artifact was uploaded by a fork")
                # Bind the upload itself to authenticated source metadata too.
                # Reuploaded reuse records retain their original execution job,
                # so their immediate uploader may legitimately be a later run.
                subprocess.run(
                    ["git", "fetch", "--no-tags", "origin", producer.head_sha],
                    cwd=ROOT,
                    capture_output=True,
                    check=True,
                    timeout=45,
                )
                if source_digest(producer.head_sha) != source_digest():
                    raise ValueError("CI artifact uploader used different tested inputs")
                raw = api(
                    f"repos/{repository()}/actions/artifacts/{artifact_record.id}/zip", binary=True
                )
                if artifact_record.digest != "sha256:" + hashlib.sha256(raw).hexdigest():
                    raise ValueError("CI evidence archive digest mismatch")
                with TemporaryDirectory(prefix="eforge-ci-evidence-") as temporary:
                    temporary_path = Path(temporary)
                    evidence = unpack_evidence(raw, temporary_path)
                    verify_origin(evidence, expected, check_id, kind)
                    if evidence.coverage_sha256:
                        shutil.copyfile(
                            temporary_path / "coverage.data", destination / "coverage.data"
                        )
                (destination / "evidence.json").write_text(
                    evidence.model_dump_json(indent=2) + "\n", encoding="utf-8"
                )
                summary = os.environ.get("GITHUB_STEP_SUMMARY")
                if summary:
                    with Path(summary).open("a", encoding="utf-8") as stream:
                        stream.write(
                            f"Reused **{check_id}** from [verified job](https://github.com/{repository()}/actions/runs/{evidence.run_id}/job/{evidence.job_id}).\n"
                        )
                output("reused", "true")
                return True
            except (
                OSError,
                ValueError,
                KeyError,
                TypeError,
                subprocess.SubprocessError,
                zipfile.BadZipFile,
            ):
                continue
    except (OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError):
        print("No eligible CI evidence could be verified; running the check fresh.")
    output("reused", "false")
    return False


def record(check_id: str, kind: KINDS, destination: Path) -> None:
    """Record executed results; a reused record retains its original provenance."""
    if (destination / "evidence.json").exists():
        return
    jobs = api(f"repos/{repository()}/actions/runs/{os.environ['GITHUB_RUN_ID']}/jobs?per_page=100")
    expected_name = os.environ["CI_JOB_NAME"]
    matches = [
        job
        for job in jobs["jobs"]
        if (job["name"] == expected_name or job["name"].endswith(" / " + expected_name))
        and job["status"] == "in_progress"
        and job["runner_name"] == os.environ["RUNNER_NAME"]
        and os.environ["CI_RUNNER"] in job["labels"]
    ]
    if len(matches) != 1:
        raise ValueError("Cannot identify the exact CI producer job")
    report = destination / "shard.json"
    coverage = destination / "coverage.data"
    evidence = Evidence(
        repository=repository(),
        check_id=check_id,
        kind=kind,
        fingerprint=fingerprint(check_id, kind),
        source_digest=source_digest(),
        source_sha=git("rev-parse", "HEAD"),
        run_id=int(os.environ["GITHUB_RUN_ID"]),
        runner_label=os.environ["CI_RUNNER"],
        attempt=int(os.environ["GITHUB_RUN_ATTEMPT"]),
        job_id=matches[0]["id"],
        requirements=requirements(kind, check_id),
        shard=json_report(report) if report.exists() else None,
        coverage_sha256=hashlib.sha256(coverage.read_bytes()).hexdigest()
        if coverage.exists()
        else None,
    )
    validate_shard(evidence)
    if subprocess.run(["git", "diff", "--quiet", "HEAD"], cwd=ROOT, check=False).returncode:
        raise ValueError("CI execution modified tracked source files")
    report.unlink(missing_ok=True)
    (destination / "evidence.json").write_text(
        evidence.model_dump_json(indent=2) + "\n", encoding="utf-8"
    )


def validate_group(
    directory: Path, expected_groups: set[str], *, count: int = 8, coverage: bool = False
) -> None:
    """Require complete executed/reused shard groups before reporting CI success."""
    groups: dict[str, list[Evidence]] = {}
    for path in directory.rglob("evidence.json"):
        evidence = Evidence.model_validate_json(path.read_bytes())
        if evidence.source_digest != source_digest() or evidence.shard is None:
            raise ValueError("CI shard artifact does not match the target source")
        group = evidence.check_id.rsplit("-", 1)[0]
        groups.setdefault(group, []).append(evidence)
        if coverage:
            data = path.with_name("coverage.data")
            if (
                not evidence.coverage_sha256
                or hashlib.sha256(data.read_bytes()).hexdigest() != evidence.coverage_sha256
            ):
                raise ValueError("Missing or corrupt CI shard coverage data")
            target = ROOT / "ci-results" / "coverage" / f".coverage.{evidence.check_id}"
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(data, target)
    if set(groups) != expected_groups:
        raise ValueError(
            "CI shard evidence is missing a required group or includes unexpected groups"
        )
    for items in groups.values():
        if any(item.shard is None or item.shard.count != count for item in items):
            raise ValueError("CI evidence uses an unexpected shard count")
        validate_reports([item.shard for item in items if item.shard is not None])


def main() -> None:
    """Expose source identity, reuse resolution, recording and group validation."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("identity", "resolve", "record", "validate"))
    parser.add_argument("--directory", type=Path)
    parser.add_argument("--coverage", action="store_true")
    parser.add_argument("--expected-group", action="append", default=[])
    parser.add_argument("--count", type=int, default=8)
    args = parser.parse_args()
    if args.command == "identity":
        output("digest", source_digest())
        return
    if args.command == "validate":
        if args.directory is None:
            parser.error("--directory is required for validation")
        if not args.expected_group:
            parser.error("At least one --expected-group is required")
        validate_group(
            args.directory, set(args.expected_group), count=args.count, coverage=args.coverage
        )
        return
    check_id = os.environ["CI_CHECK_ID"]
    if not re.fullmatch(r"[a-z0-9.-]{1,100}", check_id):
        raise ValueError("Invalid CI check identity")
    kind = TypeAdapter(KINDS).validate_python(os.environ["CI_CHECK_KIND"])
    destination = ROOT / "ci-results" / check_id
    if args.command == "resolve":
        resolve(check_id, kind, destination)
    else:
        record(check_id, kind, destination)


if __name__ == "__main__":
    main()
