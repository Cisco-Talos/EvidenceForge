"""Disposable runtime construction and live provider orchestration."""

from __future__ import annotations

import json
import os
import re
import shutil
import signal
import subprocess
import sys
import tempfile
import time
import uuid
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any

import yaml

from .adapters import UnsupportedTranscriptError, parse_transcript
from .cases import (
    EXPERIMENT_ROOT,
    REPOSITORY_ROOT,
    incomplete_requirements,
    load_cases,
    resolve_fixture,
)
from .metrics import aggregate_sessions, calculate_session_metrics, repair_drift
from .models import (
    AcceptanceReport,
    AgentName,
    CaseDefinition,
    InputDigests,
    NormalizedEvent,
    SessionMetrics,
    SessionResult,
    SessionStatus,
    ValidationAttempt,
)
from .reporting import write_report
from .util import canonical_json_bytes, digest_tree, redact_text, sha256_bytes, sha256_file

SUPPORTED_CODEX = re.compile(r"^codex-cli 0\.147\.")
SUPPORTED_CLAUDE = re.compile(r"^2\.1\.")
AGENT_CONTRACTS = {
    AgentName.CODEX: ("gpt-5.6-sol", "medium"),
    AgentName.CLAUDE: ("sonnet", "high"),
}
DEFAULT_TIMEOUT_SECONDS = 2700


@dataclass(frozen=True)
class Runtime:
    """Packaged EvidenceForge runtime shared by disposable session workspaces."""

    root: Path
    wheel: Path
    python: Path
    eforge: Path


def _run_bounded(
    command: list[str],
    *,
    cwd: Path,
    env: dict[str, str],
    timeout: int,
) -> subprocess.CompletedProcess[bytes]:
    process = subprocess.Popen(
        command,
        cwd=cwd,
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        start_new_session=True,
    )
    try:
        stdout, stderr = process.communicate(timeout=timeout)
    except subprocess.TimeoutExpired as exc:
        os.killpg(process.pid, signal.SIGTERM)
        try:
            stdout, stderr = process.communicate(timeout=5)
        except subprocess.TimeoutExpired:
            os.killpg(process.pid, signal.SIGKILL)
            stdout, stderr = process.communicate()
        raise TimeoutError(f"command timed out after {timeout}s: {command[0]}") from exc
    return subprocess.CompletedProcess(command, process.returncode, stdout, stderr)


def _checked(command: list[str], *, cwd: Path, env: dict[str, str], timeout: int = 300) -> bytes:
    result = _run_bounded(command, cwd=cwd, env=env, timeout=timeout)
    if result.returncode:
        message = redact_text(result.stderr.decode("utf-8", errors="replace"))
        raise RuntimeError(
            f"command failed ({result.returncode}): {' '.join(command[:3])}: {message}"
        )
    return result.stdout


def build_runtime(root: Path, env: dict[str, str]) -> Runtime:
    """Build the current wheel and install it into a disposable uv environment."""

    build_dir = root / "wheel"
    build_dir.mkdir(parents=True)
    _checked(["uv", "build", "--wheel", "--out-dir", str(build_dir)], cwd=REPOSITORY_ROOT, env=env)
    wheels = sorted(build_dir.glob("*.whl"))
    if len(wheels) != 1:
        raise RuntimeError(f"expected one built wheel, found {len(wheels)}")
    venv = root / "runtime"
    _checked(["uv", "venv", "--python", sys.executable, str(venv)], cwd=root, env=env)
    python = venv / "bin" / "python"
    _checked(
        ["uv", "pip", "install", "--python", str(python), str(wheels[0])],
        cwd=root,
        env=env,
    )
    return Runtime(root=root, wheel=wheels[0], python=python, eforge=venv / "bin" / "eforge")


def validate_known_good_fixtures(
    runtime: Runtime,
    cases: list[CaseDefinition],
    root: Path,
    env: dict[str, str],
) -> None:
    """Preflight every declared known-good scenario with the packaged wheel."""

    preflight = root / "known-good-preflight"
    preflight.mkdir(parents=True)
    seen: set[str] = set()
    for case in cases:
        if not case.known_good_fixture or case.known_good_fixture in seen:
            continue
        seen.add(case.known_good_fixture)
        source = resolve_fixture(case.known_good_fixture)
        destination = preflight / f"{case.id}.yaml"
        shutil.copy2(source, destination)
        result = _run_bounded(
            [str(runtime.eforge), "validate", str(destination), "--json"],
            cwd=preflight,
            env=env,
            timeout=180,
        )
        if result.returncode:
            error = redact_text(result.stdout.decode("utf-8", errors="replace"))
            raise RuntimeError(f"packaged-wheel known-good preflight failed for {case.id}: {error}")


def _provider_version(agent: AgentName, env: dict[str, str]) -> str:
    executable = agent.value
    result = _run_bounded([executable, "--version"], cwd=REPOSITORY_ROOT, env=env, timeout=30)
    if result.returncode:
        raise RuntimeError(f"{agent.value} --version failed")
    version = result.stdout.decode("utf-8", errors="replace").strip()
    supported = SUPPORTED_CODEX if agent is AgentName.CODEX else SUPPORTED_CLAUDE
    if not supported.match(version):
        raise RuntimeError(f"unsupported {agent.value} CLI version: {version}")
    return version


def _copy_shim(control_root: Path, runtime: Runtime) -> Path:
    shim_dir = control_root / "shim-bin"
    shim_dir.mkdir(parents=True)
    shutil.copy2(EXPERIMENT_ROOT / "shim.py", control_root / "shim.py")
    wrapper = shim_dir / "eforge"
    wrapper.write_text(
        f'#!/bin/sh\nexec {runtime.python} {control_root / "shim.py"} "$@"\n',
        encoding="utf-8",
    )
    wrapper.chmod(0o755)
    return shim_dir


def _install_skills(runtime: Runtime, workspace: Path, env: dict[str, str]) -> None:
    for agent in ("codex", "claude"):
        _checked(
            [str(runtime.eforge), "install-skills", "--agent", agent],
            cwd=workspace,
            env=env,
        )
    skills_root = workspace / ".agents" / "skills"
    for installed in skills_root.glob("eforge-*"):
        if installed.name not in {"eforge-scenario", "eforge-validate"}:
            shutil.rmtree(installed)
    claude_root = workspace / ".claude" / "commands" / "eforge"
    for installed in claude_root.glob("*.md"):
        if installed.name not in {"scenario.md", "validate.md"}:
            installed.unlink()


def _prepare_workspace(
    case: CaseDefinition,
    workspace: Path,
    runtime: Runtime,
    env: dict[str, str],
) -> None:
    workspace.mkdir(parents=True, exist_ok=True)
    _install_skills(runtime, workspace, env)
    (workspace / "CASE_PROMPT.md").write_text(case.prompt.rstrip() + "\n", encoding="utf-8")
    if case.starting_fixture:
        source = resolve_fixture(case.starting_fixture)
        destination = workspace / case.scenario_path
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(source, destination)


def _agent_prompt(case: CaseDefinition, agent: AgentName) -> str:
    skill = "eforge-validate" if case.mode == "repair" else "eforge-scenario"
    invocation = (
        "Read .claude/commands/eforge/"
        f"{'validate' if case.mode == 'repair' else 'scenario'}.md completely and follow it as "
        "the controlling skill. Resolve every /eforge:references:<name> instruction in that file "
        "to .claude/commands/eforge/references/<name>.md."
        if agent is AgentName.CLAUDE
        else f"Use the installed {skill} skill and its focused references."
    )
    prompt = (
        f"{invocation}\n\n"
        "This is a controlled acceptance workspace. Read CASE_PROMPT.md and perform that task. "
        "You may access only files beneath the current workspace. Use only the instrumented eforge "
        "on PATH; generation, OOB authorization, configuration changes, networking, browsers, MCP, "
        "and release operations are forbidden. Query every required focused schema contract named "
        "by the task before final validation. Keep the authored scenario at the requested path.\n"
    )
    prompt += (
        f"The required focused reference basenames for this case are: "
        f"{', '.join(case.required_references)}. Read each one from the installed skill's "
        "references directory. The required schema selectors are: "
        f"{', '.join(case.required_schema_selectors)}. Query every selector with "
        "`eforge schema <selector> --json`. These are explicit conformance requirements, not "
        "hidden evaluator expectations. "
        f"Write the final authored document at exactly ./{case.scenario_path}; do not substitute "
        "a nested scenario directory or another filename.\n"
    )
    if case.scripted_answers:
        prompt += (
            "\nThe evaluator supplies the complete scripted interview answers below. Treat them "
            "as the answers to your normal guided questions, preserve their order, and do not ask "
            "a question already answered:\n"
        )
        for index, answer in enumerate(case.scripted_answers, start=1):
            prompt += f"Answer {index}: {answer}\n"
    return prompt


def _codex_command(workspace: Path, prompt: str) -> list[str]:
    return [
        "codex",
        "exec",
        "--json",
        "--ephemeral",
        "--ignore-user-config",
        "--ignore-rules",
        "--skip-git-repo-check",
        "--approve-for-me",
        "--model",
        "gpt-5.6-sol",
        "--config",
        'model_reasoning_effort="medium"',
        "--cd",
        str(workspace),
        prompt,
    ]


def _claude_command(prompt: str) -> list[str]:
    settings = json.dumps(
        {
            "permissions": {
                "allow": ["Read", "Write", "Edit", "Bash(eforge *)"],
                "deny": ["WebFetch", "WebSearch", "NotebookEdit"],
            },
            "disableAllHooks": True,
        }
    )
    return [
        "claude",
        "--print",
        "--verbose",
        "--output-format",
        "stream-json",
        "--no-session-persistence",
        "--no-chrome",
        "--setting-sources",
        "project",
        "--strict-mcp-config",
        "--mcp-config",
        '{"mcpServers":{}}',
        "--settings",
        settings,
        "--tools",
        "Read,Write,Edit,Bash",
        "--permission-mode",
        "acceptEdits",
        "--model",
        "sonnet",
        "--effort",
        "high",
        prompt,
    ]


def _last_message(events: list[NormalizedEvent]) -> str:
    messages = [event.output for event in events if event.kind == "message" and event.output]
    return messages[-1] if messages else ""


def _provider_run(
    agent: AgentName,
    *,
    workspace: Path,
    prompt: str,
    transcript: Path,
    env: dict[str, str],
    timeout: int,
) -> tuple[list[NormalizedEvent], int]:
    command = (
        _codex_command(workspace, prompt) if agent is AgentName.CODEX else _claude_command(prompt)
    )
    result = _run_bounded(command, cwd=workspace, env=env, timeout=timeout)
    transcript.parent.mkdir(parents=True, exist_ok=True)
    transcript.write_text(
        redact_text(result.stdout.decode("utf-8", errors="replace")), encoding="utf-8"
    )
    stderr_path = transcript.with_suffix(".stderr.txt")
    stderr_path.write_text(
        redact_text(result.stderr.decode("utf-8", errors="replace")), encoding="utf-8"
    )
    if result.returncode and not result.stdout.strip():
        raise RuntimeError(
            f"{agent.value} exited with status {result.returncode}: "
            f"{redact_text(result.stderr.decode('utf-8', errors='replace'))}"
        )
    events = parse_transcript(agent, transcript)
    return events, result.returncode


def _load_trace(path: Path) -> list[dict[str, Any]]:
    if not path.exists():
        return []
    records: list[dict[str, Any]] = []
    for line in path.read_text(encoding="utf-8").splitlines():
        value = json.loads(line)
        if value.get("event_schema_version") != "1.0" or value.get("kind") != "eforge_command":
            raise ValueError("unsupported eforge trace event")
        records.append(value)
    return records


def _persist_live_artifacts(source_root: Path, destination_root: Path) -> None:
    """Copy shim-owned artifacts out of the disposable provider workspace."""

    if not source_root.is_dir():
        return
    destination_root.mkdir(parents=True, exist_ok=True)
    for source in source_root.iterdir():
        destination = destination_root / source.name
        if source.is_dir():
            shutil.copytree(source, destination, dirs_exist_ok=True)
        else:
            shutil.copy2(source, destination)


def _issue_key(issue: dict[str, Any]) -> str:
    return (
        f"{issue.get('code', issue.get('severity', 'unknown'))}:"
        f"{issue.get('field_path', '')}:{issue.get('message', '')}"
    )


def _validation_attempts(
    records: list[dict[str, Any]], case: CaseDefinition, artifact_root: Path
) -> list[ValidationAttempt]:
    attempts: list[ValidationAttempt] = []
    for record in records:
        argv = record.get("argv", [])
        if not argv or argv[0] != "validate" or not record.get("allowed"):
            continue
        digest = record.get("scenario_digest")
        complete = False
        if digest:
            matches = list((artifact_root / "snapshots").glob(f"*-{digest}.yaml"))
            if matches:
                try:
                    document = yaml.safe_load(matches[0].read_text(encoding="utf-8"))
                    complete = isinstance(document, dict) and not incomplete_requirements(
                        document, case
                    )
                except yaml.YAMLError:
                    complete = False
        try:
            payload = json.loads(record.get("stdout", ""))
        except json.JSONDecodeError:
            payload = {}
        issues = payload.get("issues", []) if isinstance(payload, dict) else []
        errors = sorted(_issue_key(issue) for issue in issues if issue.get("severity") == "error")
        warnings = sorted(
            _issue_key(issue) for issue in issues if issue.get("severity") == "warning"
        )
        attempts.append(
            ValidationAttempt(
                sequence=int(record["sequence"]),
                scenario_digest=digest,
                complete=complete,
                exit_code=int(record["exit_code"]),
                error_keys=errors,
                warning_keys=warnings,
            )
        )
    return attempts


def _observed_references(events: list[NormalizedEvent], case: CaseDefinition) -> set[str]:
    serialized = "\n".join(
        json.dumps(event.input, sort_keys=True) for event in events if event.kind == "tool_call"
    )
    return {reference for reference in case.required_references if reference in serialized}


def _schema_selectors(records: list[dict[str, Any]]) -> set[str]:
    return {
        str(record["argv"][1])
        for record in records
        if record.get("allowed")
        and len(record.get("argv", [])) >= 2
        and record["argv"][0] == "schema"
    }


def _string_values(value: Any) -> list[str]:
    if isinstance(value, str):
        return [value]
    if isinstance(value, dict):
        return [item for child in value.values() for item in _string_values(child)]
    if isinstance(value, list):
        return [item for child in value for item in _string_values(child)]
    return []


def _access_strings(event: NormalizedEvent) -> list[str]:
    """Return only tool fields that can identify filesystem access."""

    values: list[str] = []
    for key, value in event.input.items():
        normalized = key.casefold()
        if normalized in {"command", "file_path", "path", "directory"}:
            values.extend(_string_values(value))
        elif normalized == "changes":
            values.extend(
                str(change["path"])
                for change in value
                if isinstance(change, dict) and isinstance(change.get("path"), str)
            )
    return values


def _ambient_accesses(events: list[NormalizedEvent], workspace: Path) -> list[str]:
    accesses: set[str] = set()
    root = workspace.resolve()
    for event in events:
        if event.kind != "tool_call":
            continue
        for value in _access_strings(event):
            for candidate in re.findall(r"(?:^|\s)(/[^\s'\";&|]+|\.\./[^\s'\";&|]+)", value):
                path = Path(candidate)
                if not path.is_absolute():
                    path = root / path
                try:
                    resolved = path.resolve()
                except OSError:
                    accesses.add(candidate)
                    continue
                system_path = str(resolved).startswith(("/usr/", "/bin/", "/sbin/"))
                if (
                    resolved != root
                    and root not in resolved.parents
                    and not system_path
                    and resolved != Path("/dev/null")
                ):
                    accesses.add(candidate)
    return sorted(accesses)


def _transcript_violations(events: list[NormalizedEvent]) -> list[str]:
    """Detect browser, MCP, and network attempts outside the eforge shim."""

    violations: set[str] = set()
    network_commands = re.compile(r"(^|[;&|]\s*)(curl|wget|ssh|scp|nc|ncat|git\s+clone)\b")
    for event in events:
        if event.kind != "tool_call":
            continue
        tool = (event.tool or "").casefold()
        if "web" in tool or "browser" in tool or "mcp" in tool:
            violations.add(event.tool or "unknown external tool")
        for value in _string_values(event.input):
            if network_commands.search(value):
                violations.add(value)
    return sorted(violations)


def _terminal_validation(
    runtime: Runtime, workspace: Path, case: CaseDefinition, env: dict[str, str]
) -> tuple[bool, bool | None]:
    scenario = workspace / case.scenario_path
    if not scenario.is_file():
        return False, None
    validation = _run_bounded(
        [str(runtime.eforge), "validate", str(scenario), "--json"],
        cwd=workspace,
        env=env,
        timeout=120,
    )
    valid = validation.returncode == 0
    composition: bool | None = None
    if valid and yaml.safe_load(scenario.read_text(encoding="utf-8")).get("composition"):
        resolved = _run_bounded(
            [str(runtime.eforge), "resolve", str(scenario), "--explain-composition", "--json"],
            cwd=workspace,
            env=env,
            timeout=120,
        )
        composition = resolved.returncode == 0
    return valid, composition


def _infrastructure_result(
    case: CaseDefinition,
    agent: AgentName,
    version: str,
    transcript: Path,
    trace: Path,
    final_path: Path,
    error: str,
    duration: float,
) -> SessionResult:
    model, effort = AGENT_CONTRACTS[agent]
    return SessionResult(
        case_id=case.id,
        agent=agent,
        provider_version=version,
        model=model,
        effort=effort,
        status=SessionStatus.INFRASTRUCTURE_ERROR,
        metrics=SessionMetrics(duration_seconds=duration, strict_violations=[]),
        transcript_path=str(transcript),
        trace_path=str(trace),
        final_scenario_path=str(final_path),
        infrastructure_error=error,
    )


def run_session(
    *,
    case: CaseDefinition,
    agent: AgentName,
    version: str,
    runtime: Runtime,
    run_root: Path,
    execution_root: Path,
    base_env: dict[str, str],
    timeout: int,
) -> SessionResult:
    """Run and score one isolated provider/case sample."""

    session_root = run_root / "sessions" / f"{case.id}-{agent.value}"
    workspace = execution_root / f"{case.id}-{agent.value}"
    artifacts = session_root / "artifacts"
    transcript = artifacts / "transcript.jsonl"
    trace = artifacts / "eforge-trace.jsonl"
    started = time.monotonic()
    model, effort = AGENT_CONTRACTS[agent]
    try:
        _prepare_workspace(case, workspace, runtime, base_env)
        control_root = workspace / ".acceptance-control"
        shim_dir = _copy_shim(control_root, runtime)
        live_artifacts = control_root / "artifacts"
        live_trace = live_artifacts / "eforge-trace.jsonl"
        zsh_root = control_root / "zsh"
        zsh_root.mkdir()
        (zsh_root / ".zshenv").write_text(f'export PATH="{shim_dir}:$PATH"\n', encoding="utf-8")
        env = dict(base_env)
        env.update(
            {
                "PATH": f"{shim_dir}:{base_env.get('PATH', '/usr/bin:/bin')}",
                "EFORGE_ACCEPTANCE_WORKSPACE": str(workspace),
                "EFORGE_ACCEPTANCE_ARTIFACTS": str(live_artifacts),
                "EFORGE_ACCEPTANCE_TRACE": str(live_trace),
                "EFORGE_ACCEPTANCE_REAL_EFORGE": str(runtime.eforge),
                "NO_COLOR": "1",
                "ZDOTDIR": str(zsh_root),
            }
        )
        provider_transcript = transcript.with_name("provider-transcript.jsonl")
        all_events, return_code = _provider_run(
            agent,
            workspace=workspace,
            prompt=_agent_prompt(case, agent),
            transcript=provider_transcript,
            env=env,
            timeout=timeout,
        )
        message = _last_message(all_events)
        if return_code:
            raise RuntimeError(f"{agent.value} exited with status {return_code}: {message}")
        _persist_live_artifacts(live_artifacts, artifacts)
        transcript.write_text(
            "\n".join(event.model_dump_json() for event in all_events) + "\n",
            encoding="utf-8",
        )
        records = _load_trace(trace)
        attempts = _validation_attempts(records, case, artifacts)
        final_path = workspace / case.scenario_path
        terminal_valid, terminal_composition = _terminal_validation(
            runtime, workspace, case, base_env
        )
        final_document: dict[str, Any] = {}
        if final_path.is_file():
            loaded = yaml.safe_load(final_path.read_text(encoding="utf-8"))
            final_document = loaded if isinstance(loaded, dict) else {}
        if incomplete_requirements(final_document, case):
            terminal_valid = False
        drift: list[str] = []
        if case.mode == "repair" and case.starting_fixture and final_document:
            initial = yaml.safe_load(
                resolve_fixture(case.starting_fixture).read_text(encoding="utf-8")
            )
            drift = repair_drift(initial, final_document, case.allowed_repair_paths)
        forbidden = [
            " ".join(record.get("argv", []))
            for record in records
            if not record.get("allowed") and record.get("policy_class") == "forbidden"
        ]
        forbidden.extend(_transcript_violations(all_events))
        forbidden = sorted(set(forbidden))
        ambient = _ambient_accesses(all_events, workspace)
        question_counts = [
            (event.output or "").count("?")
            for event in all_events
            if event.kind == "message" and event.output
        ]
        metrics = calculate_session_metrics(
            case=case,
            attempts=attempts,
            events=all_events,
            terminal_valid=terminal_valid,
            terminal_composition_valid=terminal_composition,
            used_references=_observed_references(all_events, case),
            used_schema_selectors=_schema_selectors(records),
            repair_drift_paths=drift,
            forbidden_commands=forbidden,
            ambient_accesses=ambient,
            duration_seconds=time.monotonic() - started,
            interview_turns=len(case.scripted_answers) if case.scripted_answers else 0,
            question_discipline_violations=(sum(question_counts) if case.scripted_answers else 0),
        )
        status = SessionStatus.PASS if not metrics.strict_violations else SessionStatus.FAIL
        final_artifact = artifacts / "final-scenario.yaml"
        if final_path.is_file():
            final_artifact.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(final_path, final_artifact)
        return SessionResult(
            case_id=case.id,
            agent=agent,
            provider_version=version,
            model=model,
            effort=effort,
            status=status,
            metrics=metrics,
            transcript_path=str(transcript),
            transcript_digest=sha256_file(transcript),
            trace_path=str(trace),
            trace_digest=sha256_file(trace) if trace.is_file() else None,
            final_scenario_path=str(final_artifact),
            final_scenario_digest=(
                sha256_file(final_artifact) if final_artifact.is_file() else None
            ),
        )
    except (
        OSError,
        RuntimeError,
        TimeoutError,
        UnsupportedTranscriptError,
        ValueError,
        yaml.YAMLError,
    ) as exc:
        live_artifacts = workspace / ".acceptance-control" / "artifacts"
        _persist_live_artifacts(live_artifacts, artifacts)
        final_path = workspace / case.scenario_path
        final_artifact = artifacts / "final-scenario.yaml"
        if final_path.is_file():
            artifacts.mkdir(parents=True, exist_ok=True)
            shutil.copy2(final_path, final_artifact)
        return _infrastructure_result(
            case,
            agent,
            version,
            transcript,
            trace,
            final_artifact,
            redact_text(str(exc)),
            time.monotonic() - started,
        )


def _git_state(env: dict[str, str]) -> tuple[str, bool]:
    commit = _checked(["git", "rev-parse", "HEAD"], cwd=REPOSITORY_ROOT, env=env).decode().strip()
    status = _checked(["git", "status", "--porcelain"], cwd=REPOSITORY_ROOT, env=env).decode()
    return commit, bool(status.strip())


def run_suite(
    *,
    suite: str,
    agents: list[AgentName],
    report_path: Path,
    timeout: int = DEFAULT_TIMEOUT_SECONDS,
) -> AcceptanceReport:
    """Build, execute, score, and atomically report one suite."""

    cases = load_cases(suite)
    run_id = f"{datetime.now().strftime('%Y%m%dT%H%M%S')}-{uuid.uuid4().hex[:8]}"
    report_path = report_path.resolve()
    run_root = report_path.parent / run_id
    run_root.mkdir(parents=True, exist_ok=False)
    execution_root = Path(tempfile.mkdtemp(prefix=f"eforge-agent-acceptance-{run_id}-")).resolve()
    env = dict(os.environ)
    env.setdefault("UV_CACHE_DIR", str(Path(tempfile.gettempdir()) / "eforge-agent-acceptance-uv"))
    versions = {agent: _provider_version(agent, env) for agent in agents}
    runtime = build_runtime(execution_root / "packaged", env)
    validate_known_good_fixtures(runtime, cases, execution_root, env)
    sessions = [
        run_session(
            case=case,
            agent=agent,
            version=versions[agent],
            runtime=runtime,
            run_root=run_root,
            execution_root=execution_root,
            base_env=env,
            timeout=timeout,
        )
        for case in cases
        for agent in agents
    ]
    commit, dirty = _git_state(env)
    selected_prompts = [case.model_dump(mode="json") for case in cases]
    skill_dirs = [
        session_root
        for session_root in execution_root.glob("*/.agents/skills/eforge-*")
        if session_root.is_dir()
    ]
    skill_digest = sha256_bytes(
        canonical_json_bytes(sorted({digest_tree(path) for path in skill_dirs}))
    )
    inputs = InputDigests(
        suite=sha256_bytes(
            canonical_json_bytes({"suite": suite, "cases": [case.id for case in cases]})
        ),
        prompt=sha256_bytes(canonical_json_bytes(selected_prompts)),
        skill=skill_digest,
        model=sha256_bytes(
            canonical_json_bytes({agent.value: AGENT_CONTRACTS[agent] for agent in agents})
        ),
        provider_cli=sha256_bytes(
            canonical_json_bytes({agent.value: versions[agent] for agent in agents})
        ),
        evidenceforge_wheel=sha256_file(runtime.wheel),
        harness=digest_tree(EXPERIMENT_ROOT),
    )
    report = AcceptanceReport(
        run_id=run_id,
        created_at=datetime.now().astimezone(),
        suite=suite,
        source_commit=commit,
        source_dirty=dirty,
        inputs=inputs,
        sessions=sessions,
        aggregate=aggregate_sessions(sessions),
        report_digest="",
    )
    write_report(report_path, report)
    completed_report = AcceptanceReport.model_validate_json(report_path.read_text(encoding="utf-8"))
    shutil.rmtree(execution_root)
    return completed_report
