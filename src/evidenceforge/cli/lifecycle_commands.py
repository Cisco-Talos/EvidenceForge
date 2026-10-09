"""Shared GUI-free authored lifecycle commands for both scenario and pack groups."""

from __future__ import annotations

import difflib
import json
from collections.abc import Callable
from pathlib import Path
from typing import Any

import typer

from evidenceforge.artifacts.lifecycle import (
    _capture_sources,
    _parent,
    create_draft,
    create_new_draft,
    inspect_artifact,
    list_drafts,
    list_versions,
    publish,
    resolve_reference,
    set_artifact_names,
    set_display_name,
    set_release_notes,
    suggest_version,
    validation_findings,
)
from evidenceforge.artifacts.portable import export_release, import_release
from evidenceforge.artifacts.promotion import promote_dependency
from evidenceforge.models.exceptions import EvidenceForgeError

scenario_app = typer.Typer(help="Manage portable scenario drafts and immutable published versions.")


@scenario_app.command("bundle-properties")
def bundle_properties(
    path: Path,
    json_output: bool = typer.Option(False, "--json"),
) -> None:
    """Inspect captured bundle provenance, log formats and aggregate on-disk data sizes."""
    from evidenceforge.artifacts.bundle_properties import inspect_bundle_properties

    _emit(lambda: inspect_bundle_properties(path.resolve()).model_dump(mode="json"), json_output)


@scenario_app.command("delete")
def delete_scenario(
    source: str,
    revision: str | None = typer.Option(
        None, "--revision", help="Accept this exact deletion review; omit to review only."
    ),
    project_root: Path | None = typer.Option(None, "--project-root"),
    json_output: bool = typer.Option(False, "--json"),
    include_files: bool = typer.Option(
        False,
        "--include-files",
        help="Delete the exclusive source folder and all files inside it permanently.",
    ),
) -> None:
    """Review or permanently delete a scenario; export anything you want to keep first."""
    from evidenceforge.artifacts.removal import remove_scenario, review_scenario_deletion

    def operation() -> dict[str, Any]:
        root = _root(project_root)
        path = resolve_reference(source, root)
        result = (
            review_scenario_deletion(path, root, include_files=include_files)
            if revision is None
            else remove_scenario(path, root, revision, include_files=include_files)
        )
        return result.model_dump(mode="json")

    _emit(operation, json_output)


def _emit(operation: Callable[[], Any], json_output: bool) -> Any:
    try:
        result = operation()
        payload = {"path": str(result)} if isinstance(result, Path) else result
        typer.echo(
            json.dumps(payload, indent=2, sort_keys=True)
            if json_output
            else (str(result) if isinstance(result, Path) else json.dumps(payload, indent=2))
        )
        return result
    except (EvidenceForgeError, OSError, ValueError) as exc:
        typer.echo(json.dumps({"error": str(exc)}) if json_output else f"Error: {exc}")
        raise typer.Exit(1) from exc


def _root(project_root: Path | None) -> Path:
    return project_root.resolve() if project_root is not None else Path.cwd()


def register_lifecycle_commands(app: typer.Typer, *, pack: bool = False) -> None:
    """Expose exactly the same file services through either artifact command group."""

    @app.command("properties")
    def properties(
        source: str,
        project_root: Path | None = typer.Option(None, "--project-root"),
        context: Path | None = typer.Option(None, "--context"),
        json_output: bool = typer.Option(False, "--json"),
    ) -> None:
        """Inspect authored metadata, available note history and exact validation provenance."""
        from evidenceforge.artifacts.properties import inspect_properties

        root = _root(project_root)
        _emit(
            lambda: inspect_properties(
                resolve_reference(source, root),
                project_root=root,
                context=context,
                candidates=[Path(draft["path"]) for draft in list_drafts(root)],
            ).model_dump(mode="json"),
            json_output,
        )

    @app.command("edit-properties")
    def edit_properties(
        source: str,
        changes: Path = typer.Option(
            ..., "--changes", help="JSON object with only the fields to edit."
        ),
        expected_digest: str = typer.Option(..., "--expected-digest"),
        project_root: Path | None = typer.Option(None, "--project-root"),
        json_output: bool = typer.Option(False, "--json"),
    ) -> None:
        """Save reviewed draft display_name, description and release_notes together."""
        from evidenceforge.artifacts.properties import MetadataEdit, edit_metadata

        root = _root(project_root)

        def operation() -> Path:
            path = resolve_reference(source, root)
            edit_metadata(
                path,
                MetadataEdit.model_validate_json(changes.read_bytes()),
                project_root=root,
                expected_digest=expected_digest,
            )
            return path

        _emit(operation, json_output)

    @app.command("check")
    def check(
        source: str,
        project_root: Path | None = typer.Option(None, "--project-root"),
        context: Path | None = typer.Option(None, "--context"),
        json_output: bool = typer.Option(False, "--json"),
    ) -> None:
        """Canonically validate exact authored inputs and retain a file-based engine record."""
        from evidenceforge.artifacts.properties import check_artifact

        root = _root(project_root)
        result = _emit(
            lambda: check_artifact(
                resolve_reference(source, root), project_root=root, context=context
            ),
            json_output,
        )
        if not result["valid"]:
            raise typer.Exit(2)

    @app.command("rename")
    def rename(
        source: str,
        name: str,
        display_name: str | None = typer.Option(None, "--display-name"),
        expected_digest: str = typer.Option(..., "--expected-digest"),
        project_root: Path | None = typer.Option(None, "--project-root"),
        json_output: bool = typer.Option(False, "--json"),
    ) -> None:
        """Rename a draft or create a linked draft from a release; retain existing references."""
        root = _root(project_root)

        def operation() -> Path:
            path = resolve_reference(source, root)
            title = (
                inspect_artifact(path).get("display_name") if display_name is None else display_name
            )
            return set_artifact_names(
                path, name, title, project_root=root, expected_digest=expected_digest
            )

        _emit(operation, json_output)

    @app.command("new-draft")
    def new_draft(
        name: str,
        kind: str = typer.Option("industry" if pack else "scenario", "--kind"),
        description: str = typer.Option("New authored draft", "--description"),
        display_name: str | None = typer.Option(None, "--display-name"),
        project_root: Path | None = typer.Option(None, "--project-root"),
        json_output: bool = typer.Option(False, "--json"),
    ) -> None:
        """Create a draft scaffold without publisher configuration or a release version."""

        def operation() -> Path:
            if kind not in {"scenario", "industry", "organization"}:
                raise ValueError("choose scenario, industry or organization")
            return create_new_draft(
                kind,
                name,
                description=description,
                project_root=_root(project_root),
                display_name=display_name,
            )

        _emit(operation, json_output)

    @app.command("promote-dependency")
    def promote(
        source: str,
        release: str,
        draft_id: str = typer.Option(..., "--draft-id"),
        apply: bool = typer.Option(
            False, "--apply", help="Accept the reviewed reference and namespace conversion."
        ),
        project_root: Path | None = typer.Option(None, "--project-root"),
        json_output: bool = typer.Option(False, "--json"),
    ) -> None:
        """Preview dependency promotion; use --apply only after reviewing the changes."""
        root = _root(project_root)
        _emit(
            lambda: promote_dependency(
                resolve_reference(source, root),
                resolve_reference(release, root),
                project_root=root,
                draft_id=draft_id,
                apply=apply,
            ),
            json_output,
        )

    @app.command("draft")
    def draft(
        source: str,
        destination: Path | None = typer.Option(None, "--destination"),
        name: str | None = typer.Option(None, "--name"),
        display_name: str | None = typer.Option(None, "--display-name"),
        publisher: str | None = typer.Option(None, "--publisher"),
        parent: list[str] = typer.Option(
            [], "--parent", help="Record additional exact parents; no content merge."
        ),
        recover: bool = typer.Option(
            False, "--recover", help="Recover modified published sources into a new draft."
        ),
        project_root: Path | None = typer.Option(None, "--project-root"),
        json_output: bool = typer.Option(False, "--json"),
    ) -> None:
        """Create an independent editable draft, preserving the source and ancestry."""
        root = _root(project_root)
        _emit(
            lambda: create_draft(
                Path(source) if recover else resolve_reference(source, root),
                project_root=root,
                destination=destination,
                name=name,
                display_name=display_name,
                publisher=publisher,
                recover=recover,
                additional_parents=[_parent(resolve_reference(value, root)) for value in parent],
            ),
            json_output,
        )

    @app.command("resume")
    def resume(
        source: str,
        project_root: Path | None = typer.Option(None, "--project-root"),
        json_output: bool = typer.Option(False, "--json"),
    ) -> None:
        """Find the same draft for another editing session without allocating a release."""

        def operation() -> dict[str, Any]:
            info = inspect_artifact(resolve_reference(source, _root(project_root)))
            if not info.get("lifecycle") or info["lifecycle"]["status"] != "draft":
                raise ValueError("resume requires a draft; use draft to edit a published release")
            return info

        _emit(operation, json_output)

    @app.command("upgrade")
    def upgrade(
        source: str,
        destination: Path | None = typer.Option(None, "--destination"),
        project_root: Path | None = typer.Option(None, "--project-root"),
        json_output: bool = typer.Option(False, "--json"),
    ) -> None:
        """Upgrade a supported older schema into a linked draft; preserve the original."""
        root = _root(project_root)

        def operation() -> dict[str, Any]:
            path = create_draft(
                resolve_reference(source, root),
                project_root=root,
                destination=destination,
                upgrade=True,
            )
            return {"path": str(path), "findings": validation_findings(path, project_root=root)}

        _emit(operation, json_output)

    @app.command("publish")
    def publish_command(
        source: str,
        version: str | None = typer.Option(None, "--version", help="Exact X.Y.Z release label."),
        bump: str = typer.Option(
            "patch", "--bump", help="patch, minor or major; suggests an unused label."
        ),
        accept_warnings: bool = typer.Option(
            False,
            "--accept-warnings",
            help="Acknowledge the reported canonical validation warnings.",
        ),
        context: Path | None = typer.Option(None, "--context"),
        oob_host: list[str] = typer.Option([], "--oob-host"),
        project_root: Path | None = typer.Option(None, "--project-root"),
        json_output: bool = typer.Option(False, "--json"),
    ) -> None:
        """Validate and freeze a local release; distribution is a separate export."""
        root = _root(project_root)

        def operation() -> Path:
            if bump not in {"patch", "minor", "major"}:
                raise ValueError("--bump must be patch, minor or major")
            return publish(
                resolve_reference(source, root),
                project_root=root,
                version=version,
                bump=bump,
                context=context,
                accept_warnings=accept_warnings,
                oob_hosts=tuple(oob_host),
            )

        _emit(operation, json_output)

    @app.command("inspect-artifact" if pack else "inspect")
    def inspect(
        source: str,
        project_root: Path | None = typer.Option(None, "--project-root"),
        json_output: bool = typer.Option(False, "--json"),
    ) -> None:
        """Inspect release identity, schema, notes, lineage and complete integrity."""
        _emit(lambda: inspect_artifact(resolve_reference(source, _root(project_root))), json_output)

    @app.command("versions")
    def versions(
        publisher: str,
        name: str,
        kind: str = typer.Option("industry" if pack else "scenario", "--kind"),
        project_root: Path | None = typer.Option(None, "--project-root"),
        json_output: bool = typer.Option(False, "--json"),
    ) -> None:
        """Browse exact published versions without requiring ancestor availability."""

        def operation() -> list[dict[str, Any]]:
            if kind not in {"scenario", "industry", "organization"}:
                raise ValueError("--kind must be scenario, industry or organization")
            return list_versions(_root(project_root), publisher=publisher, name=name, kind=kind)

        _emit(operation, json_output)

    @app.command("drafts")
    def drafts(
        kind: str | None = typer.Option(None, "--kind"),
        project_root: Path | None = typer.Option(None, "--project-root"),
        json_output: bool = typer.Option(False, "--json"),
    ) -> None:
        """Find existing drafts, including those with repairable validation findings."""

        def operation() -> list[dict[str, Any]]:
            selected = (None if pack else "scenario") if kind is None else kind
            if selected not in {None, "scenario", "industry", "organization"}:
                raise ValueError("--kind must be scenario, industry or organization")
            return [
                item
                for item in list_drafts(_root(project_root), kind=selected)
                if not pack or item.get("kind") != "scenario"
            ]

        _emit(operation, json_output)

    @app.command("suggest-version")
    def suggest(
        source: str,
        bump: str = typer.Option("patch", "--bump"),
        project_root: Path | None = typer.Option(None, "--project-root"),
        json_output: bool = typer.Option(False, "--json"),
    ) -> None:
        """Review an unused publication label without allocating it to the draft."""
        root = _root(project_root)

        def operation() -> dict[str, str]:
            from evidenceforge.composition.publisher import effective_publisher

            info = inspect_artifact(resolve_reference(source, root))
            configured, _ = effective_publisher(root, required=True)
            assert configured is not None
            publisher = (info.get("lifecycle") or {}).get("publisher") or configured.publisher
            if bump not in {"patch", "minor", "major"}:
                raise ValueError("--bump must be patch, minor or major")
            return {
                "version": suggest_version(
                    root, kind=info["kind"], name=info["name"], publisher=publisher, bump=bump
                )
            }

        _emit(operation, json_output)

    @app.command("export")
    def export(
        source: str,
        destination: Path,
        project_root: Path | None = typer.Option(None, "--project-root"),
        json_output: bool = typer.Option(False, "--json"),
    ) -> None:
        """Export a verified portable release without logs or checkpoints."""
        _emit(
            lambda: export_release(resolve_reference(source, _root(project_root)), destination),
            json_output,
        )

    @app.command("import-release")
    def import_command(
        source: Path,
        project_root: Path | None = typer.Option(None, "--project-root"),
        json_output: bool = typer.Option(False, "--json"),
    ) -> None:
        """Import an immutable portable release, rejecting identity/content collisions."""
        _emit(lambda: import_release(source, project_root=_root(project_root)), json_output)

    @app.command("display-name")
    def display_name_command(
        source: str,
        value: str | None = typer.Option(None, "--value"),
        clear: bool = typer.Option(False, "--clear"),
        project_root: Path | None = typer.Option(None, "--project-root"),
        json_output: bool = typer.Option(False, "--json"),
    ) -> None:
        """Set or clear a draft title; preserve its exact case-sensitive identifier."""

        def operation() -> dict[str, Any]:
            if clear == (value is not None):
                raise ValueError("choose either --value or --clear")
            target = resolve_reference(source, _root(project_root))
            set_display_name(target, None if clear else value)
            return inspect_artifact(target)

        _emit(operation, json_output)

    @app.command("notes")
    def notes(
        source: str,
        file: Path = typer.Option(..., "--file"),
        project_root: Path | None = typer.Option(None, "--project-root"),
        json_output: bool = typer.Option(False, "--json"),
    ) -> None:
        """Accept user-reviewed notes from a UTF-8 file without publishing."""

        def operation() -> dict[str, Any]:
            target = resolve_reference(source, _root(project_root))
            set_release_notes(target, file.read_text(encoding="utf-8"))
            return inspect_artifact(target)

        _emit(operation, json_output)

    @app.command("compare")
    def compare(
        source: str,
        other: str,
        project_root: Path | None = typer.Option(None, "--project-root"),
        json_output: bool = typer.Option(False, "--json"),
    ) -> None:
        """Compare authored sources for release-note drafting and lineage review."""

        def operation() -> dict[str, Any]:
            root = _root(project_root)
            left = resolve_reference(source, root)
            right = resolve_reference(other, root)
            left_info, right_info = inspect_artifact(left), inspect_artifact(right)
            left_files, _, _ = _capture_sources(
                left, "scenario" if left_info["kind"] == "scenario" else "pack"
            )
            right_files, _, _ = _capture_sources(
                right, "scenario" if right_info["kind"] == "scenario" else "pack"
            )
            diffs = {}
            for name in sorted(set(left_files) | set(right_files)):
                if left_files.get(name) == right_files.get(name):
                    continue
                try:
                    diffs[name] = "".join(
                        difflib.unified_diff(
                            left_files.get(name, b"").decode().splitlines(True),
                            right_files.get(name, b"").decode().splitlines(True),
                            fromfile=name,
                            tofile=name,
                        )
                    )
                except UnicodeError:
                    diffs[name] = "Binary asset changed"
            return {
                "diffs": diffs,
                "source": left_info,
                "other": inspect_artifact(right),
                "diff": "".join(
                    difflib.unified_diff(
                        left.read_text().splitlines(True),
                        right.read_text().splitlines(True),
                        fromfile=str(left),
                        tofile=str(right),
                    )
                ),
            }

        _emit(operation, json_output)


register_lifecycle_commands(scenario_app)
