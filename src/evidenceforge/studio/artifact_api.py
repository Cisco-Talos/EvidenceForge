"""Optional Studio facade over portable authored artifact services."""

from __future__ import annotations

import asyncio
from collections.abc import Callable
from pathlib import Path
from typing import Any, Literal

from fastapi import Depends, FastAPI, HTTPException
from fastapi.responses import FileResponse
from pydantic import BaseModel, ConfigDict, Field, model_validator
from starlette.background import BackgroundTask

from evidenceforge.artifacts.lifecycle import (
    ArtifactError,
    create_draft,
    inspect_artifact,
    list_versions,
    publish,
    set_artifact_names,
    set_display_name,
    set_release_notes,
    storage_name,
    suggest_version,
    validation_findings,
)
from evidenceforge.artifacts.portable import export_release, import_release
from evidenceforge.artifacts.properties import (
    ArtifactProperties,
    MetadataEdit,
    check_artifact,
    edit_metadata,
    inspect_properties,
)
from evidenceforge.artifacts.removal import AffectedItem
from evidenceforge.models.exceptions import EvidenceForgeError
from evidenceforge.naming import DisplayName
from evidenceforge.schema import LifecycleMetadata
from evidenceforge.studio.assistance import AssistanceError
from evidenceforge.studio.display_names import (
    DescriptionSuggestion,
    DisplayNameContext,
    DisplayNameSuggestion,
    descriptive_context,
    suggest_description,
    suggest_display_name,
)
from evidenceforge.studio.release_notes import (
    ReleaseNotesContext,
    ReleaseNotesPreview,
    notes_context,
    suggest_release_notes,
)
from evidenceforge.utils import load_scenario_source_graph


class ArtifactInfo(BaseModel):
    """Computed file authority; no lifecycle fields are persisted in Studio's database."""

    kind: str
    name: str
    display_name: DisplayName | None = None
    path: Path
    schema_version: str | None = None
    lifecycle: LifecycleMetadata | None = None
    upgrade_available: bool = False
    digest: str
    versions: list[dict[str, Any]] = Field(default_factory=list)
    suggested_version: str | None = None
    name_consumers: list[AffectedItem] = Field(default_factory=list)
    name_review_problems: list[str] = Field(default_factory=list)
    model_config = ConfigDict(extra="forbid")


class ArtifactAction(BaseModel):
    action: Literal[
        "draft",
        "upgrade",
        "publish",
        "notes",
        "recover",
        "display-name",
        "identity",
        "publisher",
        "validate",
    ]
    name: str | None = None
    publisher: str | None = None
    version: str | None = None
    bump: Literal["patch", "minor", "major"] = "patch"
    accept_warnings: bool = False
    notes: str = ""
    display_name: DisplayName | None = None
    expected_digest: str | None = None
    draft_if_needed: bool = Field(
        default=False, description="Create a linked draft when saving a title on a non-draft source"
    )
    model_config = ConfigDict(extra="forbid")


class ArtifactImported(BaseModel):
    path: Path
    findings: list[dict[str, Any]] = Field(default_factory=list)
    model_config = ConfigDict(extra="forbid")


class PropertiesEdit(MetadataEdit):
    """A metadata save requires the exact source reviewed in the popup."""

    expected_digest: str = Field(min_length=1)


class DisplayNameRequest(BaseModel):
    """Suggest for a captured authored source or for an unsaved creation form."""

    item_id: str | None = None
    expected_digest: str | None = None
    context: DisplayNameContext | None = None
    model_config = ConfigDict(extra="forbid")

    @model_validator(mode="after")
    def one_source(self) -> DisplayNameRequest:
        """Require one source, with a reviewed digest for an existing draft."""
        if (self.item_id is None) == (self.context is None):
            raise ValueError("Provide a draft item or creation context")
        if self.item_id is not None and not self.expected_digest:
            raise ValueError("Inspect the source before requesting a suggestion")
        return self


class ReleaseNotesRequest(BaseModel):
    """Request an unsaved preview from a reviewed draft and the current editable notes."""

    item_id: str
    expected_digest: str = Field(min_length=1)
    notes: str = Field(default="", max_length=65536)
    model_config = ConfigDict(extra="forbid")


def register_artifact_routes(
    app: FastAPI, authorized: Callable[..., Any], catalog_source: Callable[..., Any]
) -> None:
    @app.get("/v1/items/{item_id}/properties")
    async def properties(item_id: str, studio: Any = Depends(authorized)) -> ArtifactProperties:
        from evidenceforge.studio.contexts import context_path

        item = catalog_source(item_id, studio)
        try:
            return await asyncio.to_thread(
                inspect_properties,
                item.path,
                project_root=item.workspace,
                candidates=[candidate.path for candidate in studio.store.items(item.workspace)],
                context=context_path(item.path, item.workspace),
            )
        except (EvidenceForgeError, OSError, ValueError) as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from exc

    @app.patch("/v1/items/{item_id}/properties")
    async def save_properties(
        item_id: str, request: PropertiesEdit, studio: Any = Depends(authorized)
    ) -> ArtifactImported:
        item = catalog_source(item_id, studio)
        async with studio.asset_lock:
            try:
                await asyncio.to_thread(
                    edit_metadata,
                    item.path,
                    MetadataEdit.model_validate(
                        request.model_dump(exclude={"expected_digest"}, exclude_unset=True)
                    ),
                    project_root=item.workspace,
                    expected_digest=request.expected_digest,
                )
                await studio.scan()
                await studio.emit(item.id, "artifact.updated", {"path": str(item.path)})
                return ArtifactImported(path=item.path)
            except (EvidenceForgeError, OSError, ValueError) as exc:
                raise HTTPException(status_code=409, detail=str(exc)) from exc

    @app.post("/v1/assist/description")
    async def description_preview(
        request: DisplayNameRequest, studio: Any = Depends(authorized)
    ) -> DescriptionSuggestion:
        if not request.item_id:
            raise HTTPException(status_code=400, detail="Inspect an authored source first")
        item = catalog_source(request.item_id, studio)
        try:
            async with studio.asset_lock:
                if inspect_artifact(item.path)["digest"] != request.expected_digest:
                    raise ArtifactError("source changed after review; inspect it again")
                context = descriptive_context(item.kind, load_scenario_source_graph(item.path).data)
            result = await suggest_description(context, studio.settings.codex_path)
            async with studio.asset_lock:
                if inspect_artifact(item.path)["digest"] != request.expected_digest:
                    raise ArtifactError("source changed during suggestion; inspect it again")
            return result
        except AssistanceError as exc:
            raise HTTPException(status_code=503, detail=str(exc)) from exc
        except (EvidenceForgeError, OSError, ValueError) as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from exc

    """Use the existing authenticated workspace, mutation lock, scanner and recovery contracts."""

    @app.post("/v1/assist/release-notes")
    async def release_notes_preview(
        request: ReleaseNotesRequest, studio: Any = Depends(authorized)
    ) -> ReleaseNotesPreview:
        def checked_draft() -> tuple[Any, dict[str, Any]]:
            item = catalog_source(request.item_id, studio)
            current = inspect_artifact(item.path)
            if current["digest"] != request.expected_digest:
                raise ArtifactError("Source changed while suggesting notes; refresh and try again")
            if (current.get("lifecycle") or {}).get("status") != "draft":
                raise ArtifactError("Create a Schema 3 draft before editing release notes")
            return item, current

        def capture() -> ReleaseNotesContext:
            item, current = checked_draft()
            metadata = LifecycleMetadata.model_validate(current["lifecycle"])
            parent_names = {parent.name for parent in metadata.parents}
            candidates = [
                candidate.path
                for candidate in studio.store.items(item.workspace)
                if candidate.name in parent_names
            ]
            context = descriptive_context(item.kind, load_scenario_source_graph(item.path).data)
            return notes_context(
                item.path, item.workspace, context, metadata.parents, candidates, request.notes
            )

        try:
            async with studio.asset_lock:
                context = await asyncio.to_thread(capture)
            suggestion = await suggest_release_notes(context, studio.settings.codex_path)
            async with studio.asset_lock:
                await asyncio.to_thread(checked_draft)
            return ReleaseNotesPreview(
                release_notes=suggestion.release_notes, findings=context.findings
            )
        except AssistanceError as exc:
            raise HTTPException(status_code=503, detail=str(exc)) from exc
        except (EvidenceForgeError, OSError, ValueError) as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from exc

    @app.post("/v1/assist/display-name")
    async def display_name_preview(
        request: DisplayNameRequest, studio: Any = Depends(authorized)
    ) -> DisplayNameSuggestion:
        def source_context() -> DisplayNameContext:
            item = catalog_source(request.item_id, studio)
            current = inspect_artifact(item.path)
            if current["digest"] != request.expected_digest:
                raise ArtifactError("Source changed while suggesting a name; refresh and try again")
            return descriptive_context(item.kind, load_scenario_source_graph(item.path).data)

        try:
            context = request.context
            if request.item_id is not None:
                async with studio.asset_lock:
                    context = await asyncio.to_thread(source_context)
            assert context is not None
            suggestion = await suggest_display_name(context, studio.settings.codex_path)
            if request.item_id is not None:
                async with studio.asset_lock:
                    await asyncio.to_thread(source_context)
            return suggestion
        except AssistanceError as exc:
            raise HTTPException(status_code=503, detail=str(exc)) from exc
        except (EvidenceForgeError, OSError, ValueError) as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from exc

    @app.get("/v1/artifacts/inspect")
    async def inspect(path: Path, studio: Any = Depends(authorized)) -> ArtifactInfo:
        try:
            raw = await asyncio.to_thread(inspect_artifact, path)
            return ArtifactInfo(
                kind=raw["kind"],
                name=raw["name"],
                display_name=raw.get("display_name"),
                path=path,
                schema_version=raw.get("schema_version", "3.0"),
                lifecycle=raw.get("lifecycle"),
                digest=raw["digest"],
            )
        except (EvidenceForgeError, OSError, ValueError) as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from exc

    @app.get("/v1/items/{item_id}/lifecycle")
    async def lifecycle(
        item_id: str, names: bool = False, studio: Any = Depends(authorized)
    ) -> ArtifactInfo:
        item = catalog_source(item_id, studio)
        try:
            raw = await asyncio.to_thread(inspect_artifact, item.path)
            metadata = raw.get("lifecycle")
            versions = []
            suggested_version = None
            name_consumers = []
            name_review_problems = []
            if names and item.kind != "scenario":
                from evidenceforge.studio.pack_lifecycle import review_pack_identity

                items = studio.store.items(item.workspace)
                review = await asyncio.to_thread(
                    review_pack_identity,
                    item.path,
                    item.workspace,
                    [candidate.path for candidate in items if candidate.kind == "scenario"],
                    [
                        candidate.path
                        for candidate in items
                        if candidate.kind == "organization_pack"
                    ],
                )
                name_consumers = review.affected
                name_review_problems = review.problems
            if metadata and metadata.get("status") == "draft":
                from evidenceforge.composition.publisher import effective_publisher

                configured, _ = effective_publisher(item.workspace, required=False)
                publisher = metadata.get("publisher") or (
                    configured.publisher if configured else None
                )
                if publisher:
                    suggested_version = await asyncio.to_thread(
                        suggest_version,
                        item.workspace,
                        kind=raw["kind"],
                        name=raw["name"],
                        publisher=publisher,
                    )
            if metadata and metadata.get("publisher"):
                versions = await asyncio.to_thread(
                    list_versions,
                    item.workspace,
                    kind=raw["kind"],
                    name=raw["name"],
                    publisher=metadata["publisher"],
                )
            return ArtifactInfo(
                kind=raw["kind"],
                name=raw["name"],
                display_name=raw.get("display_name"),
                path=item.path,
                schema_version=raw.get("schema_version", "3.0" if metadata else None),
                lifecycle=metadata,
                upgrade_available=raw.get("upgrade_available", False),
                digest=raw["digest"],
                versions=versions,
                suggested_version=suggested_version,
                name_consumers=name_consumers,
                name_review_problems=name_review_problems,
            )
        except (EvidenceForgeError, OSError, ValueError) as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from exc

    @app.post("/v1/items/{item_id}/lifecycle")
    async def action(
        item_id: str, request: ArtifactAction, studio: Any = Depends(authorized)
    ) -> ArtifactImported:
        item = catalog_source(item_id, studio)
        async with studio.asset_lock:
            try:
                findings = []
                if request.expected_digest and request.action != "recover":
                    if inspect_artifact(item.path)["digest"] != request.expected_digest:
                        raise ArtifactError("source changed after review; inspect it again")
                if request.action in {"draft", "upgrade", "recover", "publisher"}:
                    result = await asyncio.to_thread(
                        create_draft,
                        item.path,
                        project_root=item.workspace,
                        name=request.name,
                        publisher=request.publisher,
                        display_name=request.display_name,
                        upgrade=request.action == "upgrade",
                        recover=request.action == "recover",
                    )
                    if request.action == "upgrade":
                        findings = await asyncio.to_thread(
                            validation_findings, result, project_root=item.workspace
                        )
                elif request.action == "identity":
                    if not request.name or not request.expected_digest:
                        raise ArtifactError("Inspect the source and provide its new identifier")
                    result = await asyncio.to_thread(
                        set_artifact_names,
                        item.path,
                        request.name,
                        request.display_name,
                        project_root=item.workspace,
                        expected_digest=request.expected_digest,
                    )
                elif request.action == "display-name":
                    current = await asyncio.to_thread(inspect_artifact, item.path)
                    result = item.path
                    if (
                        request.draft_if_needed
                        and (current.get("lifecycle") or {}).get("status") != "draft"
                    ):
                        if not request.expected_digest:
                            raise ArtifactError("Inspect the source before changing its title")
                        result = await asyncio.to_thread(
                            create_draft,
                            item.path,
                            project_root=item.workspace,
                            display_name=request.display_name,
                        )
                    await asyncio.to_thread(
                        set_display_name,
                        result,
                        request.display_name,
                        expected_digest=request.expected_digest if result == item.path else None,
                    )
                elif request.action == "notes":
                    await asyncio.to_thread(
                        set_release_notes,
                        item.path,
                        request.notes,
                        expected_digest=request.expected_digest,
                    )
                    result = item.path
                elif request.action == "validate":
                    from evidenceforge.studio.contexts import context_path

                    checked = await asyncio.to_thread(
                        check_artifact,
                        item.path,
                        project_root=item.workspace,
                        context=context_path(item.path, item.workspace),
                    )
                    findings = checked["findings"]
                    result = item.path
                else:
                    from evidenceforge.studio.contexts import context_path

                    result = await asyncio.to_thread(
                        publish,
                        item.path,
                        project_root=item.workspace,
                        version=request.version,
                        bump=request.bump,
                        accept_warnings=request.accept_warnings,
                        context=context_path(item.path, item.workspace),
                    )
                await studio.scan()
                found = next(
                    (
                        candidate
                        for candidate in studio.store.items(item.workspace)
                        if candidate.path == result
                    ),
                    None,
                )
                if found is not None and found.project_id is None and item.project_id is not None:
                    found.project_id = item.project_id
                    studio.store.save_item(found)
                await studio.emit(item.id, "artifact.updated", {"path": str(result)})
                return ArtifactImported(path=result, findings=findings)
            except (EvidenceForgeError, OSError, ValueError) as exc:
                raise HTTPException(status_code=409, detail=str(exc)) from exc

    @app.get("/v1/items/{item_id}/release")
    async def export(item_id: str, studio: Any = Depends(authorized)) -> FileResponse:
        import shutil
        import tempfile

        item = catalog_source(item_id, studio)
        temporary = Path(tempfile.mkdtemp(prefix="studio-release-")).resolve()
        try:
            extension = ".efscenario" if item.kind == "scenario" else ".efpack"
            target = temporary / f"{storage_name(item.name)}-{item.version}{extension}"
            await asyncio.to_thread(export_release, item.path, target)
            return FileResponse(
                target, filename=target.name, background=BackgroundTask(shutil.rmtree, temporary)
            )
        except (ArtifactError, OSError, ValueError) as exc:
            shutil.rmtree(temporary)
            raise HTTPException(status_code=409, detail=str(exc)) from exc

    @app.post("/v1/artifacts/import")
    async def import_artifact(
        request: ArtifactImported, studio: Any = Depends(authorized)
    ) -> ArtifactImported:
        async with studio.asset_lock:
            try:
                result = await asyncio.to_thread(
                    import_release, request.path, project_root=studio.settings.workspace
                )
                await studio.scan()
                await studio.emit("library", "artifact.imported", {"path": str(result)})
                return ArtifactImported(path=result)
            except (EvidenceForgeError, OSError, ValueError) as exc:
                raise HTTPException(status_code=409, detail=str(exc)) from exc
