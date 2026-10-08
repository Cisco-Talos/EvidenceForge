"""Bounded optional AI previews shared by Studio's small suggestion actions."""

from __future__ import annotations

import asyncio
import logging
import tempfile
from pathlib import Path
from typing import Any

from pydantic import BaseModel, ValidationError

from evidenceforge.models.exceptions import EvidenceForgeError
from evidenceforge.studio.codex import CodexClient, CodexUnavailableError

logger = logging.getLogger(__name__)


class AssistanceError(EvidenceForgeError):
    """An optional preview failed; manual authoring remains available."""


PREVIEW_CONFIG = (
    "features.apps=false",
    "features.plugins=false",
    "features.hooks=false",
    "features.shell_tool=false",
    "features.unified_exec=false",
    "features.multi_agent=false",
    "features.browser_use=false",
    "features.computer_use=false",
    "features.code_mode=false",
    'web_search="disabled"',
    "tools.view_image=false",
)


async def request_suggestion[Response: BaseModel](
    context: BaseModel,
    binary: Path | None,
    response_model: type[Response],
    instructions: str,
    *,
    label: str,
    timeout: float = 120,
) -> Response:
    """Request a bounded ephemeral preview through the configured local AI account."""
    payload = context.model_dump_json()
    if len(payload.encode("utf-8")) > 128 * 1024:
        raise AssistanceError(
            "Too much context for a quick AI suggestion. Use chat or enter text manually."
        )
    completion: asyncio.Future[dict[str, Any]] = asyncio.get_running_loop().create_future()
    messages: dict[str, list[str]] = {}
    thread_id: str | None = None

    async def event(method: str, params: dict[str, Any]) -> None:
        if completion.done():
            return
        if method == "codex/disconnected":
            completion.set_exception(AssistanceError("AI connection closed. Try again."))
        elif thread_id and params.get("threadId") == thread_id:
            if method == "item/completed":
                item = params.get("item", {})
                if item.get("type") == "agentMessage" and item.get("phase") != "commentary":
                    messages.setdefault(str(params.get("turnId")), []).append(item.get("text", ""))
            elif method == "turn/completed":
                completion.set_result(params.get("turn", {}))

    async def request(request_id: int | str, method: str, params: dict[str, Any]) -> None:
        # This text-only request cannot grant approvals or invoke client-side tools.
        if not completion.done():
            completion.set_exception(
                AssistanceError(f"AI requested a tool instead of {label}. Try again.")
            )
        await client.respond(request_id, {"decision": "decline"})

    client = CodexClient(binary, event, request, config_overrides=PREVIEW_CONFIG)
    try:
        async with asyncio.timeout(timeout):
            with tempfile.TemporaryDirectory(prefix="eforge-ai-preview-") as temporary:
                cwd = str(Path(temporary).resolve())
                effective = await client.call("config/read", {"cwd": cwd, "includeLayers": True})
                if not isinstance(effective.get("layers"), list):
                    raise AssistanceError(
                        f"This AI client cannot isolate {label} suggestions. Enter text manually."
                    )
                servers = {
                    name: {"enabled": False}
                    for layer in effective["layers"]
                    for name in (layer.get("config", {}).get("mcp_servers") or {})
                }
                started = await client.call(
                    "thread/start",
                    {
                        "cwd": cwd,
                        "sandbox": "read-only",
                        "approvalPolicy": "never",
                        "ephemeral": True,
                        "developerInstructions": instructions,
                        "config": {"mcp_servers": servers, "project_doc_max_bytes": 0},
                    },
                )
                thread_id = started.get("thread", {}).get("id")
                if not thread_id:
                    raise AssistanceError(f"AI did not start the {label} request. Try again.")
                if (
                    started.get("sandbox", {}).get("type") != "readOnly"
                    or started.get("approvalPolicy") != "never"
                ):
                    raise AssistanceError(
                        f"This AI client cannot isolate {label} suggestions. Enter text manually."
                    )
                response = await client.call(
                    "turn/start",
                    {
                        "threadId": thread_id,
                        "input": [{"type": "text", "text": payload, "text_elements": []}],
                        "outputSchema": response_model.model_json_schema(),
                    },
                )
                turn = await completion
                if turn.get("id") != response.get("turn", {}).get("id"):
                    raise AssistanceError(f"AI returned an unrelated {label} response.")
                if turn.get("status") != "completed":
                    raise AssistanceError(
                        "AI could not finish the suggestion. Check AI sign-in or enter text manually."
                    )
                output = messages.get(str(turn.get("id")), [])
                if not output:
                    output = [
                        item.get("text", "")
                        for item in turn.get("items", [])
                        if item.get("type") == "agentMessage" and item.get("phase") != "commentary"
                    ]
                if len(output) != 1:
                    raise AssistanceError(
                        f"AI did not return a single {label} suggestion. Try again."
                    )
                try:
                    return response_model.model_validate_json(output[0])
                except (ValidationError, ValueError) as exc:
                    raise AssistanceError(
                        f"AI returned an invalid {label}. Try again or enter text manually."
                    ) from exc
    except TimeoutError as exc:
        raise AssistanceError("The AI suggestion timed out. Try again.") from exc
    except CodexUnavailableError as exc:
        raise AssistanceError(str(exc)) from exc
    finally:
        if completion.done() and not completion.cancelled():
            completion.exception()
        else:
            completion.cancel()
        await client.stop()
