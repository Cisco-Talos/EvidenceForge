"""Frozen version 7 chat records with captured network context."""

from pydantic import Field

from evidenceforge.studio.state_records_v3 import ChatControl as ChatControlV3
from evidenceforge.studio.state_records_v3 import ChatDraftSubmission as ChatDraftSubmissionV3
from evidenceforge.studio.state_records_v3 import ChatInput as ChatInputV3
from evidenceforge.studio.state_records_v3 import ChatViewState as ChatViewStateV3
from evidenceforge.studio.topology import NetworkChatContext


class ChatInput(ChatInputV3):
    """Keep the attachment bound to the queued message and its dispatch ID."""

    network_context: NetworkChatContext | None = None


class ChatDraftSubmission(ChatDraftSubmissionV3):
    """Distinguish retries with and without the optional image."""

    network_view_included: bool = False


class ChatViewState(ChatViewStateV3):
    """Keep the captured view in the composer until it is sent."""

    pending_message: ChatDraftSubmission | None = None
    network_context: NetworkChatContext | None = None
    include_current_view: bool = True


class ChatControl(ChatControlV3):
    """Persist the private composer alongside queue state."""

    view: ChatViewState = Field(default_factory=ChatViewState)
