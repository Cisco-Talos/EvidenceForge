"""Version 8 chat records that retain routed diagram context."""

from pydantic import Field

from evidenceforge.studio.state_records_v7 import ChatControl as ChatControlV7
from evidenceforge.studio.state_records_v7 import ChatInput as ChatInputV7
from evidenceforge.studio.state_records_v7 import ChatViewState as ChatViewStateV7
from evidenceforge.studio.topology import RoutedNetworkChatContext


class ChatInput(ChatInputV7):
    """Queued message with its captured routed diagram."""

    network_context: RoutedNetworkChatContext | None = None


class ChatViewState(ChatViewStateV7):
    """Composer state with a routed diagram draft."""

    network_context: RoutedNetworkChatContext | None = None


class ChatControl(ChatControlV7):
    """Composer and queue state."""

    view: ChatViewState = Field(default_factory=ChatViewState)
