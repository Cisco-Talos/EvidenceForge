"""Generation checkpoint error hierarchy."""

from evidenceforge.models.exceptions import GenerationError


class CheckpointError(GenerationError):
    """Checkpoint state is unavailable, unsafe, corrupt, or incompatible."""


class CheckpointLockError(CheckpointError):
    """Another live process owns the output checkpoint workspace."""


class CheckpointCompatibilityError(CheckpointError):
    """A recovery point does not match the requested generation run."""


class CheckpointCorruptionError(CheckpointError):
    """A recovery point or referenced immutable object failed validation."""


class CheckpointFilesystemError(CheckpointError):
    """The destination filesystem cannot provide required checkpoint guarantees."""
