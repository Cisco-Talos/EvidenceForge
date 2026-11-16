"""Small real publications for example installation tests; never shipped as examples."""

from pathlib import Path

from evidenceforge.artifacts.lifecycle import create_draft, publish
from evidenceforge.composition.publisher import PublisherIdentity, set_publisher


def publish_example(author: Path, name: str = "example-one", version: str = "1.0.0") -> Path:
    """Publish a valid scenario with nested authored companions and frozen configuration."""
    author.mkdir(parents=True, exist_ok=True)
    set_publisher(
        author,
        PublisherIdentity(publisher="evidenceforge", publisher_display_name="EvidenceForge"),
        scope="project",
        force=True,
    )
    source = author / "scenario.yaml"
    source.write_bytes(Path("tests/fixtures/scenarios/minimal.yaml").read_bytes())
    draft = create_draft(source, project_root=author, name=name)
    assets = draft.parent / "assets"
    assets.mkdir()
    (assets / "message.eml").write_bytes(b"Subject: Authored example\r\n\r\nHello\r\n")
    (draft.parent / "ENVIRONMENT.md").write_text("# Example environment\n", encoding="utf-8")
    release = publish(draft, project_root=author, version=version, accept_warnings=True)
    return release.parent.parent
