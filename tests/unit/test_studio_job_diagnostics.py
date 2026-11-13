"""Captured Windows error paragraphs retain their wrapped diagnostic details."""

from pathlib import Path

import pytest

from evidenceforge.studio.job_diagnostics import read_job_diagnostics


@pytest.mark.parametrize("newline", ["\n", "\r\n", "\r"])
def test_wrapped_manifest_failure_retains_hashes_without_following_paragraph(
    tmp_path: Path, newline: str
) -> None:
    path = tmp_path / "job.log"
    declared = "a" * 64
    actual = "b" * 64
    lines = [
        "Runtime ready",
        "Fatal error: generation behavior surface changed without a matching manifest",
        "revision:",
        f"declared={declared},",
        f"actual={actual}",
        "",
        "Unrelated later message",
    ]
    path.write_bytes(newline.join(lines).encode())
    result = read_job_diagnostics(path, tmp_path, "job")
    assert result.available
    assert result.message == " ".join(lines[1:5])
    assert "Unrelated" not in result.message
