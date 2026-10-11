"""Verify the actual native AppImage, bundled GStreamer plugins and private runtime."""

from __future__ import annotations

import argparse
import json
import os
import platform
import subprocess
import sys
import tempfile
from pathlib import Path

from verify_studio_runtime import verify_runtime


def verify_gstreamer(appdir: Path, temporary: Path) -> None:
    """Require appsink to load from bundled plugins with an empty host-plugin search path."""
    plugins = list(appdir.glob("usr/**/gstreamer-1.0/libgstapp.so"))
    scanners = list(appdir.glob("usr/**/gst-plugin-scanner"))
    if len(plugins) != 1 or len(scanners) != 1:
        raise ValueError("AppImage must bundle the GStreamer appsink plugin and its scanner")
    library_paths = {appdir / "usr/lib", plugins[0].parent.parent}
    environment = {
        **os.environ,
        "LD_LIBRARY_PATH": ":".join(str(path) for path in sorted(library_paths)),
        "GST_PLUGIN_PATH": str(plugins[0].parent),
        "GST_PLUGIN_PATH_1_0": str(plugins[0].parent),
        "GST_PLUGIN_SYSTEM_PATH": "",
        "GST_PLUGIN_SYSTEM_PATH_1_0": "",
        "GST_PLUGIN_SCANNER": str(scanners[0]),
        "GST_PLUGIN_SCANNER_1_0": str(scanners[0]),
        "GST_REGISTRY": str(temporary / "gstreamer-registry.bin"),
        "GST_REGISTRY_1_0": str(temporary / "gstreamer-registry.bin"),
    }
    result = subprocess.run(
        ["/usr/bin/gst-inspect-1.0", "appsink"],
        env=environment,
        capture_output=True,
        text=True,
        check=True,
        timeout=60,
    )
    if str(plugins[0]) not in result.stdout:
        raise ValueError("GStreamer appsink did not load from the extracted AppImage")


def main() -> None:
    """Extract the installer without FUSE and run the shared packaged acceptance checks."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("appimage", type=Path)
    arguments = parser.parse_args()
    architecture = platform.machine()
    if sys.platform != "linux" or architecture not in {"aarch64", "x86_64"}:
        parser.error("Verify AppImages on native aarch64 or x86_64 Linux")
    image = arguments.appimage.resolve()
    with image.open("rb") as stream:
        header = stream.read(20)
    expected_machine = 183 if architecture == "aarch64" else 62
    if (
        header[:6] != b"\x7fELF\x02\x01"
        or int.from_bytes(header[18:20], "little") != expected_machine
    ):
        parser.error("The AppImage must match the native Linux builder architecture")
    with tempfile.TemporaryDirectory(prefix="eforge AppImage ü ") as temporary:
        root = Path(temporary).resolve()
        subprocess.run(
            [str(image), "--appimage-extract"],
            cwd=root,
            stdout=subprocess.DEVNULL,
            check=True,
            timeout=120,
        )
        appdir = root / "squashfs-root"
        manifests = list(appdir.glob("usr/**/runtime/manifest.json"))
        if len(manifests) != 1:
            raise ValueError("AppImage must contain exactly one private runtime manifest")
        verify_gstreamer(appdir, root)
        report = verify_runtime(manifests[0].parent, architecture)
        report["bundled_gstreamer_appsink"] = "passed"
        print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
