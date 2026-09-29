"""Small vector icons for desktop controls."""

from __future__ import annotations

from PySide6.QtCore import QByteArray, QRectF, Qt
from PySide6.QtGui import QIcon, QPainter, QPixmap
from PySide6.QtSvg import QSvgRenderer

_PATHS = {
    "add": '<path d="M12 5v14M5 12h14"/>',
    "close": '<path d="M18 6 6 18M6 6l12 12"/>',
    "filter": '<path d="M4 6h16l-6.5 7v5l-3 1v-6z"/>',
    "folder": '<path d="M3 7a2 2 0 0 1 2-2h4l2 2h8a2 2 0 0 1 2 2v9a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2z"/>',
    "file": '<path d="M7 3h7l4 4v14H7a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2zM14 3v5h5"/>',
    "more": '<circle cx="5" cy="12" r="1"/><circle cx="12" cy="12" r="1"/><circle cx="19" cy="12" r="1"/>',
    "refresh": '<path d="M20 7v5h-5M4 17v-5h5M5.5 9a7 7 0 0 1 12-2l2.5 5M4 12l2.5 5a7 7 0 0 0 12-2"/>',
    "import": '<path d="M12 3v12m-4-4 4 4 4-4M4 17v3h16v-3"/>',
    "edit": '<path d="m4 20 4.5-1 11-11-3.5-3.5-11 11L4 20zM14 6l3.5 3.5"/>',
    "play": '<path d="m8 5 11 7-11 7z"/>',
    "pause": '<path d="M8 5v14M16 5v14"/>',
    "check": '<path d="m4 12 5 5L20 6"/>',
    "copy": '<rect x="8" y="8" width="12" height="12" rx="2"/><path d="M16 8V6a2 2 0 0 0-2-2H6a2 2 0 0 0-2 2v8a2 2 0 0 0 2 2h2"/>',
    "hide": '<path d="M3 3 21 21M10.6 10.6a2 2 0 0 0 2.8 2.8M6.5 6.5C4.5 7.8 3 9.7 2 12c2 4.5 5.5 7 10 7 1.7 0 3.2-.2 4.5-.8M9.2 5.2A11 11 0 0 1 12 5c4.5 0 8 2.5 10 7-.6 1.3-1.3 2.4-2.2 3.3"/>',
    "external": '<path d="M14 4h6v6M20 4l-9 9M20 13v6a1 1 0 0 1-1 1H5a1 1 0 0 1-1-1V5a1 1 0 0 1 1-1h6"/>',
    "chat": '<path d="M4 5h16v12H8l-4 3z"/>',
    "layers": '<path d="m12 3 9 5-9 5-9-5zM3 12l9 5 9-5M3 16l9 5 9-5"/>',
    "runs": '<path d="M4 4v16h16M7 15l4-4 3 2 5-6"/>',
    "settings": '<path d="M12 3v2m0 14v2M3 12h2m14 0h2M5.6 5.6 7 7m10 10 1.4 1.4M18.4 5.6 17 7M7 17l-1.4 1.4"/><circle cx="12" cy="12" r="4"/>',
}
_icon_cache: dict[tuple[str, str], QIcon] = {}


def icon(name: str, *, color: str = "#b5c5da") -> QIcon:
    """Render a crisp theme-colored icon at standard toolbar size."""
    key = (name, color)
    cached = _icon_cache.get(key)
    if cached is not None:
        return cached
    path = _PATHS[name]
    svg = (
        '<svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" '
        f'fill="none" stroke="{color}" stroke-width="1.8" stroke-linecap="round" '
        f'stroke-linejoin="round">{path}</svg>'
    )
    renderer = QSvgRenderer(QByteArray(svg.encode("utf-8")))
    pixmap = QPixmap(40, 40)
    pixmap.fill(Qt.GlobalColor.transparent)
    painter = QPainter(pixmap)
    renderer.render(painter, QRectF(0, 0, 40, 40))
    painter.end()
    pixmap.setDevicePixelRatio(2)
    result = QIcon(pixmap)
    _icon_cache[key] = result
    return result
