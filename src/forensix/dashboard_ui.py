"""
Offline Dashboard UI Asset Provider for ForensiX (V7.3).

Provides controlled, in-memory serving of fixed UI resources (HTML, CSS, JS).
Enforces zero runtime filesystem traversal and zero external dependencies.
"""

from pathlib import Path
from types import MappingProxyType
from typing import Dict, Mapping, Optional, Tuple

# UI asset directory relative to this module
_UI_DIR = Path(__file__).resolve().parent / "ui"

# Inline SVG favicon for ForensiX (FX mark in cyan/indigo)
_FAVICON_SVG = (
    b'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 32 32">'
    b'<rect width="32" height="32" rx="6" fill="#0b0f19"/>'
    b'<path d="M7 8h10v3H10v4h6v3h-6v6H7V8zm12 0h3.5l2.5 4.5 2.5-4.5H31l-4.5 7.5L31 24h-3.5L25 19.5 22.5 24H19l4.5-8.5L19 8z" fill="#06b6d4"/>'
    b'</svg>'
)


def _load_asset(filename: str) -> bytes:
    """Load a static asset file from the fixed package directory."""
    path = _UI_DIR / filename
    if path.is_file():
        return path.read_bytes()
    raise FileNotFoundError(f"Required ForensiX UI asset not found: {path}")


def load_static_assets() -> Dict[str, Tuple[str, bytes]]:
    """
    Load all trusted, fixed UI assets into an in-memory dictionary mapping.

    Returns:
        Dict mapping exact route paths to (content_type, bytes).
    """
    html_bytes = _load_asset("index.html")
    css_bytes = _load_asset("dashboard.css")
    js_bytes = _load_asset("dashboard.js")

    return {
        "/": ("text/html; charset=utf-8", html_bytes),
        "/index.html": ("text/html; charset=utf-8", html_bytes),
        "/static/dashboard.css": ("text/css; charset=utf-8", css_bytes),
        "/static/dashboard.js": ("application/javascript; charset=utf-8", js_bytes),
        "/favicon.svg": ("image/svg+xml", _FAVICON_SVG),
    }


# Immutable in-memory registry of fixed UI assets initialized at import time
STATIC_ASSETS: Mapping[str, Tuple[str, bytes]] = MappingProxyType(load_static_assets())


def get_static_asset(path: str) -> Optional[Tuple[str, bytes]]:
    """
    Retrieve a static asset by exact normalized route path from in-memory store.

    Guarantees zero dynamic filesystem path resolution or disk access during request handling.

    Args:
        path: Normalized URL path.

    Returns:
        Tuple of (content_type, content_bytes), or None if not found.
    """
    return STATIC_ASSETS.get(path)
