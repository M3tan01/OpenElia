"""Stage fetchers. Each module exposes ``fetch(mode: str) -> list[dict]``.

``mode == "mock"`` loads the matching fixture under ``pipeline/fixtures/``.
``mode == "live"`` performs the real pull (some are stubbed until creds exist).
The downstream path is identical regardless of mode.
"""
import json
import os

_FIXTURE_DIR = os.path.abspath(
    os.path.join(os.path.dirname(__file__), "..", "fixtures")
)


def load_fixture(name: str) -> list[dict]:
    """Load a JSON fixture list by filename (e.g. 'ioc_feed.json')."""
    path = os.path.join(_FIXTURE_DIR, name)
    with open(path) as fh:
        return json.load(fh)
