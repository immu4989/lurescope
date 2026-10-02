"""Workbench source and cached assets must refer to the same script revisions."""

import hashlib
import importlib.util
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from lurescope.app import app

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "static_stamp", ROOT / "scripts/stamp_static_assets.py"
)
stamp = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(stamp)


def test_checked_in_html_has_exact_script_hashes_without_writes():
    before = (stamp.ROOT / "index.html").read_bytes()
    assert stamp.main(["--check"]) == 0
    assert (stamp.ROOT / "index.html").read_bytes() == before


def test_changed_asset_requires_restamp_and_is_idempotent(tmp_path, monkeypatch):
    for name in stamp.SCRIPTS:
        (tmp_path / name).write_text("/* synthetic */", encoding="utf-8")
    html = "\n".join(f'<script src="static/{name}"></script>' for name in stamp.SCRIPTS)
    target = tmp_path / "index.html"
    target.write_text(html, encoding="utf-8")
    monkeypatch.setattr(stamp, "ROOT", tmp_path)
    with pytest.raises(ValueError, match="stale script URLs"):
        stamp.main(["--check"])
    stamp.main([])
    assert stamp.main(["--check"]) == 0
    (tmp_path / stamp.SCRIPTS[0]).write_text("/* changed */", encoding="utf-8")
    with pytest.raises(ValueError, match="stale script URLs"):
        stamp.main(["--check"])
    stamp.main([])
    assert hashlib.sha256(b"/* changed */").hexdigest() in target.read_text()
    assert stamp.stamped_html(tmp_path) == target.read_text()
    target.write_text(html + html, encoding="utf-8")
    with pytest.raises(ValueError, match="exactly once"):
        stamp.main([])


@pytest.mark.parametrize("path", ["/", "/static/browser-engine.js", "/static/evidence-explorer.js",
                                  "/static/model.json"])
def test_workbench_responses_require_cache_revalidation(path):
    client = TestClient(app)
    response = client.get(path)
    assert response.status_code == 200
    assert response.headers["cache-control"] == "no-cache"
    if path != "/":
        cached = client.get(path, headers={"If-None-Match": response.headers["etag"]})
        assert cached.status_code == 304
        assert cached.headers["cache-control"] == "no-cache"
