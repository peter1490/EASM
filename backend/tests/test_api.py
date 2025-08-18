import asyncio

import pytest
from httpx import AsyncClient

from app.main import get_app


@pytest.mark.asyncio
async def test_health():
    app = get_app()
    async with AsyncClient(app=app, base_url="http://test") as ac:
        resp = await ac.get("/api/health")
        assert resp.status_code == 200
        assert resp.json()["status"] == "ok"


@pytest.mark.asyncio
async def test_scan_flow():
    app = get_app()
    async with AsyncClient(app=app, base_url="http://test") as ac:
        create = await ac.post("/api/scans", json={"target": "example.com"})
        assert create.status_code == 200
        scan = create.json()
        scan_id = scan["id"]

        # Scan should be queued or quickly completed
        assert scan["status"] in {"queued", "completed"}

        # Listing should include it
        listing = await ac.get("/api/scans")
        assert listing.status_code == 200
        assert any(item["id"] == scan_id for item in listing.json())

        # Poll for completion
        for _ in range(20):
            detail = await ac.get(f"/api/scans/{scan_id}")
            assert detail.status_code == 200
            if detail.json()["status"] == "completed":
                break
            await asyncio.sleep(0.1)

        final = await ac.get(f"/api/scans/{scan_id}")
        assert final.status_code == 200
        body = final.json()
        assert body["status"] == "completed"
        assert isinstance(body["findings"], list)


