from __future__ import annotations

import os
from typing import Any, Dict, Optional

_client = None


def _get_client():
    global _client
    if _client is not None:
        return _client
    url = os.getenv("OPENSEARCH_URL")
    if not url:
        _client = False  # sentinel: disabled
        return _client
    try:
        from opensearchpy import OpenSearch

        _client = OpenSearch(hosts=[url], timeout=2, use_ssl=url.startswith("https"))
        return _client
    except Exception:
        _client = False
        return _client


def index_document(index: str, doc_id: str, body: Dict[str, Any]) -> None:
    client = _get_client()
    if not client:
        return
    try:
        client.index(index=index, id=doc_id, body=body, refresh=False)
    except Exception:
        # Best-effort indexing; ignore failures in dev/test
        return


def index_asset(asset: Dict[str, Any]) -> None:
    index_document("assets", asset["id"], asset)


def index_finding(finding: Dict[str, Any]) -> None:
    index_document("findings", finding["id"], finding)


def index_evidence(evidence: Dict[str, Any]) -> None:
    index_document("evidence", evidence["id"], evidence)


