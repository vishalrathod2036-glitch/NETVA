"""Ingestion layer — parse all scan data sources.

Usage:
    raw = ingest_all(use_lab_defaults=True)
    # Returns dict with keys: nessus, nmap, iac, acl, iam
"""
from __future__ import annotations

from typing import Any

from backend.ingestion.nessus_parser import parse_nessus, generate_lab_nessus_xml
from backend.ingestion.nmap_parser import parse_nmap, generate_lab_nmap_xml
from backend.ingestion.iac_parser import parse_iac, generate_lab_iac_json
from backend.ingestion.acl_parser import parse_acl, generate_lab_acl
from backend.ingestion.iam_parser import parse_iam, generate_lab_iam_json


def ingest_all(
    *,
    use_lab_defaults: bool = False,
    nessus_xml: str | None = None,
    nmap_xml: str | None = None,
    iac_json: str | None = None,
    acl_text: str | None = None,
    iam_json: str | None = None,
) -> dict[str, Any]:
    """Ingest data from all sources, returning raw parsed objects.

    If *use_lab_defaults* is True, synthetic lab data is generated for any
    source that is not explicitly provided.
    """
    if use_lab_defaults:
        nessus_xml = nessus_xml or generate_lab_nessus_xml()
        nmap_xml = nmap_xml or generate_lab_nmap_xml()
        iac_json = iac_json or generate_lab_iac_json()
        acl_text = acl_text or generate_lab_acl()
        iam_json = iam_json or generate_lab_iam_json()

    result: dict[str, Any] = {}
    result["nessus"] = parse_nessus(nessus_xml) if nessus_xml else None
    result["nmap"] = parse_nmap(nmap_xml) if nmap_xml else None
    result["iac"] = parse_iac(iac_json) if iac_json else None
    result["acl"] = parse_acl(acl_text) if acl_text else None
    result["iam"] = parse_iam(iam_json) if iam_json else None

    return result
