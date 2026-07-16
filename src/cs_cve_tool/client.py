from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, List, Optional

from falconpy import SpotlightVulnerabilities


@dataclass
class FalconCredentials:
    client_id: str
    client_secret: str
    base_url: Optional[str] = None


class FalconSpotlightClient:
    def __init__(self, creds: FalconCredentials) -> None:
        init_kwargs: Dict[str, Any] = {
            "client_id": creds.client_id,
            "client_secret": creds.client_secret,
        }
        if creds.base_url:
            init_kwargs["base_url"] = creds.base_url

        self._svc = SpotlightVulnerabilities(**init_kwargs)

    def query_vulnerabilities(self, filter_expression: str, limit: Optional[int] = 100, sort: str = "updated_timestamp.desc") -> List[Dict[str, Any]]:
        """Fetch spotlight vulnerabilities and return normalized resource objects.

        The FalconPy SDK has slight method differences across versions, so this
        wrapper checks available methods and normalizes the response shape.
        """
        rows: List[Dict[str, Any]] = []
        effective_filter = filter_expression.strip() if filter_expression else "status:'open'"
        after: Optional[str] = None

        while True:
            if limit is None:
                page_size = 400
            else:
                if len(rows) >= limit:
                    break
                page_size = min(400, max(1, limit - len(rows)))

            response = self._query_page(filter_expression=effective_filter, sort=sort, limit=page_size, after=after)
            body = response.get("body", {}) if isinstance(response, dict) else {}
            resources = body.get("resources", [])

            if not resources:
                break

            # Some endpoints return full resources, others only IDs.
            if resources and isinstance(resources[0], str):
                resources = self._resolve_ids(resources)
            elif resources and isinstance(resources[0], dict):
                resources = self._enrich_resources(resources)

            rows.extend(resources)

            meta = body.get("meta", {})
            pagination = meta.get("pagination", {})
            after = pagination.get("after")
            if not after:
                break

        return rows if limit is None else rows[:limit]

    def _query_page(self, filter_expression: str, sort: str, limit: int, after: Optional[str]) -> Dict[str, Any]:
        kwargs: Dict[str, Any] = {
            "filter": filter_expression,
            "sort": sort,
            "limit": limit,
        }
        if after:
            kwargs["after"] = after

        if hasattr(self._svc, "query_vulnerabilities"):
            return self._svc.query_vulnerabilities(**kwargs)
        if hasattr(self._svc, "queryVulnerabilities"):
            return self._svc.queryVulnerabilities(**kwargs)
        if hasattr(self._svc, "query_vulnerabilities_combined"):
            return self._svc.query_vulnerabilities_combined(**kwargs)
        if hasattr(self._svc, "queryVulnerabilitiesCombined"):
            return self._svc.queryVulnerabilitiesCombined(**kwargs)

        raise RuntimeError("No supported query vulnerabilities method found in FalconPy SpotlightVulnerabilities.")

    def _resolve_ids(self, ids: List[str]) -> List[Dict[str, Any]]:
        if hasattr(self._svc, "get_vulnerabilities_combined"):
            response = self._svc.get_vulnerabilities_combined(ids=ids)
        elif hasattr(self._svc, "getVulnerabilitiesCombined"):
            response = self._svc.getVulnerabilitiesCombined(ids=ids)
        elif hasattr(self._svc, "get_vulnerabilities"):
            response = self._svc.get_vulnerabilities(ids=ids)
        elif hasattr(self._svc, "getVulnerabilities"):
            response = self._svc.getVulnerabilities(ids=ids)
        else:
            raise RuntimeError("No supported get vulnerabilities method found in FalconPy SpotlightVulnerabilities.")

        body = response.get("body", {}) if isinstance(response, dict) else {}
        resources = body.get("resources", [])
        return resources if isinstance(resources, list) else []

    def _enrich_resources(self, resources: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Hydrate combined-query rows with full CVE details when available.

        Combined Spotlight responses often include only `cve.id`. This method
        attempts a follow-up get call keyed by row `id` and merges richer fields.
        """
        ids = [r.get("id") for r in resources if isinstance(r, dict) and r.get("id")]
        if not ids:
            return resources

        resolved = self._resolve_ids(ids)
        if not resolved:
            return resources

        by_id: Dict[str, Dict[str, Any]] = {
            str(r.get("id")): r for r in resolved if isinstance(r, dict) and r.get("id")
        }

        merged: List[Dict[str, Any]] = []
        for row in resources:
            if not isinstance(row, dict):
                merged.append(row)
                continue

            row_id = str(row.get("id")) if row.get("id") else None
            full = by_id.get(row_id) if row_id else None
            merged.append(full if full else row)

        return merged
