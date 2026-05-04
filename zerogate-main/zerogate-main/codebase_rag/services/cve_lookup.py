"""CVE lookup against NVD API (National Vulnerability Database).

Provides async lookup of known CVEs for a given package name and version.
Falls back gracefully if the NVD API is unreachable.
"""

from __future__ import annotations

from dataclasses import dataclass

from loguru import logger


NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"


@dataclass
class CVERecord:
    """A single CVE finding from the NVD database."""
    cve_id: str
    severity: str
    description: str
    affected_versions: str


async def lookup_cve(package_name: str, version: str = "") -> list[CVERecord]:
    """Query NVD for known CVEs affecting a specific package.

    Args:
        package_name: The package name to search for (e.g. "flask", "log4j").
        version: Optional version string for filtering.

    Returns:
        A list of CVERecord objects, or an empty list on failure.
    """
    results: list[CVERecord] = []
    try:
        import httpx
    except ImportError:
        logger.warning("httpx not installed. Skipping CVE lookup.")
        return results

    try:
        async with httpx.AsyncClient(timeout=10) as client:
            resp = await client.get(
                NVD_API_URL,
                params={"keywordSearch": package_name, "resultsPerPage": 5},
            )
            if resp.status_code != 200:
                logger.warning(f"NVD API returned {resp.status_code} for {package_name}")
                return results

            data = resp.json()
            for vuln in data.get("vulnerabilities", [])[:5]:
                cve = vuln.get("cve", {})
                cve_id = cve.get("id", "")
                descriptions = cve.get("descriptions", [])
                desc = descriptions[0].get("value", "") if descriptions else ""

                # Extract severity from CVSS v3.1 metrics
                severity = "UNKNOWN"
                metrics = cve.get("metrics", {})
                cvss_v31 = metrics.get("cvssMetricV31", [])
                if cvss_v31:
                    severity = cvss_v31[0].get("cvssData", {}).get(
                        "baseSeverity", "UNKNOWN"
                    )

                results.append(
                    CVERecord(
                        cve_id=cve_id,
                        severity=severity,
                        description=desc[:300],
                        affected_versions=version,
                    )
                )

    except Exception as e:
        logger.warning(f"CVE lookup failed for {package_name}: {e}")

    return results
