"""
Module: report_parser.py
Description: Ingests raw scanner outputs (such as OWASP ZAP JSON reports)
             and normalizes findings into a unified security alert schema.
"""

import json
import os
import logging
from typing import List, Dict, Any

logger = logging.getLogger("ReportParser")

# Strict mapping table to normalize scanner severities
SEVERITY_MAP = {
    "0": "INFO",
    "1": "LOW",
    "2": "MEDIUM",
    "3": "HIGH",
    "informational": "INFO",
    "low": "LOW",
    "medium": "MEDIUM",
    "high": "HIGH",
    "critical": "CRITICAL"
}


def parse_security_alerts(json_report_filepath: str) -> List[Dict[str, Any]]:
    """
    Parses scanner JSON outputs and returns a normalized list of vulnerability records.
    
    Standardized Output Schema:
      - title: Flaw name or misconfiguration title.
      - severity: Mapped to INFO, LOW, MEDIUM, HIGH, or CRITICAL.
      - target_uri: Affected endpoint or URI.
      - description: Deployment and operational risk breakdown.
    """
    if not os.path.isfile(json_report_filepath):
        logger.error(f"Report file not found: {json_report_filepath}")
        return []

    try:
        with open(json_report_filepath, "r", encoding="utf-8") as f:
            data = json.load(f)
    except (json.JSONDecodeError, OSError) as err:
        logger.error(f"Error reading {json_report_filepath}: {err}")
        return []

    normalized_alerts: List[Dict[str, Any]] = []

    # Handle OWASP ZAP structured JSON schema
    site_entries = data.get("site", [])
    if isinstance(site_entries, dict):
        site_entries = [site_entries]

    for site in site_entries:
        raw_alerts = site.get("alerts", [])
        for alert in raw_alerts:
            raw_risk = str(alert.get("riskcode", alert.get("riskdesc", "INFO"))).lower()
            # If string is formatted like "Low (Medium)", extract the first token
            clean_risk = raw_risk.split()[0] if " " in raw_risk else raw_risk
            severity = SEVERITY_MAP.get(clean_risk, "INFO")

            # Extract target endpoint instances
            instances = alert.get("instances", [])
            target_uri = instances[0].get("uri", site.get("@name", "N/A")) if instances else site.get("@name", "N/A")

            record: Dict[str, Any] = {
                "title": alert.get("alert", alert.get("name", "Unknown Security Alert")),
                "severity": severity,
                "target_uri": target_uri,
                "description": alert.get("desc", alert.get("description", "No description provided.")),
                "solution": alert.get("solution", ""),
                "cwe_id": alert.get("cweid", None)
            }
            normalized_alerts.append(record)

    return normalized_alerts
