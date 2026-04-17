"""
nessus_parser.py — Parse Nessus XML (.nessus) export files and seed
                   the HackSmarter SQLite database with the findings.

A .nessus file is a Nessus XML v2 document with this rough shape:

  <NessusClientData_v2>
    <Report name="...">
      <ReportHost name="192.168.1.1">
        <HostProperties>
          <tag name="host-fqdn">example.com</tag>
          ...
        </HostProperties>
        <ReportItem port="443" protocol="tcp" severity="3"
                    pluginName="SSL Certificate Expiry"
                    pluginID="15901" ...>
          <description>...</description>
          <solution>...</solution>
          <plugin_output>...</plugin_output>
        </ReportItem>
        ...
      </ReportHost>
    </Report>
  </NessusClientData_v2>

Severity mapping (Nessus integer → human label):
  0 → info   1 → low   2 → medium   3 → high   4 → critical

Only items with severity >= 1 are imported as vulnerabilities.
Informational items (severity 0) with an open port are still used
to seed the open_ports table.
"""

from __future__ import annotations

import logging
import os
from dataclasses import dataclass, field
from typing import List, Optional

try:
    import defusedxml.ElementTree as ET
except ImportError:  # pragma: no cover – defusedxml is in requirements
    import xml.etree.ElementTree as ET  # type: ignore

logger = logging.getLogger("hacksmarter.nessus_parser")

# ---------------------------------------------------------------------------
# Severity helpers
# ---------------------------------------------------------------------------

_SEVERITY_MAP = {0: "info", 1: "low", 2: "medium", 3: "high", 4: "critical"}


def _severity_label(raw: int) -> str:
    return _SEVERITY_MAP.get(raw, "info")


# ---------------------------------------------------------------------------
# Data containers
# ---------------------------------------------------------------------------

@dataclass
class NessusHost:
    ip: str
    fqdn: Optional[str] = None
    os_name: Optional[str] = None


@dataclass
class NessusFinding:
    host: str          # IP or FQDN used as the "target"
    port: str
    protocol: str
    plugin_id: str
    plugin_name: str
    severity: int      # 0-4 integer
    description: str
    solution: str
    plugin_output: str


@dataclass
class NessusParseResult:
    hosts: List[NessusHost] = field(default_factory=list)
    findings: List[NessusFinding] = field(default_factory=list)
    targets: List[str] = field(default_factory=list)  # unique host identifiers


# ---------------------------------------------------------------------------
# Parser
# ---------------------------------------------------------------------------

def parse_nessus_file(path: str) -> NessusParseResult:
    """
    Parse a .nessus XML file and return a :class:`NessusParseResult`.

    Raises
    ------
    FileNotFoundError
        If *path* does not exist.
    ValueError
        If the file does not look like a Nessus XML v2 document.
    """
    if not os.path.isfile(path):
        raise FileNotFoundError(f"Nessus file not found: {path}")

    try:
        tree = ET.parse(path)
    except ET.ParseError as exc:
        raise ValueError(f"Failed to parse XML in {path}: {exc}") from exc

    root = tree.getroot()
    if "NessusClientData" not in root.tag:
        raise ValueError(
            f"Not a Nessus XML v2 file (root tag: <{root.tag}>). "
            "Export as '.nessus' from Nessus / Tenable.io."
        )

    result = NessusParseResult()
    seen_targets: set = set()

    for report in root.findall(".//Report"):
        for report_host in report.findall("ReportHost"):
            ip = report_host.get("name", "").strip()
            if not ip:
                continue

            # ---- Host metadata ----------------------------------------
            props = report_host.find("HostProperties")
            fqdn: Optional[str] = None
            os_name: Optional[str] = None
            if props is not None:
                for tag in props.findall("tag"):
                    name = tag.get("name", "")
                    val = (tag.text or "").strip()
                    if name == "host-fqdn" and val:
                        fqdn = val
                    elif name in ("operating-system", "os") and val:
                        os_name = val

            host_obj = NessusHost(ip=ip, fqdn=fqdn, os_name=os_name)
            result.hosts.append(host_obj)

            # Prefer FQDN as the canonical target; fall back to IP
            canonical = fqdn or ip
            if canonical not in seen_targets:
                seen_targets.add(canonical)
                result.targets.append(canonical)

            # ---- ReportItems (findings) --------------------------------
            for item in report_host.findall("ReportItem"):
                raw_sev = int(item.get("severity", "0"))
                port = item.get("port", "0")
                protocol = item.get("protocol", "tcp")
                plugin_id = item.get("pluginID", "")
                plugin_name = item.get("pluginName", "")

                description = _text(item, "description")
                solution = _text(item, "solution")
                plugin_output = _text(item, "plugin_output")

                finding = NessusFinding(
                    host=canonical,
                    port=port,
                    protocol=protocol,
                    plugin_id=plugin_id,
                    plugin_name=plugin_name,
                    severity=raw_sev,
                    description=description,
                    solution=solution,
                    plugin_output=plugin_output,
                )
                result.findings.append(finding)

    logger.info(
        "Parsed %s: %d hosts, %d findings",
        os.path.basename(path),
        len(result.hosts),
        len(result.findings),
    )
    return result


def _text(element, tag: str) -> str:
    """Return stripped text of a child element, or empty string."""
    child = element.find(tag)
    if child is not None and child.text:
        return child.text.strip()
    return ""


# ---------------------------------------------------------------------------
# DB seeding
# ---------------------------------------------------------------------------

def seed_db_from_nessus(result: NessusParseResult) -> dict:
    """
    Write parsed Nessus findings into the HackSmarter SQLite database.

    Must be called **after** ``tools.init_db()`` (or ``tools.set_output_dir()``)
    so that ``tools.DB_PATH`` is set correctly.

    Returns a summary dict with counts for logging/testing.
    """
    import tools  # imported here to avoid circular imports at module level

    subdomains: List[str] = []
    open_ports: List[dict] = []
    vulnerabilities: List[dict] = []

    seen_ports: set = set()

    for finding in result.findings:
        port = finding.port
        host = finding.host

        # Accumulate open ports (deduplicated)
        if port not in ("0",) and (host, port) not in seen_ports:
            seen_ports.add((host, port))
            open_ports.append({"target": host, "port": port})

        # Severity 0 = informational — skip as a vuln, but keep port data
        if finding.severity == 0:
            continue

        sev_label = _severity_label(finding.severity)
        poc_parts = []
        if finding.plugin_output:
            poc_parts.append(f"Plugin output:\n{finding.plugin_output}")
        if finding.solution:
            poc_parts.append(f"Solution:\n{finding.solution}")
        poc = "\n\n".join(poc_parts) or "See Nessus report for details."

        description = finding.description or finding.plugin_name

        vulnerabilities.append({
            "target": host,
            "template": f"nessus-{finding.plugin_id}",
            "severity": sev_label,
            "description": f"[Nessus] {finding.plugin_name}: {description}",
            "poc": poc,
        })

    # Subdomains: any FQDN that differs from the bare IP
    for h in result.hosts:
        if h.fqdn and h.fqdn != h.ip:
            subdomains.append(h.fqdn)

    # Write to DB
    if subdomains:
        tools.update_db("subdomains", subdomains)
    if open_ports:
        tools.update_db("open_ports", open_ports)
    if vulnerabilities:
        tools.update_db("vulnerabilities", vulnerabilities)

    # Mark nessus as having "run" for every host so the recon agent
    # skips redundant port scans on pre-scanned targets if desired.
    for target in result.targets:
        tools.mark_as_run("nessus_import", target)

    summary = {
        "hosts": len(result.hosts),
        "subdomains": len(subdomains),
        "open_ports": len(open_ports),
        "vulnerabilities": len(vulnerabilities),
    }
    logger.info("Nessus DB seed complete: %s", summary)
    return summary
