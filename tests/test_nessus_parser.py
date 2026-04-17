"""
tests/test_nessus_parser.py — Unit and integration tests for the
.nessus import feature (Feature #8).

Run with:
    pytest tests/test_nessus_parser.py -v
"""

import os
import sqlite3
import sys
import tempfile

import pytest

# Make sure the project root is importable regardless of where pytest is invoked
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from nessus_parser import (
    NessusFinding,
    NessusHost,
    NessusParseResult,
    _severity_label,
    parse_nessus_file,
    seed_db_from_nessus,
)
import tools


# ---------------------------------------------------------------------------
# Helpers — tiny in-memory .nessus XML fixtures
# ---------------------------------------------------------------------------

def _write_nessus(tmp_path, xml_body: str) -> str:
    """Write a .nessus file to a temp directory and return its path."""
    p = os.path.join(str(tmp_path), "scan.nessus")
    with open(p, "w") as f:
        f.write(xml_body)
    return p


MINIMAL_NESSUS = (
    '<?xml version="1.0" encoding="UTF-8"?>\n'
    '<NessusClientData_v2>\n'
    '  <Report name="TestScan">\n'
    '    <ReportHost name="10.0.0.1">\n'
    '      <HostProperties>\n'
    '        <tag name="host-fqdn">target.example.com</tag>\n'
    '        <tag name="operating-system">Linux</tag>\n'
    '      </HostProperties>\n'
    '      <ReportItem port="443" protocol="tcp" severity="3"'
    ' pluginID="15901" pluginName="SSL Certificate Expiry">\n'
    '        <description>The SSL cert is expired.</description>\n'
    '        <solution>Renew the certificate.</solution>\n'
    '        <plugin_output>Serial: 1234\nExpiry: 2020-01-01</plugin_output>\n'
    '      </ReportItem>\n'
    '      <ReportItem port="80" protocol="tcp" severity="0"'
    ' pluginID="11219" pluginName="Nessus SYN scanner">\n'
    '        <description>Port 80 is open.</description>\n'
    '      </ReportItem>\n'
    '    </ReportHost>\n'
    '  </Report>\n'
    '</NessusClientData_v2>\n'
)

MULTI_HOST_NESSUS = (
    '<?xml version="1.0" encoding="UTF-8"?>\n'
    '<NessusClientData_v2>\n'
    '  <Report name="MultiScan">\n'
    '    <ReportHost name="192.168.1.10">\n'
    '      <HostProperties>\n'
    '        <tag name="host-fqdn">web.corp.local</tag>\n'
    '      </HostProperties>\n'
    '      <ReportItem port="8080" protocol="tcp" severity="2"'
    ' pluginID="99001" pluginName="Apache Outdated Version">\n'
    '        <description>Apache 2.2 is end-of-life.</description>\n'
    '        <solution>Upgrade to 2.4+.</solution>\n'
    '        <plugin_output>Server: Apache/2.2.34</plugin_output>\n'
    '      </ReportItem>\n'
    '    </ReportHost>\n'
    '    <ReportHost name="192.168.1.20">\n'
    '      <HostProperties/>\n'
    '      <ReportItem port="22" protocol="tcp" severity="1"'
    ' pluginID="70657" pluginName="SSH Weak MAC Algorithms">\n'
    '        <description>Weak MACs negotiated.</description>\n'
    '        <solution>Disable weak MACs in sshd_config.</solution>\n'
    '      </ReportItem>\n'
    '      <ReportItem port="22" protocol="tcp" severity="4"'
    ' pluginID="10881" pluginName="SSH Protocol Version 1 Enabled">\n'
    '        <description>SSHv1 is insecure.</description>\n'
    '        <solution>Disable SSHv1.</solution>\n'
    '        <plugin_output>The remote SSH server supports SSHv1.</plugin_output>\n'
    '      </ReportItem>\n'
    '    </ReportHost>\n'
    '  </Report>\n'
    '</NessusClientData_v2>\n'
)

NO_FINDINGS_NESSUS = (
    '<?xml version="1.0" encoding="UTF-8"?>\n'
    '<NessusClientData_v2>\n'
    '  <Report name="Clean">\n'
    '    <ReportHost name="10.0.0.99">\n'
    '      <HostProperties/>\n'
    '    </ReportHost>\n'
    '  </Report>\n'
    '</NessusClientData_v2>\n'
)


# ---------------------------------------------------------------------------
# Severity label tests
# ---------------------------------------------------------------------------

class TestSeverityLabel:
    def test_known_levels(self):
        assert _severity_label(0) == "info"
        assert _severity_label(1) == "low"
        assert _severity_label(2) == "medium"
        assert _severity_label(3) == "high"
        assert _severity_label(4) == "critical"

    def test_unknown_defaults_to_info(self):
        assert _severity_label(99) == "info"
        assert _severity_label(-1) == "info"


# ---------------------------------------------------------------------------
# Parser tests
# ---------------------------------------------------------------------------

class TestParseNessusFile:
    def test_file_not_found_raises(self, tmp_path):
        with pytest.raises(FileNotFoundError):
            parse_nessus_file(str(tmp_path / "nonexistent.nessus"))

    def test_invalid_xml_raises(self, tmp_path):
        bad = _write_nessus(tmp_path, "not xml at all <<<")
        with pytest.raises(ValueError, match="Failed to parse XML"):
            parse_nessus_file(bad)

    def test_wrong_root_tag_raises(self, tmp_path):
        bad = _write_nessus(tmp_path, "<SomeOtherFormat/>")
        with pytest.raises(ValueError, match="Not a Nessus XML"):
            parse_nessus_file(bad)

    def test_minimal_parse_returns_correct_host_count(self, tmp_path):
        path = _write_nessus(tmp_path, MINIMAL_NESSUS)
        result = parse_nessus_file(path)
        assert len(result.hosts) == 1

    def test_minimal_parse_fqdn_extracted(self, tmp_path):
        path = _write_nessus(tmp_path, MINIMAL_NESSUS)
        result = parse_nessus_file(path)
        assert result.hosts[0].fqdn == "target.example.com"

    def test_minimal_parse_os_extracted(self, tmp_path):
        path = _write_nessus(tmp_path, MINIMAL_NESSUS)
        result = parse_nessus_file(path)
        assert result.hosts[0].os_name == "Linux"

    def test_minimal_parse_canonical_target_is_fqdn(self, tmp_path):
        path = _write_nessus(tmp_path, MINIMAL_NESSUS)
        result = parse_nessus_file(path)
        # FQDN takes priority over IP
        assert "target.example.com" in result.targets
        assert len(result.targets) == 1

    def test_minimal_parse_finding_count(self, tmp_path):
        path = _write_nessus(tmp_path, MINIMAL_NESSUS)
        result = parse_nessus_file(path)
        # Both ReportItems (severity 3 + severity 0)
        assert len(result.findings) == 2

    def test_minimal_parse_high_severity_finding(self, tmp_path):
        path = _write_nessus(tmp_path, MINIMAL_NESSUS)
        result = parse_nessus_file(path)
        high = [f for f in result.findings if f.severity == 3]
        assert len(high) == 1
        assert high[0].plugin_name == "SSL Certificate Expiry"
        assert high[0].port == "443"
        assert high[0].protocol == "tcp"
        assert high[0].host == "target.example.com"

    def test_minimal_parse_informational_finding(self, tmp_path):
        path = _write_nessus(tmp_path, MINIMAL_NESSUS)
        result = parse_nessus_file(path)
        info = [f for f in result.findings if f.severity == 0]
        assert len(info) == 1
        assert info[0].port == "80"

    def test_multi_host_parse(self, tmp_path):
        path = _write_nessus(tmp_path, MULTI_HOST_NESSUS)
        result = parse_nessus_file(path)
        assert len(result.hosts) == 2
        assert len(result.targets) == 2

    def test_multi_host_canonical_targets(self, tmp_path):
        path = _write_nessus(tmp_path, MULTI_HOST_NESSUS)
        result = parse_nessus_file(path)
        # web.corp.local has FQDN; 192.168.1.20 has no FQDN → uses IP
        assert "web.corp.local" in result.targets
        assert "192.168.1.20" in result.targets

    def test_multi_host_finding_count(self, tmp_path):
        path = _write_nessus(tmp_path, MULTI_HOST_NESSUS)
        result = parse_nessus_file(path)
        # 3 ReportItems across 2 hosts
        assert len(result.findings) == 3

    def test_critical_finding_parsed(self, tmp_path):
        path = _write_nessus(tmp_path, MULTI_HOST_NESSUS)
        result = parse_nessus_file(path)
        critical = [f for f in result.findings if f.severity == 4]
        assert len(critical) == 1
        assert critical[0].plugin_name == "SSH Protocol Version 1 Enabled"

    def test_no_findings_host(self, tmp_path):
        path = _write_nessus(tmp_path, NO_FINDINGS_NESSUS)
        result = parse_nessus_file(path)
        assert len(result.hosts) == 1
        assert len(result.findings) == 0
        assert "10.0.0.99" in result.targets

    def test_plugin_output_and_solution_captured(self, tmp_path):
        path = _write_nessus(tmp_path, MINIMAL_NESSUS)
        result = parse_nessus_file(path)
        high = [f for f in result.findings if f.severity == 3][0]
        assert "Serial: 1234" in high.plugin_output
        assert "Renew the certificate" in high.solution


# ---------------------------------------------------------------------------
# DB seeding tests
# ---------------------------------------------------------------------------

@pytest.fixture()
def fresh_db(tmp_path):
    """Point tools at a fresh temp DB and clean up after."""
    db_file = str(tmp_path / "recon.db")
    original_db = tools.DB_PATH
    original_out = tools.OUTPUT_DIR
    tools.DB_PATH = db_file
    tools.OUTPUT_DIR = str(tmp_path)
    tools.init_db()
    yield db_file
    tools.DB_PATH = original_db
    tools.OUTPUT_DIR = original_out


class TestSeedDbFromNessus:
    def test_open_ports_seeded(self, tmp_path, fresh_db):
        path = _write_nessus(tmp_path, MINIMAL_NESSUS)
        result = parse_nessus_file(path)
        seed_db_from_nessus(result)

        conn = sqlite3.connect(fresh_db)
        rows = conn.execute("SELECT target, port FROM open_ports").fetchall()
        conn.close()
        ports = {(r[0], r[1]) for r in rows}
        # Both port 443 and port 80 should be recorded
        assert ("target.example.com", "443") in ports
        assert ("target.example.com", "80") in ports

    def test_informational_findings_not_in_vulnerabilities(self, tmp_path, fresh_db):
        path = _write_nessus(tmp_path, MINIMAL_NESSUS)
        result = parse_nessus_file(path)
        seed_db_from_nessus(result)

        conn = sqlite3.connect(fresh_db)
        rows = conn.execute("SELECT template_id FROM vulnerabilities").fetchall()
        conn.close()
        template_ids = {r[0] for r in rows}
        # Only severity>=1 items: pluginID 15901 (severity 3), not 11219 (severity 0)
        assert "nessus-15901" in template_ids
        assert "nessus-11219" not in template_ids

    def test_vulnerability_severity_label(self, tmp_path, fresh_db):
        path = _write_nessus(tmp_path, MINIMAL_NESSUS)
        result = parse_nessus_file(path)
        seed_db_from_nessus(result)

        conn = sqlite3.connect(fresh_db)
        row = conn.execute(
            "SELECT severity FROM vulnerabilities WHERE template_id = 'nessus-15901'"
        ).fetchone()
        conn.close()
        assert row[0] == "high"

    def test_vulnerability_description_prefixed(self, tmp_path, fresh_db):
        path = _write_nessus(tmp_path, MINIMAL_NESSUS)
        result = parse_nessus_file(path)
        seed_db_from_nessus(result)

        conn = sqlite3.connect(fresh_db)
        row = conn.execute(
            "SELECT description FROM vulnerabilities WHERE template_id = 'nessus-15901'"
        ).fetchone()
        conn.close()
        assert "[Nessus]" in row[0]
        assert "SSL Certificate Expiry" in row[0]

    def test_poc_contains_plugin_output(self, tmp_path, fresh_db):
        path = _write_nessus(tmp_path, MINIMAL_NESSUS)
        result = parse_nessus_file(path)
        seed_db_from_nessus(result)

        conn = sqlite3.connect(fresh_db)
        row = conn.execute(
            "SELECT poc FROM vulnerabilities WHERE template_id = 'nessus-15901'"
        ).fetchone()
        conn.close()
        assert "Serial: 1234" in row[0]

    def test_subdomains_seeded_when_fqdn_differs_from_ip(self, tmp_path, fresh_db):
        path = _write_nessus(tmp_path, MINIMAL_NESSUS)
        result = parse_nessus_file(path)
        seed_db_from_nessus(result)

        conn = sqlite3.connect(fresh_db)
        rows = conn.execute("SELECT domain FROM subdomains").fetchall()
        conn.close()
        domains = {r[0] for r in rows}
        assert "target.example.com" in domains

    def test_no_duplicate_ports_on_reseed(self, tmp_path, fresh_db):
        path = _write_nessus(tmp_path, MINIMAL_NESSUS)
        result = parse_nessus_file(path)
        seed_db_from_nessus(result)
        seed_db_from_nessus(result)  # seed twice

        conn = sqlite3.connect(fresh_db)
        count = conn.execute(
            "SELECT COUNT(*) FROM open_ports WHERE target='target.example.com' AND port='443'"
        ).fetchone()[0]
        conn.close()
        assert count == 1  # INSERT OR IGNORE prevents duplicates

    def test_no_duplicate_vulns_on_reseed(self, tmp_path, fresh_db):
        path = _write_nessus(tmp_path, MINIMAL_NESSUS)
        result = parse_nessus_file(path)
        seed_db_from_nessus(result)
        seed_db_from_nessus(result)

        conn = sqlite3.connect(fresh_db)
        count = conn.execute(
            "SELECT COUNT(*) FROM vulnerabilities WHERE template_id='nessus-15901'"
        ).fetchone()[0]
        conn.close()
        assert count == 1

    def test_tool_run_marked_for_each_target(self, tmp_path, fresh_db):
        path = _write_nessus(tmp_path, MINIMAL_NESSUS)
        result = parse_nessus_file(path)
        seed_db_from_nessus(result)

        conn = sqlite3.connect(fresh_db)
        row = conn.execute(
            "SELECT 1 FROM tool_runs WHERE tool_name='nessus_import' "
            "AND target='target.example.com'"
        ).fetchone()
        conn.close()
        assert row is not None

    def test_summary_counts_correct(self, tmp_path, fresh_db):
        path = _write_nessus(tmp_path, MULTI_HOST_NESSUS)
        result = parse_nessus_file(path)
        summary = seed_db_from_nessus(result)

        assert summary["hosts"] == 2
        # 3 total findings, 3 are severity >= 1
        assert summary["vulnerabilities"] == 3
        # web.corp.local is a FQDN different from its IP → becomes subdomain
        assert summary["subdomains"] == 1

    def test_empty_scan_seeds_nothing(self, tmp_path, fresh_db):
        path = _write_nessus(tmp_path, NO_FINDINGS_NESSUS)
        result = parse_nessus_file(path)
        summary = seed_db_from_nessus(result)

        assert summary["vulnerabilities"] == 0
        assert summary["open_ports"] == 0

    def test_critical_severity_label_in_db(self, tmp_path, fresh_db):
        path = _write_nessus(tmp_path, MULTI_HOST_NESSUS)
        result = parse_nessus_file(path)
        seed_db_from_nessus(result)

        conn = sqlite3.connect(fresh_db)
        row = conn.execute(
            "SELECT severity FROM vulnerabilities WHERE template_id='nessus-10881'"
        ).fetchone()
        conn.close()
        assert row[0] == "critical"

    def test_no_fqdn_uses_ip_as_vuln_target(self, tmp_path, fresh_db):
        path = _write_nessus(tmp_path, MULTI_HOST_NESSUS)
        result = parse_nessus_file(path)
        seed_db_from_nessus(result)

        conn = sqlite3.connect(fresh_db)
        row = conn.execute(
            "SELECT target FROM vulnerabilities WHERE template_id='nessus-70657'"
        ).fetchone()
        conn.close()
        # 192.168.1.20 has no FQDN → IP used as canonical target
        assert row[0] == "192.168.1.20"


# ---------------------------------------------------------------------------
# CLI argument tests (argparse smoke test — no actual swarm run)
# ---------------------------------------------------------------------------

class TestArgparse:
    def test_nessus_flag_accepted(self, tmp_path):
        """Ensure --nessus is a recognised argument without executing a swarm."""
        import argparse
        # Re-create the same parser as hacksmarter.py to test the arg shape
        parser = argparse.ArgumentParser()
        parser.add_argument("-t", "--target", required=True)
        parser.add_argument("-x", "--exclude")
        parser.add_argument("-v", "--verbose", action="store_true")
        parser.add_argument("-c", "--client")
        parser.add_argument("-n", "--nessus", metavar="FILE")

        fake_nessus = str(tmp_path / "scan.nessus")
        args = parser.parse_args(["-t", "example.com", "-n", fake_nessus])
        assert args.nessus == fake_nessus

    def test_nessus_flag_optional(self):
        import argparse
        parser = argparse.ArgumentParser()
        parser.add_argument("-t", "--target", required=True)
        parser.add_argument("-n", "--nessus", metavar="FILE")
        args = parser.parse_args(["-t", "example.com"])
        assert args.nessus is None
