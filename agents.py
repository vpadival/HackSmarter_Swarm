"""
agents.py — LangGraph nodes for HackSmarter Swarm.

Key fixes applied
-----------------
1. strategy_node now calls the LLM with structured output (StrategyDecision)
   to make a real pivot/complete decision instead of the hardcoded "PIVOT".
2. Tool exclusion uses a single normalised helper (_is_excluded) everywhere,
   removing the inconsistency between filter_tools() and the inline checks.
3. All bare print() calls replaced with logger calls.
"""

import json
import logging
import os

from dotenv import load_dotenv

load_dotenv()

from pydantic import BaseModel, Field
from typing import Literal, Optional

from langchain_google_genai import ChatGoogleGenerativeAI
from langgraph.prebuilt import create_react_agent

from state import PentestState
from tools import (
    DB_PATH,
    add_vulnerability_tool,
    execute_curl_request,
    filter_live_targets_httpx,
    format_scope_tool,
    is_already_run,
    mark_as_run,
    run_dehashed_tool,
    run_feroxbuster_tool,
    run_hydra_check,
    run_nc_banner_grab,
    run_nmap_tool,
    run_nuclei_tool,
    run_ssh_audit,
    run_subfinder_tool,
    run_testssl_verification,
    run_wpscan_tool,
    run_httpx_tool,
    update_db,
)
import tools  # for tools.OUTPUT_DIR / tools.DB_PATH

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------
logger = logging.getLogger("hacksmarter.agents")

# ---------------------------------------------------------------------------
# LLM initialisation
# ---------------------------------------------------------------------------
llm = ChatGoogleGenerativeAI(model="gemini-2.5-flash", temperature=0)


# ---------------------------------------------------------------------------
# Structured output schema for the strategy node
# ---------------------------------------------------------------------------

class StrategyDecision(BaseModel):
    status: Literal["complete", "pivot"] = Field(
        description=(
            "Choose 'complete' if sufficient high-value findings exist or the scan "
            "has stagnated. Choose 'pivot' to run another recon loop."
        )
    )
    pivot_directives: Optional[str] = Field(
        default=None,
        description=(
            "If pivoting, give explicit instructions for the Recon Agent "
            "(e.g. 'Brute force directories on 192.168.1.5:8443')."
        ),
    )
    markdown_report: Optional[str] = Field(
        default=None,
        description="If complete, a professional pentest summary in Markdown.",
    )
    dradis_json: Optional[dict] = Field(
        default=None,
        description="If complete, structured findings JSON for Dradis Pro ingestion.",
    )


# ---------------------------------------------------------------------------
# Tool-exclusion helpers  (single consistent implementation)
# ---------------------------------------------------------------------------

def _is_excluded(tool_name: str, excluded_list: list) -> bool:
    """
    Return True if *tool_name* matches any entry in *excluded_list*
    (case-insensitive substring match).
    """
    if not excluded_list:
        return False
    name_lower = tool_name.lower()
    return any(ex.lower() in name_lower for ex in excluded_list)


def _filter_tools(tool_list: list, excluded_list: list) -> list:
    """Remove tools whose names match any entry in *excluded_list*."""
    if not excluded_list:
        return tool_list
    kept = []
    for t in tool_list:
        if _is_excluded(t.name, excluded_list):
            logger.info("Tool excluded: %s", t.name)
        else:
            kept.append(t)
    return kept


# ---------------------------------------------------------------------------
# DB read helper
# ---------------------------------------------------------------------------

def get_db_data() -> dict:
    """Return the current findings from the SQLite database as a dict."""
    import sqlite3

    db: dict = {
        "subdomains": [],
        "open_ports": [],
        "vulnerabilities": [],
        "interesting_files": [],
        "leaked_credentials": [],
        "tool_runs": {},
    }

    if not os.path.exists(tools.DB_PATH):
        return db

    conn = sqlite3.connect(tools.DB_PATH)
    c = conn.cursor()
    try:
        c.execute("SELECT domain FROM subdomains")
        db["subdomains"] = [r[0] for r in c.fetchall()]

        c.execute("SELECT target, port FROM open_ports")
        db["open_ports"] = [{"target": r[0], "port": r[1]} for r in c.fetchall()]

        c.execute(
            "SELECT target, template_id, severity, description, poc FROM vulnerabilities"
        )
        db["vulnerabilities"] = [
            {
                "target": r[0],
                "template": r[1],
                "severity": r[2],
                "description": r[3],
                "poc": r[4],
            }
            for r in c.fetchall()
        ]

        c.execute("SELECT target, url, comment FROM interesting_files")
        db["interesting_files"] = [
            {"target": r[0], "url": r[1], "comment": r[2]} for r in c.fetchall()
        ]

        c.execute(
            "SELECT domain, email, username, password, hashed_password, source "
            "FROM leaked_credentials"
        )
        db["leaked_credentials"] = [
            {
                "domain": r[0],
                "email": r[1],
                "username": r[2],
                "password": r[3],
                "hashed_password": r[4],
                "source": r[5],
            }
            for r in c.fetchall()
        ]

        c.execute("SELECT tool_name, target FROM tool_runs")
        tool_runs: dict = {}
        for tool_name, tgt in c.fetchall():
            tool_runs.setdefault(tool_name, []).append(tgt)
        db["tool_runs"] = tool_runs

    except Exception as exc:
        logger.error("get_db_data error: %s", exc)
    finally:
        conn.close()

    return db


# ---------------------------------------------------------------------------
# Nodes
# ---------------------------------------------------------------------------

def strategy_node(state: PentestState):
    logger.info("--- [NODE: STRATEGY & REPORTING] ---")

    current_vulns = state.get("vulnerabilities", [])
    current_vuln_count = len(current_vulns)
    last_count = state.get("last_vuln_count", -1)

    # Deterministic stagnation guard — if no new findings, force completion.
    if current_vuln_count == last_count:
        logger.warning("Stagnation detected: no new findings. Forcing completion.")
        return _write_reports(state, current_vuln_count)

    # --- FIX: use the LLM with structured output to make the real decision ---
    db = get_db_data()
    structured_llm = llm.with_structured_output(StrategyDecision)

    decision_prompt = (
        "You are a Senior Penetration Test Lead reviewing the current findings of an "
        "automated recon-and-vulnerability assessment.\n\n"
        "Current findings:\n"
        f"{json.dumps(db, indent=2)}\n\n"
        "Decide whether the assessment is 'complete' (enough high-value findings have "
        "been collected, or further pivoting is unlikely to yield new results) or "
        "'pivot' (meaningful new attack surface is likely to be uncovered by another "
        "recon loop).\n\n"
        "If pivoting, provide explicit directives for the Recon Agent."
    )

    try:
        decision: StrategyDecision = structured_llm.invoke(decision_prompt)
        logger.info("LLM strategy decision: %s", decision.status)
    except Exception as exc:
        logger.error("Strategy LLM call failed (%s) — defaulting to pivot.", exc)
        return {
            "current_phase": "TACTICAL_RECON",
            "last_vuln_count": current_vuln_count,
        }

    if decision.status == "complete":
        return _write_reports(state, current_vuln_count, decision)

    # Pivot — pass directives to the next recon loop
    return {
        "current_phase": "TACTICAL_RECON",
        "strategy_directives": decision.pivot_directives or "",
        "last_vuln_count": current_vuln_count,
    }


def _write_reports(
    state: PentestState,
    current_vuln_count: int,
    decision: Optional[StrategyDecision] = None,
) -> dict:
    """Generate and persist the Markdown and Dradis JSON reports."""
    logger.info("Assembling final pentest reports…")
    db = get_db_data()

    dradis_path = os.path.join(tools.OUTPUT_DIR, "dradis_import.json")
    report_path = os.path.join(tools.OUTPUT_DIR, "final_report.md")

    with open(dradis_path, "w") as f:
        json.dump(db, f, indent=4)

    # Use the LLM's markdown if it provided one; otherwise generate fresh.
    if decision and decision.markdown_report:
        final_md = decision.markdown_report
    else:
        report_prompt = (
            "You are a Senior Security Consultant. Write a professional Executive "
            "Summary based on the following pentest data. Include a vulnerability "
            "table with columns: Target | Vulnerability | Severity | Reproduction (PoC).\n\n"
            f"Raw Data:\n{json.dumps(db)}"
        )
        response = llm.invoke(report_prompt)
        final_md = (
            response.content
            if isinstance(response.content, str)
            else response.content[0].get("text", "")
        )

    with open(report_path, "w") as f:
        f.write(final_md)

    logger.info(
        "Reports saved: %s, %s", dradis_path, report_path
    )

    return {
        "current_phase": "COMPLETE",
        "last_vuln_count": current_vuln_count,
    }


def recon_node(state: PentestState):
    logger.info("--- [NODE: TACTICAL RECON] ---")

    excluded = state.get("excluded_tools", [])
    all_recon_tools = [
        run_subfinder_tool,
        run_nmap_tool,
        format_scope_tool,
        run_wpscan_tool,
        run_feroxbuster_tool,
        run_httpx_tool,
        run_dehashed_tool,
    ]
    recon_tools = _filter_tools(all_recon_tools, excluded)

    directives = (
        state.get("strategy_directives") or "Perform initial discovery on the target."
    )
    known_subs = state.get("subdomains", [])
    subdomain_ctx = (
        f"\nKnown subdomains: {', '.join(known_subs)}" if known_subs else ""
    )

    system_prompt = (
        f"You are a Tactical Recon Specialist. Current objective: {directives}\n"
        "Find subdomains, scan ports, check for WordPress vulnerabilities, and query "
        "Dehashed for leaked credentials associated with the target domain.\n\n"
        "### STRICT RULES ###\n"
        "1. ONLY scan the primary target and subdomains returned by subfinder.\n"
        "2. Use run_httpx_tool to verify a target is live BEFORE running feroxbuster "
        "or wpscan on it.\n"
        "3. If subfinder returns 0 subdomains, only the primary target is in scope.\n"
        "4. Always run run_dehashed_tool on the primary target domain to check for "
        "leaked credentials in breach databases.\n"
        f"{subdomain_ctx}\n"
        "When finished, summarise all findings including any leaked credentials."
    )

    agent = create_react_agent(llm, recon_tools, prompt=system_prompt)
    result = agent.invoke({"messages": [("user", f"Target: {state['target_domain']}")]})

    summary = result["messages"][-1].content
    logger.info("Recon summary: %s", summary)

    db = get_db_data()
    return {
        "subdomains": db["subdomains"],
        "open_ports": db["open_ports"],
        "interesting_files": db.get("interesting_files", []),
        "leaked_credentials": db.get("leaked_credentials", []),
        "current_phase": "recon_conducted",
    }


def vuln_node(state: PentestState):
    logger.info("--- [NODE: VULN ANALYSIS] ---")

    excluded = state.get("excluded_tools", [])

    # Build target matrix from discovered ports and subdomains
    targets_to_scan: set = set()
    for port_data in state.get("open_ports", []):
        port = str(port_data.get("port"))
        target = port_data.get("target")
        if port in ("80", "8080"):
            targets_to_scan.add(f"http://{target}:{port}")
        elif port in ("443", "8443"):
            targets_to_scan.add(f"https://{target}:{port}")

    for sub in state.get("subdomains", []):
        targets_to_scan.add(f"http://{sub}:80")
        targets_to_scan.add(f"https://{sub}:443")

    if not targets_to_scan:
        logger.info("No web targets to scan.")
        return {"current_phase": "vuln_complete"}

    live_targets = filter_live_targets_httpx(list(targets_to_scan))
    if not live_targets:
        logger.info("httpx found 0 live targets — skipping Nuclei.")
        return {"current_phase": "vuln_complete"}

    # --- Nuclei ---
    # FIX: use _is_excluded() with the tool's actual function name for consistency
    if not _is_excluded("run_nuclei_tool", excluded):
        new_nuclei_targets = [u for u in live_targets if not is_already_run("nuclei", u)]
        if new_nuclei_targets:
            logger.info("Nuclei scanning %d new targets…", len(new_nuclei_targets))
            run_nuclei_tool.invoke({
                "targets": new_nuclei_targets,
                "verbose": state.get("verbose", False),
            })
            for t in new_nuclei_targets:
                mark_as_run("nuclei", t)
        else:
            logger.info("All live targets already scanned by Nuclei.")
    else:
        logger.info("Nuclei excluded by user.")

    # --- Feroxbuster ---
    if not _is_excluded("run_feroxbuster_tool", excluded):
        new_ferox_targets = [u for u in live_targets if not is_already_run("feroxbuster", u)]
        if new_ferox_targets:
            logger.info("Feroxbuster scanning %d new targets…", len(new_ferox_targets))
            run_feroxbuster_tool.invoke({
                "url": new_ferox_targets,
                "verbose": state.get("verbose", False),
            })
        else:
            logger.info("All live targets already scanned by feroxbuster.")
    else:
        logger.info("Feroxbuster excluded by user.")

    db = get_db_data()
    current_vulns = db.get("vulnerabilities", [])
    interesting_files = db.get("interesting_files", [])

    if not current_vulns and not interesting_files:
        logger.info("No vulnerabilities or interesting files to verify.")
        return {"vulnerabilities": [], "current_phase": "vuln_complete"}

    logger.info(
        "%d potential vulns, %d interesting files — starting verification…",
        len(current_vulns),
        len(interesting_files),
    )

    all_verification_tools = [
        execute_curl_request,
        run_nmap_tool,
        run_nc_banner_grab,
        run_ssh_audit,
        run_hydra_check,
        run_testssl_verification,
        add_vulnerability_tool,
    ]
    verification_tools = _filter_tools(all_verification_tools, excluded)

    system_prompt = (
        "You are a Senior Penetration Tester verifying findings.\n\n"
        "TYPES OF FINDINGS TO VERIFY:\n"
        "1. Nuclei Vulnerabilities — standard automated findings.\n"
        "2. Interesting Files — discovered by feroxbuster (e.g. .env, .git, backups). "
        "Use execute_curl_request to inspect these.\n\n"
        "### SENSITIVE DATA ###\n"
        "If execute_curl_request reveals secrets (API keys, passwords, PII), you MUST "
        "call add_vulnerability_tool to record the finding.\n\n"
        "### POC REQUIREMENT ###\n"
        "For every verified finding provide:\n"
        "1. The EXACT command used.\n"
        "2. The specific output confirming the vulnerability.\n"
    )

    agent = create_react_agent(llm, verification_tools, prompt=system_prompt)
    result = agent.invoke({
        "messages": [(
            "user",
            f"Verify findings:\n\n### NUCLEI ###\n{current_vulns}"
            f"\n\n### INTERESTING FILES ###\n{interesting_files}",
        )]
    })

    summary = result["messages"][-1].content
    clean = (
        summary if isinstance(summary, str)
        else summary[0].get("text", str(summary))
    )
    logger.info("Verification summary:\n%s", clean)

    return {
        "vulnerabilities": db.get("vulnerabilities", []),
        "current_phase": "vuln_complete",
    }