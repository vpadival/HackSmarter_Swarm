# agents.py
from dotenv import load_dotenv
import os
import json
import time 

load_dotenv()

from state import PentestState
from tools import (
    format_scope_tool, run_subfinder_tool, run_nmap_tool, run_wpscan_tool,
    run_nuclei_tool, execute_curl_request, filter_live_targets_httpx,
    run_nc_banner_grab, run_ssh_audit, run_hydra_check,
    run_testssl_verification, run_feroxbuster_tool, run_httpx_tool, add_vulnerability_tool, DB_PATH, update_db,
    is_already_run, mark_as_run
)
import tools # Added to support tools.OUTPUT_DIR and tools.DB_PATH
from langchain_google_genai import ChatGoogleGenerativeAI
from langgraph.prebuilt import create_react_agent
from pydantic import BaseModel, Field
from typing import Optional, Literal

# Initialize the Gemini Model (Make sure your GOOGLE_API_KEY is in your environment vars)
llm = ChatGoogleGenerativeAI(model="gemini-2.5-pro", temperature=0)

# 1. Define the exact structure we want Gemini to output
class StrategyDecision(BaseModel):
    status: Literal["complete", "pivot"] = Field(description="Choose 'complete' if enough high-value data is found, or 'pivot' to run deeper recon.")
    pivot_directives: Optional[str] = Field(description="If pivoting, give explicit instructions for the Recon Agent (e.g., 'Brute force directories on 192.168.1.5:8443').")
    markdown_report: Optional[str] = Field(description="If complete, write a professional pentest summary in Markdown.")
    dradis_json: Optional[dict] = Field(description="If complete, output a structured JSON representing the findings, suitable for Dradis Pro ingestion.")

def get_db_data():
    """Helper to read the current findings from disk."""
    # Default structure to ensure all state keys exist
    default_db = {
        "subdomains": [], 
        "open_ports": [], 
        "vulnerabilities": [],
        "interesting_files": [],
        "scanned_targets": [],
        "tool_runs": {}
    }
    
    if os.path.exists(tools.DB_PATH):
        with open(tools.DB_PATH, "r") as f:
            try:
                data = json.load(f)
                # Merge loaded data into the default structure
                default_db.update(data)
                return default_db
            except json.JSONDecodeError:
                pass
    return default_db

def filter_tools(tools: list, excluded_names: list) -> list:
    """Filters a list of tools based on excluded substrings."""
    if not excluded_names:
        return tools
    
    filtered = []
    for tool in tools:
        # Check if any excluded string is in the tool's name
        should_exclude = any(name.lower() in tool.name.lower() for name in excluded_names)
        if not should_exclude:
            filtered.append(tool)
        else:
            print(f"[!] Tool Exclusion: Skipping tool '{tool.name}'")
            
    return filtered

def is_tool_excluded(tool_name: str, excluded_list: list) -> bool:
    """Checks if a tool name (or common substring) is in the excluded list."""
    if not excluded_list:
        return False
    # If the tool name itself is in excluded, or if an exclusion matches a substring
    return any(ex.lower() in tool_name.lower() for ex in excluded_list)

def strategy_node(state: PentestState):
    print("\n--- [NODE: STRATEGY & REPORTING] ---")
    
    # 1. Gather current metrics
    current_subdomains = state.get("subdomains", [])
    current_ports = state.get("open_ports", [])
    current_vulns = state.get("vulnerabilities", [])
    current_files = state.get("interesting_files", [])
    
    current_vuln_count = len(current_vulns)
    last_count = state.get("last_vuln_count", -1) # Default to -1 on the very first pass
    
    # 2. Deterministic Guardrail
    force_complete = False
    if current_vuln_count == last_count:
        print("[!] Stagnation detected: No new findings. Forcing completion.")
        force_complete = True

    # Define the default AI decision to prevent the NameError
    # (If you add an LLM prompt here later to make a choice, it will overwrite this)
    decision = "PIVOT" 

    # 3. The Exit & Reporting Hook
    if force_complete or decision == "COMPLETE":
        print("\n[*] Assembling final pentest reports...")
        db = get_db_data()
        
        # Generate paths
        dradis_path = os.path.join(tools.OUTPUT_DIR, "dradis_import.json")
        report_path = os.path.join(tools.OUTPUT_DIR, "final_report.md")
        
        # Generate the Machine-Readable Report (Dradis/JSON)
        with open(dradis_path, "w") as f:
            json.dump(db, f, indent=4)
            
        # Generate the Human-Readable Report (Markdown)
        report_prompt = (
            "You are a Senior Security Consultant. Write a professional Executive Summary "
            "based on the following pentest data. You MUST include a table of vulnerabilities.\n\n"
            "The table should have these columns: Target, Vulnerability, Severity, and Reproduction (PoC).\n"
            "In the 'Reproduction' column, provide the exact commands or steps needed for a human "
            "to reproduce the finding. Use code blocks for commands.\n\n"
            f"Raw Data: {json.dumps(db)}"
        )
        final_report_md = llm.invoke(report_prompt).content
        
        with open(report_path, "w") as f:
            # Clean up the markdown text just in case there's a signature
            clean_md = final_report_md if isinstance(final_report_md, str) else final_report_md[0].get("text", "")
            f.write(clean_md)
            
        print("[*] SUCCESS: dradis_import.json and final_report.md have been saved to disk.")
        
        return {
            "current_phase": "COMPLETE",
            "last_vuln_count": current_vuln_count
        }

    # 4. If not complete, print status and keep looping
    if not force_complete:
        print(f"[*] Strategy Decision: {decision} (Continuing scan...)")
        
    return {
        "current_phase": "TACTICAL_RECON",
        "last_vuln_count": current_vuln_count
    }

def recon_node(state: PentestState):
    print("\n--- [NODE: TACTICAL RECON] ---")
    
    initial_recon_tools = [
        run_subfinder_tool, run_nmap_tool, format_scope_tool, 
        run_wpscan_tool, run_feroxbuster_tool, run_httpx_tool
    ]
    recon_tools = filter_tools(initial_recon_tools, state.get("excluded_tools", []))
    directives = state.get("strategy_directives") or "Perform initial discovery on the target."
    
    discovered_subdomains = state.get("subdomains", [])
    subdomain_context = f"\nKnown/Discovered Subdomains: {', '.join(discovered_subdomains)}" if discovered_subdomains else ""

    system_prompt = (
        f"You are a Tactical Recon Specialist. Current objective: {directives}\n"
        "Analyze the target, find subdomains, scan for ports, and check for WordPress vulnerabilities.\n\n"
        "### STRICT OPERATIONAL RULES ###\n"
        "1. NO GUESSING: You must ONLY scan the primary target and subdomains that were returned by subfinder. "
        "Do NOT assume subdomains like 'dev', 'internal', or 'test' exist unless subfinder actually found them.\n"
        "2. VERIFY BEFORE SCANNING: Use run_httpx_tool to verify if a discovered subdomain or port is hosting a live web server "
        "BEFORE attempting to run feroxbuster or wpscan on it.\n"
        "3. SUBDOMAIN CONTEXT: Rely on the tools' output. If subfinder returns 0 subdomains, then you only have the primary target to scan.\n"
        f"{subdomain_context}\n"
        "If you identify a live web server, you should also perform directory discovery using feroxbuster. "
        "When you are finished, summarize what you found."
    )

    recon_agent = create_react_agent(llm, recon_tools, prompt=system_prompt)

    # Execute the agent
    result = recon_agent.invoke({
        "messages": [("user", f"Target: {state['target_domain']}")]
    })

    # NEW: Print the Agent's final response so you can see its summary!
    final_msg = result["messages"][-1].content
    print(f"[*] Tactical Recon Summary: {final_msg}")

    # Sync state with our Source of Truth (the DB)
    db = get_db_data()
    return {
        "subdomains": db["subdomains"],
        "open_ports": db["open_ports"],
        "interesting_files": db.get("interesting_files", []),
        "current_phase": "recon_conducted"
    }

def vuln_node(state: PentestState):
    """
    Vuln Worker: Compiles a comprehensive target list, runs Nuclei, 
    and uses Gemini to verify findings.
    """
    print("\n--- [NODE: VULN ANALYSIS] ---")
    
    # 1. Compile the Target Matrix (Using a set to avoid duplicates)
    targets_to_scan = set()

    # Add explicitly discovered web ports from nmap
    for port_data in state.get("open_ports", []):
        port = str(port_data.get("port"))
        target = port_data.get("target")
        if port in ["80", "443", "8080", "8443"]:
            protocol = "https" if port in ["443", "8443"] else "http"
            targets_to_scan.add(f"{protocol}://{target}:{port}")

    # Add a baseline "blind sweep" for all discovered subdomains
    for sub in state.get("subdomains", []):
        # We can add both back in now, because HTTPX will filter out the dead ones instantly!
        targets_to_scan.add(f"http://{sub}:80")
        targets_to_scan.add(f"https://{sub}:443")

    if not targets_to_scan:
        print("[-] No web targets to scan. Skipping.")
        return {"current_phase": "vuln_complete"}

    # ==========================================
    # THE HTTPX BOUNCER
    # ==========================================
    live_targets = filter_live_targets_httpx(list(targets_to_scan))
    
    if not live_targets:
        print("[-] HTTPX found 0 live web servers. Skipping Nuclei.")
        return {"current_phase": "vuln_complete"}

    # ==========================================
    # THE SCAN LEDGER (UPDATED)
    # ==========================================
    # Filter out targets we've already scanned in previous loops
    new_targets = [url for url in live_targets if not is_already_run("nuclei", url)]
    
    excluded = [e.lower() for e in state.get("excluded_tools", [])]
    if is_tool_excluded("run_nuclei_tool", excluded):
        print("[!] Tool Exclusion: Skipping automated Nuclei scan.")
        new_targets = []

    if not new_targets:
        print(f"[-] All {len(live_targets)} live targets have already been scanned by Nuclei. Skipping heavy scan.")
    else:
        print(f"[*] Executing Nuclei on {len(new_targets)} NEW live targets...")
        
        # 2. Aggregated Execution: Run Nuclei ONCE on all new targets
        run_nuclei_tool.invoke({"targets": new_targets, "verbose": state.get("verbose")})
            
        # Log these new targets to the ledger
        for target in new_targets:
            mark_as_run("nuclei", target)
        
    # ==========================================
    # THE FEROXBUSTER BULK DISCOVERY (NEW)
    # ==========================================
    # Filter for targets not yet scanned by feroxbuster
    feroxbuster_targets = [url for url in live_targets if not is_already_run("feroxbuster", url)]
    
    if is_tool_excluded("run_feroxbuster_tool", excluded):
        print("[!] Tool Exclusion: Skipping automated feroxbuster scan.")
        feroxbuster_targets = []
        
    if feroxbuster_targets:
        print(f"[*] Executing Bulk Feroxbuster on {len(feroxbuster_targets)} targets...")
        run_feroxbuster_tool.invoke({"url": feroxbuster_targets, "verbose": state.get("verbose")})
    else:
        print(f"[-] All {len(live_targets)} live targets have already been scanned by feroxbuster. Skipping.")

    db = get_db_data()
    current_vulns = db.get("vulnerabilities", [])
    interesting_files = db.get("interesting_files", [])

    if not current_vulns and not interesting_files:
         print("[-] No vulnerabilities or interesting files found to verify.")
         return {
             "vulnerabilities": [], 
             "current_phase": "vuln_complete"
         }

    print(f"[*] DB holds {len(current_vulns)} potential vulns and {len(interesting_files)} interesting files. Waking up Gemini for verification...")

    # 4. LLM Execution: Verify Findings
    initial_verification_tools = [
        execute_curl_request, 
        run_nmap_tool, 
        run_nc_banner_grab, 
        run_ssh_audit, 
        run_hydra_check, 
        run_testssl_verification,
        add_vulnerability_tool
    ]
    verification_tools = filter_tools(initial_verification_tools, state.get("excluded_tools", []))
    
    system_prompt = (
    "You are a Senior Penetration Tester. Your goal is to verify findings.\n\n"
    "TYPES OF FINDINGS TO VERIFY:\n"
    "1. Nuclei Vulnerabilities: Standard automated findings.\n"
    "2. Interesting Files: Discovered by feroxbuster (e.g., .env, .git, backups). You MUST use execute_curl_request to inspect these files.\n\n"
    "### CRITICAL REQUIREMENT: SENSITIVE INFO DISCOVERY ###\n"
    "If you use execute_curl_request and discover sensitive information (API keys, passwords, database credentials, PII, etc.), "
    "you MUST use add_vulnerability_tool to manually add this finding to the database.\n\n"
    "### POC REQUIREMENT ###\n"
    "For every verified finding (automated or manual), you must provide a 'Proof of Concept' (PoC).\n"
    "The PoC must include:\n"
    "1. The EXACT command or tool call you used (e.g., the hydra command or curl string).\n"
    "2. The specific line of output that confirms the vulnerability.\n\n"
    "Format your verification as a structured summary that clearly separates the 'Verification Status' from the 'Reproduction Steps'."
)

    agent_executor = create_react_agent(llm, verification_tools, prompt=system_prompt)

    # Create the modern LangGraph prebuilt agent
    # 4. LLM Execution: Verify Findings 
    # (The manual retry loop has been removed here, as we now use LangGraph's native RetryPolicy)
    verification_results = agent_executor.invoke({
        "messages": [("user", f"Verify the following findings:\n\n### RAW VULNERABILITIES (Nuclei) ###\n{current_vulns}\n\n### INTERESTING FILES (Feroxbuster) ###\n{interesting_files}")]
    })


    # Extract and print the final answer so you can see the agent's thought process
    final_summary = verification_results["messages"][-1].content
    
    # Bulletproof parser to strip out signatures if they appear
    if isinstance(final_summary, list) and len(final_summary) > 0:
        clean_summary = final_summary[0].get("text", str(final_summary))
    else:
        clean_summary = str(final_summary)
        
    print(f"\n[*] Vulnerability Verification Summary:\n{clean_summary}\n")
    
    # 5. Return the State Update
    return {
        "vulnerabilities": current_vulns, # The complete, shared history
        "current_phase": "vuln_complete"
    }