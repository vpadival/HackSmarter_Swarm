# main.py
import argparse
import os
from langgraph.graph import StateGraph, END
from state import PentestState
from agents import recon_node, vuln_node, strategy_node
from tools import run_nuclei_tool, execute_curl_request, run_nmap_tool, DB_PATH
from langgraph.checkpoint.memory import MemorySaver
from langgraph.types import RetryPolicy

# 1. Initialize the Graph with our State
workflow = StateGraph(PentestState)
memory = MemorySaver()

# 2. Add the Nodes (The Agents) with a robust Retry Policy for Gemini API 503/429 errors
# This pauses for 30s as requested by the user, with exponential backoff.
GEMINI_RETRY_POLICY = RetryPolicy(
    max_attempts=3,
    initial_interval=30.0,
    backoff_factor=2.0
)

def node_with_retry_log(node_func):
    """Wraps a node function to print a message when a transient API error occurs."""
    def wrapper(state):
        try:
            return node_func(state)
        except Exception as e:
            err_str = str(e).lower()
            if "503" in err_str or "unavailable" in err_str or "429" in err_str:
                print(f"\n[!] Gemini API Spike Detected (503/429). Retrying node in 30s...")
            raise e
    return wrapper

workflow.add_node("recon", node_with_retry_log(recon_node), retry=GEMINI_RETRY_POLICY)
workflow.add_node("vuln", node_with_retry_log(vuln_node), retry=GEMINI_RETRY_POLICY)
workflow.add_node("strategy", node_with_retry_log(strategy_node), retry=GEMINI_RETRY_POLICY)

def parse_targets(target_input: str) -> list:
    """Parses targets from string, comma-separated string, or file."""
    raw_targets = []
    if os.path.isfile(target_input):
        with open(target_input, 'r') as f:
            for line in f:
                parts = line.strip().split(',')
                raw_targets.extend(parts)
    else:
        raw_targets = target_input.split(',')
    
    return [t.strip() for t in raw_targets if t.strip()]

# 3. Define the routing logic (Conditional Edge)
def router(state: PentestState):
    """Routes the graph based on the Strategy Node's decision."""
    
    # FIX: Change "complete" to "COMPLETE" to match what strategy_node outputs!
    if state.get("current_phase") == "COMPLETE":
        return "end"   # Maps to END in your dictionary
        
    return "pivot"     # Maps to "recon" in your dictionary

# 4. Add the Edges (The Flow)
workflow.set_entry_point("recon")               # Always start with Recon
workflow.add_edge("recon", "vuln")              # Recon always flows to Vuln
workflow.add_edge("vuln", "strategy")           # Vuln always flows to Strategy

# The Conditional Edge: Based on 'router', go to END or back to Recon
workflow.add_conditional_edges(
    "strategy",
    router,
    {
        "end": END,
        "pivot": "recon" 
    }
)

# 5. Compile the application
app = workflow.compile(checkpointer=memory)

# --- Execution ---
if __name__ == "__main__":
    print("[*] Initializing the Hack Smarter Swarm...")

    # 1. Handle Arguments
    parser = argparse.ArgumentParser(description="Hack Smarter AI Swarm. Built to assist, not replace.")
    parser.add_argument("-t", "--target", required=True, help="Target(s) or file path")
    parser.add_argument("-x", "--exclude", help="Comma-separated list of tools to exclude (e.g., nuclei,nmap)")
    args = parser.parse_args()

    targets = parse_targets(args.target)
    excluded_tools = [t.strip() for t in args.exclude.split(',')] if args.exclude else []
    print(f"[*] Loaded {len(targets)} target(s).")
    if excluded_tools:
        print(f"[*] Tool Exclusions: {', '.join(excluded_tools)}")

    # 2. Iterate through targets
    for index, target in enumerate(targets):
        print(f"\n{'='*40}\n[*] DEPLOYING AGAINST: {target}\n{'='*40}")

        initial_state = {
            "target_domain": target, 
            "subdomains": [],
            "open_ports": [],
            "vulnerabilities": [],
            "last_vuln_count": -1,
            "current_phase": "start",
            "strategy_directives": "",
            "excluded_tools": excluded_tools,
            "markdown_report": "",
            "dradis_json": {}
        }

        # Unique thread_id per target to keep the AI's "brains" separated
        config = {
            "configurable": {"thread_id": f"run_{index}"}, 
            "recursion_limit": 15
        }

        try:
            # 3. Run the graph
            final_state = app.invoke(initial_state, config=config)
            
            # 4. Success Check
            # We check the phase, because the Node already handled the file saving.
            if final_state.get("current_phase") == "COMPLETE":
                print(f"[*] Swarm successfully completed operations on {target}.")
                print(f"[*] Artifacts generated: dradis_import.json, final_report.md")
            else:
                print(f"\n[!] Swarm stopped early in phase: {final_state.get('current_phase')}")

        except Exception as e:
            print(f"\n[!] Swarm error on {target}: {e}")
            continue # Don't let one bad target kill the whole list

    print("\n[*] All targets processed.")