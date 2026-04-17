"""
hacksmarter.py — Entry point for the HackSmarter Swarm.

Key fixes applied
-----------------
1. Duplicate ``if __name__ == "__main__"`` block removed.
2. ``run_swarm`` defined before the entry point (no dead code).
3. ``tools.set_allowed_scope()`` called before scanning so every tool can
   enforce the scope whitelist.
4. Python logging configured at startup — ``--verbose`` sets DEBUG level.
"""

import argparse
import logging
import os
import signal
import sys
import time

from langgraph.checkpoint.memory import MemorySaver
from langgraph.graph import END, StateGraph
from langgraph.types import RetryPolicy

from agents import recon_node, strategy_node, vuln_node
from state import PentestState
import tools
from tools import set_allowed_scope
from nessus_parser import parse_nessus_file, seed_db_from_nessus

# ---------------------------------------------------------------------------
# Logging setup (called from __main__ after args are parsed)
# ---------------------------------------------------------------------------

def _configure_logging(verbose: bool = False):
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format="%(asctime)s [%(levelname)s] %(name)s — %(message)s",
        datefmt="%H:%M:%S",
    )


logger = logging.getLogger("hacksmarter")

# ---------------------------------------------------------------------------
# Signal handling
# ---------------------------------------------------------------------------

_last_interrupt_time: float = 0


def _handle_sigint(signum, frame):
    global _last_interrupt_time
    now = time.time()
    if now - _last_interrupt_time < 2:
        logger.warning("Emergency exit — swarm terminated by user.")
        os.killpg(0, signal.SIGKILL)
        sys.exit(1)
    _last_interrupt_time = now
    logger.warning(
        "Interrupt detected — skipping current task. "
        "Press Ctrl+C again within 2 s to exit completely."
    )
    tools.SKIP_CURRENT_TASK = True


# ---------------------------------------------------------------------------
# LangGraph workflow
# ---------------------------------------------------------------------------

_RETRY_POLICY = RetryPolicy(max_attempts=3, initial_interval=30.0, backoff_factor=2.0)


def _node_with_retry_log(node_func):
    """Wrap a node function to log transient Gemini API errors before retry."""
    def wrapper(state):
        try:
            return node_func(state)
        except Exception as exc:
            msg = str(exc).lower()
            if "503" in msg or "unavailable" in msg or "429" in msg:
                logger.warning(
                    "Gemini API spike (503/429) detected in %s — retrying in 30 s…",
                    node_func.__name__,
                )
            raise
    return wrapper


workflow = StateGraph(PentestState)
memory = MemorySaver()

workflow.add_node("recon", _node_with_retry_log(recon_node), retry=_RETRY_POLICY)
workflow.add_node("vuln", _node_with_retry_log(vuln_node), retry=_RETRY_POLICY)
workflow.add_node("strategy", _node_with_retry_log(strategy_node), retry=_RETRY_POLICY)

workflow.set_entry_point("recon")
workflow.add_edge("recon", "vuln")
workflow.add_edge("vuln", "strategy")


def _router(state: PentestState) -> str:
    if state.get("current_phase") == "COMPLETE":
        return "end"
    return "pivot"


workflow.add_conditional_edges("strategy", _router, {"end": END, "pivot": "recon"})

app = workflow.compile(checkpointer=memory)


# ---------------------------------------------------------------------------
# Target parsing
# ---------------------------------------------------------------------------

def parse_targets(target_input: str) -> list:
    """Parse targets from a plain string, comma-separated string, or file path."""
    raw: list = []
    if os.path.isfile(target_input):
        with open(target_input) as f:
            for line in f:
                raw.extend(line.strip().split(","))
    else:
        raw = target_input.split(",")
    return [t.strip() for t in raw if t.strip()]


# ---------------------------------------------------------------------------
# Swarm runner
# ---------------------------------------------------------------------------

def run_swarm(
    targets: list,
    excluded_tools: list,
    client_name: str = None,
    verbose: bool = False,
    nessus_file: str = None,
):
    """Run the AI swarm against the provided target list."""
    if excluded_tools:
        logger.info("Tool exclusions: %s", ", ".join(excluded_tools))

    if client_name:
        client_dir = os.path.join("clients", client_name)
        logger.info("Client context: %s (path: %s)", client_name, client_dir)
        os.makedirs(client_dir, exist_ok=True)
        tools.set_output_dir(client_dir)
    else:
        tools.init_db()

    # FIX: register the authorised scope BEFORE any tool is invoked
    set_allowed_scope(targets)

    # ------------------------------------------------------------------
    # Optional: seed the database from a .nessus file before scanning
    # ------------------------------------------------------------------
    if nessus_file:
        logger.info("Loading Nessus baseline from: %s", nessus_file)
        try:
            nessus_result = parse_nessus_file(nessus_file)
            summary = seed_db_from_nessus(nessus_result)
            logger.info(
                "Nessus import complete — %d host(s), %d port(s), "
                "%d vuln(s) seeded into DB.",
                summary["hosts"],
                summary["open_ports"],
                summary["vulnerabilities"],
            )
            # Extend scope to include any hosts discovered in the Nessus file
            # that aren't already in the target list (e.g. extra IPs/FQDNs).
            nessus_targets = [
                t for t in nessus_result.targets if t not in targets
            ]
            if nessus_targets:
                logger.info(
                    "Extending scope with %d host(s) from Nessus file: %s",
                    len(nessus_targets),
                    nessus_targets,
                )
                targets = targets + nessus_targets
                set_allowed_scope(targets)
        except (FileNotFoundError, ValueError) as exc:
            logger.error("Failed to load Nessus file: %s", exc)
            raise SystemExit(1) from exc

    for index, target in enumerate(targets):
        logger.info("=" * 40)
        logger.info("DEPLOYING AGAINST: %s", target)
        logger.info("=" * 40)

        initial_state = {
            "target_domain": target,
            "subdomains": [],
            "open_ports": [],
            "vulnerabilities": [],
            "interesting_files": [],
            "leaked_credentials": [],
            "last_vuln_count": -1,
            "current_phase": "start",
            "strategy_directives": "",
            "excluded_tools": excluded_tools,
            "verbose": verbose,
            "client_name": client_name,
        }

        config = {
            "configurable": {"thread_id": f"run_{index}"},
            "recursion_limit": 50,
        }

        try:
            final_state = app.invoke(initial_state, config=config)
            if final_state.get("current_phase") == "COMPLETE":
                output_prefix = f"clients/{client_name}/" if client_name else ""
                logger.info(
                    "Swarm completed on %s. Artifacts: %sdradis_import.json, %sfinal_report.md",
                    target,
                    output_prefix,
                    output_prefix,
                )
            else:
                logger.warning("Swarm did not reach COMPLETE state for %s.", target)
        except Exception as exc:
            logger.error("Swarm error on %s: %s", target, exc)

    logger.info("All targets processed.")


# ---------------------------------------------------------------------------
# Entry point  (single, no duplicate)
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    signal.signal(signal.SIGINT, _handle_sigint)

    parser = argparse.ArgumentParser(
        description=(
            "Hack Smarter AI Swarm — built to assist, not replace.\n"
            "Learn ethical hacking at hacksmarter.org"
        ),
        formatter_class=argparse.RawTextHelpFormatter,
    )
    parser.add_argument(
        "-t", "--target", required=True,
        help="Target(s): a domain, comma-separated list, or path to a .txt scope file.",
    )
    parser.add_argument(
        "-x", "--exclude",
        help="Comma-separated tool names to skip (e.g. nuclei,ferox).",
    )
    parser.add_argument(
        "-v", "--verbose", action="store_true",
        help="Enable verbose/debug output.",
    )
    parser.add_argument(
        "-c", "--client",
        help="Client name — organises all output under clients/<name>/.",
    )
    parser.add_argument(
        "-n", "--nessus",
        metavar="FILE",
        help=(
            "Path to a .nessus export file. Findings are seeded into the DB "
            "as a baseline before the AI swarm runs, so the swarm focuses on "
            "verifying and deepening existing findings rather than starting "
            "from scratch. Hosts discovered in the file are added to scope "
            "automatically."
        ),
    )
    args = parser.parse_args()

    _configure_logging(args.verbose)

    targets = parse_targets(args.target)
    excluded = [t.strip() for t in args.exclude.split(",")] if args.exclude else []

    logger.info("Initialising Hack Smarter Swarm…")
    logger.info("Loaded %d target(s).", len(targets))

    run_swarm(targets, excluded, args.client, args.verbose, args.nessus)