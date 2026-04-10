"""
state.py — Shared state type for the HackSmarter LangGraph swarm.
"""

from typing import Annotated, List, Optional, TypedDict


def _merge_unique(existing: list, new: list) -> list:
    """Reducer that appends only items not already present."""
    result = list(existing) if existing else []
    for item in new:
        if item not in result:
            result.append(item)
    return result


class PentestState(TypedDict):
    target_domain: str
    last_vuln_count: int

    subdomains: Annotated[List[str], _merge_unique]
    open_ports: Annotated[List[dict], _merge_unique]
    vulnerabilities: Annotated[List[dict], _merge_unique]
    interesting_files: Annotated[List[dict], _merge_unique]
    excluded_tools: List[str]
    verbose: bool

    current_phase: str
    strategy_directives: str
    client_name: Optional[str]