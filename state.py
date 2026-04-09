# state.py
from typing import TypedDict, Annotated, List

# Create a smart reducer function to deduplicate lists
def merge_unique(existing: list, new: list) -> list:
    result = existing.copy() if existing else []
    for item in new:
        if item not in result:
            result.append(item)
    return result

class PentestState(TypedDict):
    target_domain: str 
    last_vuln_count: int
    
    # Use our new merge_unique function instead of operator.add
    subdomains: Annotated[List[str], merge_unique]
    open_ports: Annotated[List[dict], merge_unique]
    vulnerabilities: Annotated[List[dict], merge_unique]
    interesting_files: Annotated[List[dict], merge_unique]
    excluded_tools: List[str]
    
    current_phase: str
    strategy_directives: str