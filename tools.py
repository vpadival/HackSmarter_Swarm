# tools.py
import subprocess
import json
import re
from langchain_core.tools import tool
import os
from typing import Union, List

DB_PATH = "pentest_db.json"

def update_db(key: str, new_data: list):
    # Default structure
    db = {"subdomains": [], "open_ports": [], "vulnerabilities": [], "interesting_files": [], "tool_runs": {}}
    
    if os.path.exists(DB_PATH):
        with open(DB_PATH, "r") as f:
            try:
                # Merge existing data into the default structure
                existing_db = json.load(f)
                db.update(existing_db)
            except json.JSONDecodeError:
                pass

    # Deduplicate and merge
    current_list = db.get(key, [])
    for item in new_data:
        if item not in current_list:
            current_list.append(item)
    
    db[key] = current_list
    with open(DB_PATH, "w") as f:
        json.dump(db, f, indent=4)
    return db[key]

def is_already_run(tool_name: str, target: str) -> bool:
    """Checks if a tool has already been run against a target in this database."""
    if not os.path.exists(DB_PATH):
        return False
    with open(DB_PATH, "r") as f:
        try:
            db = json.load(f)
            # The key in tool_runs is the tool's common name
            runs = db.get("tool_runs", {}).get(tool_name, [])
            return target in runs
        except json.JSONDecodeError:
            return False

def mark_as_run(tool_name: str, target: str):
    """Marks a tool as having been run against a target."""
    db = {"subdomains": [], "open_ports": [], "vulnerabilities": [], "interesting_files": [], "tool_runs": {}}
    if os.path.exists(DB_PATH):
        with open(DB_PATH, "r") as f:
            try:
                existing_db = json.load(f)
                db.update(existing_db)
            except json.JSONDecodeError:
                pass
    
    if "tool_runs" not in db:
        db["tool_runs"] = {}
        
    tool_runs = db["tool_runs"]
    if tool_name not in tool_runs:
        tool_runs[tool_name] = []
    
    if target not in tool_runs[tool_name]:
        tool_runs[tool_name].append(target)
    
    db["tool_runs"] = tool_runs
    with open(DB_PATH, "w") as f:
        json.dump(db, f, indent=4)

def filter_live_targets_httpx(targets: list) -> list:
    """
    Takes a list of raw URLs/Domains, pipes them into httpx, 
    and returns only the ones that respond with a live web server.
    """
    print(f"[*] Probing {len(targets)} potential targets with httpx...")
    if not targets:
        return []
        
    try:
        input_data = "\n".join(targets)
        
        # REMOVED check=True. We want the output even if it exits with status 1
        result = subprocess.run(
            ['httpx-toolkit', '-silent'], # Changed from 'httpx'
            input=input_data,
            capture_output=True, text=True
        )
        
        output = result.stdout.strip()
        
        # If output is totally empty, it means 0 live hosts (or a catastrophic crash)
        if not output:
            if result.returncode != 0 and result.stderr:
                print(f"[!] httpx error output: {result.stderr.strip()}")
            return []
            
        # Parse the output into a clean list of verified URLs
        live_urls = [line.strip() for line in output.split('\n') if line.strip()]
        return live_urls
        
    except FileNotFoundError:
        print("[!] httpx binary not found! Falling back to raw target list. Make sure it's installed and in your PATH.")
        return targets
    except Exception as e:
        print(f"[!] Unexpected httpx error: {e}. Falling back to raw target list.")
        return targets

@tool
def run_httpx_tool(targets: Union[str, List[str]]) -> List[str]:
    """
    Takes a single target or a list of targets (URLs/domains), 
    probes them with httpx, and returns a list of only the live web servers.
    Use this to verify if a target is alive before running dirsearch or wpscan.
    """
    target_list = [targets] if isinstance(targets, str) else targets
    return filter_live_targets_httpx(target_list)

@tool
def format_scope_tool(scope: str) -> dict:
    """
    Analyzes the user-provided scope and categorizes it.
    Args: scope (str): The raw input (e.g., '192.168.1.1', 'example.com', '10.0.0.0/24')
    """
    # Basic regex for IP vs Domain (You can expand this for CIDR)
    is_ip = re.match(r"^\d{1,3}(\.\d{1,3}){3}$", scope)
    
    return {
        "original_scope": scope,
        "type": "IP" if is_ip else "Domain",
        "ready_for_nmap": bool(is_ip),
        "ready_for_subfinder": not bool(is_ip)
    }

@tool
def run_subfinder_tool(domain: str) -> str:
    """
    Finds subdomains for a given target domain using subfinder.
    Returns a success message with the count of subdomains found. 
    This list should be considered the exhaustive source of truth for subdomains.
    """
    if is_already_run("subfinder", domain):
        return f"[!] Skipping subfinder for {domain} - Results already in database."
        
    print(f"[*] Recon Agent executing subfinder on {domain}...")
    try:
        # We REMOVED -j to support older/Kali versions of subfinder
        result = subprocess.run(
            ['subfinder', '-d', domain, '-silent'], 
            capture_output=True, text=True, check=True
        )
        
        output = result.stdout.strip()
        
        if not output:
            mark_as_run("subfinder", domain)
            return f"Subfinder scan completed for {domain}. Result: 0 subdomains discovered. This is a valid result."

        # Parse plain text output (one subdomain per line)
        subdomains = [line.strip() for line in output.split('\n') if line.strip()]
                
        # Persist to the shared DB
        update_db("subdomains", subdomains)
        mark_as_run("subfinder", domain)
        return f"Subfinder scan successful. Found {len(subdomains)} subdomains and added them to the database."
        
    except subprocess.CalledProcessError as e:
        return f"Subfinder command failed. Error: {e.stderr}"
    except Exception as e:
        return f"An unexpected error occurred: {str(e)}"

@tool
def run_nmap_tool(target: str) -> list:
    """
    Runs a fast nmap port scan against a target IP or domain.
    Args: target (str): The IP or domain to scan.
    """
    if is_already_run("nmap", target):
        return f"[!] Skipping nmap for {target} - Results already in database."

    print(f"[*] Recon Agent executing nmap on {target}...")
    try:
        # Using grepable output (-oG) for easier Python parsing without external XML libraries
        # -T4 and --top-ports 1000 for speed during the agent loop
        result = subprocess.run(
            ['nmap', '-T4', '--top-ports', '1000', '-oG', '-', target],
            capture_output=True, text=True, check=True
        )
        
        open_ports = []
        for line in result.stdout.split('\n'):
            if "Ports:" in line:
                # Extract the port numbers (Simplified parsing for example)
                ports_section = line.split("Ports: ")[1]
                for port_data in ports_section.split(', '):
                    if "/open/" in port_data:
                        port_num = port_data.split('/')[0].strip()
                        open_ports.append({"target": target, "port": port_num})
                        
        update_db("open_ports", open_ports)
        mark_as_run("nmap", target)
        return f"Successfully updated DB with {len(open_ports)} ports for {target}."
    except subprocess.CalledProcessError as e:
        return [{"error": f"Nmap failed: {e.stderr}"}]

@tool
def run_nuclei_tool(targets: list) -> str:
    """
    Runs Nuclei against a list of targets and safely parses the JSON output into the DB.
    Args: targets (list): A list of target URLs to scan.
    """
    out_file = 'nuclei_out.json'
    
    # 1. Clean up old output files to prevent cross-contamination
    if os.path.exists(out_file):
        os.remove(out_file)

    if not targets:
        return "No targets provided to Nuclei."

    print(f"[*] Recon Agent executing Nuclei on {len(targets)} targets...")
    try:
        # Run optimized nuclei command
        # Passing targets via stdin to handle multiple URLs safely and aggregated rate limiting
        input_data = "\n".join(targets)
        result = subprocess.run(
            [
                'nuclei', 
                '-je', out_file, 
                '-severity', 'medium,high,critical',
                '-exclude-tags', 'dos,fuzz',  # CRITICAL: Exclude templates that crash or overload servers
                '-rl', '5',                   # Hard throttle: Maximum 5 requests per second 
                '-c', '5',                    # Concurrency: Only 5 active templates at a time
                '-timeout', '10',             # Give the smaller servers 10 seconds to reply
                '-retries', '0',              # If a request drops, let it fail. Do NOT retry and compound the DoS.
                '-mhe', '3'      
            ],
            input=input_data,
            capture_output=True, text=True, check=False # check=False so it doesn't crash on non-zero exits
        )
        
        findings = []
        if os.path.exists(out_file):
            with open(out_file, 'r') as f:
                try:
                    # Try parsing as a single JSON array
                    parsed_data = json.load(f)
                    items = parsed_data if isinstance(parsed_data, list) else [parsed_data]
                except json.JSONDecodeError:
                    # Fallback to JSON Lines
                    f.seek(0)
                    items = [json.loads(line) for line in f if line.strip()]

                for item in items:
                    findings.append({
                        "template": item.get("template-id"),
                        # Grab the exact host/port Nuclei found it on
                        "target": item.get("matched-at", "unknown"), 
                        "severity": item.get("info", {}).get("severity"),
                        "description": item.get("info", {}).get("name")
                    })
            
            if findings:
                update_db("vulnerabilities", findings)
                return f"Nuclei complete. Added {len(findings)} findings to DB."
        
        return "Nuclei finished with 0 findings."
        
    except Exception as e:
        print(f"[!] Critical Nuclei Parsing Error: {str(e)}")
        return f"Nuclei tool error: {str(e)}"

@tool
def run_nc_banner_grab(target: str, port: int, send_string: str = "") -> str:
    """
    Uses netcat (nc) to grab a service banner or send a custom string to a port.
    Useful for manual verification of non-HTTP services.
    """
    try:
        # -w 2: 2 second timeout, -v: verbose, -n: no DNS
        cmd = ["nc", "-vn", "-w", "2", str(target), str(port)]
        # Add a newline to mimic echo's default behavior
        input_data = send_string + "\n"
        result = subprocess.run(cmd, input=input_data, capture_output=True, text=True)
        
        output = result.stdout if result.stdout else result.stderr
        return f"NC Output for {target}:{port}:\n{output}"
    except Exception as e:
        return f"NC Error: {str(e)}"

@tool
def run_ssh_audit(target: str, port: int = 22) -> str:
    """
    Runs ssh-audit to check for weak ciphers, algorithms, and vulnerabilities 
    like Terrapin (CVE-2023-48795).
    """
    try:
        # Assuming ssh-audit is installed via pip or apt
        result = subprocess.run(
            ['ssh-audit', '-p', str(port), target],
            capture_output=True, text=True
        )
        return f"SSH Audit Results for {target}:\n{result.stdout}"
    except Exception as e:
        return f"SSH Audit Error: {str(e)}"

@tool
def run_hydra_check(target: str, service: str, user: str, password: str, port: int = None) -> str:
    """
    Runs Hydra to verify if a specific username and password pair work on a service.
    Supported services: ssh, ftp, http-get, mysql, mssql, etc.
    """
    try:
        port_args = [f"-s", str(port)] if port else []
        # -l: user, -p: pass, -f: exit on found, -u: loop around users
        cmd = ["hydra", "-l", user, "-p", password] + port_args + ["-f", f"{service}://{target}"]
        
        result = subprocess.run(cmd, capture_output=True, text=True)
        
        if "1 of 1 target successfully completed" in result.stdout:
            return f"[!] SUCCESS: Credentials verified! {user}:{password} works on {service}."
        return f"[-] FAILURE: Credentials {user}:{password} were rejected."
        
    except Exception as e:
        return f"Hydra Error: {str(e)}"

@tool
def run_testssl_verification(target: str) -> str:
    """
    Runs testssl.sh for a deep dive into SSL/TLS vulnerabilities.
    Only use this if Nuclei flags a specific SSL issue.
    """
    try:
        # --quiet: less noise, --severity MEDIUM: skip the fluff
        result = subprocess.run(
            ['testssl.sh', '--quiet', '--severity', 'MEDIUM', target],
            capture_output=True, text=True
        )
        return f"TestSSL Results for {target}:\n{result.stdout}"
    except Exception as e:
        return f"TestSSL Error: {str(e)}"

@tool
def execute_curl_request(url: str, method: str = "GET", headers: dict = None, data: str = None) -> str:
    """
    Executes a custom HTTP request using curl to verify vulnerabilities.
    Args: 
        url (str): The target URL.
        method (str): HTTP method (GET, POST, etc.)
        headers (dict): Optional headers.
        data (str): Optional payload body.
    """
    # Build the curl command safely
    cmd = ['curl', '-s', '-i', '-X', method, url]
    if headers:
        for k, v in headers.items():
            cmd.extend(['-H', f"{k}: {v}"])
    if data:
        cmd.extend(['-d', data])
        
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
        # Return only the first 2000 characters to prevent blowing up the LLM context window
        return result.stdout[:2000] 
    except subprocess.TimeoutExpired:
        return "Error: Curl request timed out."
    except Exception as e:
        return f"Error: {str(e)}"

@tool
def run_wpscan_tool(target_url: str) -> str:
    """
    Runs WPScan against a target URL to check for WordPress installations, 
    vulnerabilities, and outdated plugins.
    Args: target_url (str): The URL to scan (e.g., http://example.com)
    """
    if is_already_run("wpscan", target_url):
        return f"[!] Skipping wpscan for {target_url} - Results already in database."

    print(f"[*] Recon Agent executing wpscan on {target_url}...")
    try:
        wpscan_token = os.environ.get("WPSCAN_API_TOKEN")
        token_args = ["--api-token", wpscan_token] if wpscan_token else []

        # Try running without update first for speed
        result = subprocess.run(
            ['wpscan', '--url', target_url, '--no-update', '--random-user-agent', '-e', 'vp,vt'] + token_args,
            capture_output=True, text=True
        )
        
        # Check if it failed due to missing database
        if "missing database" in (result.stdout + result.stderr).lower():
            print("[!] WPScan database missing. Attempting update...")
            subprocess.run(['wpscan', '--update'], capture_output=True, text=True)
            # Retry after update
            result = subprocess.run(
                ['wpscan', '--url', target_url, '--no-update', '--random-user-agent', '-e', 'vp,vt'],
                capture_output=True, text=True
            )
        
        output = result.stdout if result.stdout else result.stderr
        
        # Mark as run
        mark_as_run("wpscan", target_url)

        # Return truncated output to prevent LLM context blowup
        return f"WPScan Results for {target_url}:\n{output[:3000]}"
    except FileNotFoundError:
        return "[!] WPScan binary not found! Make sure it is installed and in your PATH."
    except Exception as e:
        return f"WPScan Error: {str(e)}"

@tool
def run_dirsearch_tool(url: Union[str, List[str]], extensions: str = "php,html,js,txt") -> str:
    """
    Performs directory and file discovery on a web server using dirsearch.
    Args:
        url (Union[str, List[str]]): The target URL or a list of target URLs.
        extensions (str): Comma-separated list of extensions to check (default: php,html,js,txt).
    """
    targets = [url] if isinstance(url, str) else url
    
    # Filter targets that were already run
    new_targets = [t for t in targets if not is_already_run("dirsearch", t)]
    
    if not new_targets:
        return f"All {len(targets)} targets have already been scanned by dirsearch."

    print(f"[*] Executing dirsearch on {len(new_targets)} targets...")
    out_file = 'dirsearch_out.json'
    targets_file = 'dirsearch_targets.txt'
    
    if os.path.exists(out_file):
        os.remove(out_file)
        
    try:
        # If multiple targets, use a temporary file
        if len(new_targets) > 1:
            with open(targets_file, 'w') as f:
                f.write("\n".join(new_targets))
            cmd_targets = ['-l', targets_file]
        else:
            cmd_targets = ['-u', new_targets[0]]

        # Run dirsearch
        subprocess.run(
            [
                'dirsearch'
            ] + cmd_targets + [
                '-e', extensions, 
                '--format', 'json', 
                '-o', out_file,
                '--random-user-agent',
                '--quiet-mode'
            ],
            capture_output=True, text=True, check=False
        )
        
        findings = []
        if os.path.exists(out_file):
            with open(out_file, 'r') as f:
                try:
                    data = json.load(f)
                    
                    # Dirsearch JSON structure for bulk scans:
                    # Sometimes it's a dict with 'results' key, or a dict where keys are targets.
                    # We'll try to find any 'status' items in the hierarchy.
                    
                    def extract_results(d):
                        if isinstance(d, dict):
                            if "status" in d and "path" in d:
                                status = d.get("status")
                                if status in [200, 301, 302]:
                                    findings.append({
                                        "url": d.get("url", "unknown"),
                                        "status": status,
                                        "content-length": d.get("content-length"),
                                        "path": d.get("path")
                                    })
                            for v in d.values():
                                extract_results(v)
                        elif isinstance(d, list):
                            for item in d:
                                extract_results(item)

                    extract_results(data)
                except json.JSONDecodeError:
                    print("[!] Error decoding dirsearch JSON output.")
            
            # Mark all targets as run
            for target in new_targets:
                mark_as_run("dirsearch", target)
                
            if findings:
                update_db("interesting_files", findings)
                # Return a summary to the LLM
                summary = "\n".join([f"Found: {f['url']} (Status: {f['status']})" for f in findings[:10]])
                if len(findings) > 10:
                    summary += f"\n... and {len(findings) - 10} more."
                return f"Dirsearch complete. Added {len(findings)} findings to DB.\nRecent discoveries:\n{summary}"
                
        return f"Dirsearch finished on {len(new_targets)} targets with 0 interesting findings."

    except FileNotFoundError:
        return "[!] dirsearch binary not found! Make sure it's installed and in your PATH."
    except Exception as e:
        return f"Dirsearch Error: {str(e)}"
    finally:
        if os.path.exists(targets_file):
            os.remove(targets_file)