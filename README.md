# Hack Smarter Swarm: AI Pentesting Assistant

**Author:** Tyler Ramsbey  
**Organizations:** [Kairos Sec](https://kairos-sec.com) | [Hack Smarter](https://hacksmarter.org)

> Note from Tyler: I wouldn't use this in a client environment (yet). This initially started as a small project because I wanted to learn LangGraph; but I decide to expand it and make it available for others to learn from. I'll be adding to it extensively in the near future. 

## Overview
Hack Smarter Swarm is a multi-agent AI penetration testing assistant built to **assist (not replace)** ethical hackers and security professionals. Powered by [LangGraph](https://python.langchain.com/docs/langgraph/) and Gemini, the swarm acts as your automated reconnaissance and initial vulnerability assessment assistant.

It orchestrates industry-standard open-source tools to autonomously map attack surfaces, verify live web servers, probe for vulnerabilities, and eliminate false positives, saving you time and giving you a head-start on deeper, manual exploitation.

<img width="70%" alt="image" src="https://github.com/user-attachments/assets/e5f3694b-34c2-4739-8f56-5b9161da8d22" />

#### Changing the LLM Model
Hack Smarter Swarm is built using Gemini, but since it uses LangChain, it is very easy to swap to another model provider (like OpenAI or Anthropic).
1. Open `agents.py`.
2. Locate the `llm` initialization near the top of the file: `llm = ChatGoogleGenerativeAI(...)`.
3. Import the required Chat model from LangChain (e.g., `from langchain_openai import ChatOpenAI`).
4. Replace the `llm` variable with your new model (e.g., `llm = ChatOpenAI(model="gpt-4o", temperature=0)`).
5. Add your new API key to the `.env` file and install the corresponding LangChain partner package via pip.

## The Philosophy: Assisting, NEVER Replacing
Unlike many open-source projects that chase full autonomy or try to completely abstract away the human element with a "black box" hack button, this swarm is built purely to be an **assistant**. It handles the tedious, time-consuming tasks: 
- Deduplicating subdomains.
- Correlating `nmap` outputs with live `httpx` findings.
- Running `nuclei` and then actively weeding out false positives for you.

You get a clean, validated `dradis_import.json` and a Markdown report with concrete Proof of Concepts (PoCs). You do the deep-dive manual exploitation.

## Features
- **Multi-Agent Architecture**:
  - **Tactical Recon Specialist**: Handles domain discovery, port scanning, and WordPress-specific vulnerability checks.
  - **Vuln Worker**: Identifies web surfaces, runs Nuclei, and verifies vulnerabilities using LLM logic.
  - **Strategy & Reporting Node**: Analyzes results, determines if it should pivot deeper, and generates professional summaries.
- **Deduplication & State Management**: Maintains a persistent local ledger (`pentest_db.json`) of findings across loops.
- **False-Positive Reduction**: Actively verifies potential vulnerabilities using an AI agent armed with `curl`, `nmap`, `nc` (Netcat), `ssh-audit`, `hydra`, and `testssl.sh`. It will then provide the full PoC to make it easy to reproduce. 
- **Reporting Ready**: Automatically outputs:
  - `final_report.md`: A high-level, human-readable executive summary.
  - `dradis_import.json`: A structured JSON file ready for ingestion into reporting platforms like Dradis.

<img width="70%" alt="image" src="https://github.com/user-attachments/assets/1c3ee63a-1ea2-454b-9904-8af6553db62f" />

## Prerequisites

### Python Dependencies
Python 3.10+ is recommended. Install the required Python libraries:
```bash
pip install -r requirements.txt
```

### System Dependencies (Pentesting Tools)
The AI interacts with the following command-line binaries. Ensure they are installed and accessible in your system's `$PATH`:
- [Subfinder](https://github.com/projectdiscovery/subfinder)
- [Nmap](https://nmap.org/)
- [HTTPX Toolkit](https://github.com/projectdiscovery/httpx) (Make sure the alias is `httpx-toolkit`)
- [Nuclei](https://github.com/projectdiscovery/nuclei)
- `curl`
- `nc` (Netcat)
- [Hydra](https://github.com/vanhauser-thc/thc-hydra)
- [WPScan](https://github.com/wpscantech/wpscan)
- [testssl.sh](https://testssl.sh/)
- [dirsearch](https://github.com/maurosoria/dirsearch)

### Environment Variables
You need a Google Gemini API Key. Ensure it is placed in a `.env` file in the root of the project:
```env
GOOGLE_API_KEY="your_api_key_here"
WPSCAN_API_TOKEN="your_wpscan_token_here"
```

## Usage

```bash
python hacksmarter.py -t <target>
```

You can pass a single domain, a comma-separated list of domains, or a `.txt` file containing your scope:
```bash
# Single Target
python hacksmarter.py -t example.com

# Multiple Targets
python hacksmarter.py -t "example.com, 192.168.1.1"

# Target File
python hacksmarter.py -t scope.txt

# Excluding Tools
You can exclude specific tools from the workflow using the `-x` or `--exclude` flag followed by a comma-separated list of tool name substrings (e.g., `nuclei`, `nmap`, `wpscan`, `dirsearch`).

# Skip Nuclei and Nmap
python hacksmarter.py -t example.com -x nuclei,nmap

# Skip WPScan and Dirsearch
python hacksmarter.py -t example.com -x wpscan,dirsearch
```

---

## Contributing

Hack Smarter Swarm is designed to be easily extensible. You can easily add more tools or modify the existing agents.

### Adding New Tools
1. Open `tools.py` and define a new Python function that executes your desired tool (e.g., via `subprocess`).
2. Decorate the function with `@tool` from `langchain_core.tools`.
3. Include a detailed docstring explaining **what the tool does** and **what its arguments are**, as the LLM uses this to understand how to call it.
4. If your tool finds new subdomains, ports, or vulnerabilities, make sure to save the results to the shared state using `update_db(key, data)`.

### Modifying Agents
1. Open `agents.py`.
2. Locate the node for the agent you want to modify (e.g., `recon_node` or `vuln_node`).
3. Import your newly created tool from `tools.py` at the top of the file.
4. Add your tool to the agent's tool list (e.g., `recon_tools` or `verification_tools`).
5. Update the agent's `system_prompt` to give the AI context on when and how to use your tool, or how its overall strategy should change.
