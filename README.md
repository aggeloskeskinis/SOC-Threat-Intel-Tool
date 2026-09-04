# SOC Threat Intelligence Tool

A Python-based automated tool designed for Security Operations Center (SOC) analysts. It facilitates the bulk checking and triage of Indicators of Compromise utilizing the VirusTotal API.

## Core Features
* **Bulk Analysis:** Automatically parses and processes targets from the `targets.txt` file.
* **Intelligent Recognition:** Dynamically identifies whether the input is an IPv4 address, Domain name, or File Hash (MD5/SHA256).
* **Error Handling & Rate Limiting:** Implements exception handling for network stability and automated delays to comply with API rate limits.
* **Automated Reporting:** Generates a structured output report (`reports.txt`) for immediate SOC documentation.

## Execution Instructions
1. Insert your VirusTotal API key inside the `detective.py` script.
2. Populate the `targets.txt` file with the desired IOCs (one per line).
3. Execute the script via terminal: `python detective.py`