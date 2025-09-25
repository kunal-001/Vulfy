# VULFY - Full Stack Vulnerability Scanner

VULFY is an advanced vulnerability scanning tool that combines multiple security scanning frameworks into a single, user-friendly interface. It provides comprehensive security assessments for websites and networks.

## Features

- 🛡️ Integrated scanning using multiple tools:
  - Nmap (Port scanning and OS detection)
  - Nikto (Web vulnerability scanning)
  - SQLMap (SQL injection testing)
  - SSLyze (SSL/TLS security scanning)
  - Dirb (Directory brute forcing)
  - DNSRecon (DNS analysis)

- 🎯 User-friendly CLI interface with numbered menu options
- 📝 Detailed vulnerability reports in plain language
- 🛠️ Actionable recommendations for fixing identified vulnerabilities
- 🌐 Support for both IP addresses and website URLs
- ⚡ Automated tool installation
- 🤝 Open-source and community-driven

## Installation

1. Clone the repository:
   ```bash
   git clone 
   cd VulnSeekers
   ```

2. Run the setup script:
   ```bash
   chmod +x setup.sh
   ./setup.sh
   ```

The setup script will automatically:
- Update system packages
- Install required security tools
- Install Python dependencies
- Verify installation

## Usage

1. Run the tool:
   ```bash
   python3 vulfy.py
   ```

2. Follow the on-screen menu to select your scan options:
   - Enter target IP address or URL
   - Choose from available scan options (1-11)
   - View detailed scan results and recommendations

## Available Scans

1. Nmap Port Scan
2. Nikto Web Vulnerability Scan
3. SQL Injection Testing
4. SSL/TLS Security Scan
5. Directory Brute Force
6. XSS Vulnerability Scan
7. Subdomain Enumeration
8. DNS Analysis
9. Header Security Check
10. Full Scan (All Tests)
11. About Us
12. Exit

