# ForenShell - Automated Forensic Toolkit

**Version:** 1.0.0  
**Author:** Ben Deshet

## Description
ForenShell is an automated forensic toolkit designed to streamline the analysis of memory and other binary files using well-known Linux forensic utilities. It aims to simplify the workflow of extracting artifacts, analyzing file structures, and performing memory forensics with minimal user intervention.

The toolkit automates:
- Installation and verification of essential forensic tools (`binwalk`, `bulk_extractor`, `foremost`, `strings`).
- Memory file analysis through [Volatility](https://www.volatilityfoundation.org/).
- Extraction of relevant network packets, strings, and other artifacts of interest.
- Generation of a comprehensive general report, consolidating the findings of multiple tools in one place.

## Supported Linux Distributions
This script relies on `apt-get` for installation, making it best suited for **Debian-based Linux distributions**:
- Ubuntu (and its derivatives)
- Debian
- Kali Linux
- Linux Mint (Debian/Ubuntu based)

While it may work on other distributions with `apt-get` package management or by adjusting the tool installation commands, its primary focus and testing have been on Debian-based systems.

## Features
- **Automated Tool Installation:** Checks for and installs required forensic utilities automatically.
- **Memory Forensics:** Employs Volatility to analyze memory images, gathering process trees, DLL lists, network connections, and more.
- **File Carving & Analysis:** Uses `foremost` to carve files, `binwalk` to identify embedded files, and `bulk_extractor` to find evidence of interest.
- **Strings Extraction:** Automatically searches for a set of predefined keywords in extracted strings for quick triage.
- **Detailed Reporting:** Compiles logs and results from all tools into a single, comprehensive report for easy review.

## Prerequisites
- **Root Privileges:** You must run the script as `root` or allow it to switch to `root`.
- **Internet Connection:** Required for installing tools and downloading Volatility.

## Installation & Setup
1. **Clone the Repository:**
   ```bash
   git clone https://github.com/BenZeroDay/ForenShell.git
   cd ForenShell
2. **Make the Script Executable**
   ```bash
   chmod +x forenshell.sh
3. **Run the Script**
   ```bash
   sudo ./forenshell.sh
