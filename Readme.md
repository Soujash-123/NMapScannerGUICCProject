# Professional NMAP Service Scanner

## Overview
This is a professional-grade network scanning application built with Python and wxPython, providing a user-friendly graphical interface for network reconnaissance and service discovery using NMAP.

## Features

### Scan Capabilities
- Multiple scan types:
  - SYN Scan
  - TCP Connect Scan
  - UDP Scan
  - Service Detection Scan
- Comprehensive port scanning
- Customizable port range selection
- Adjustable timing templates (T0-T5)

### User Interface
- Dark-themed, professional design
- Multiple result view tabs:
  - Raw Output
  - Services Grid
  - Host Information
- Progress tracking
- Detailed error handling

### Advanced Features
- Root access authentication
- OS detection (when root access granted)
- Hostname and IP address resolution
- Threaded scanning for responsive UI

## Prerequisites

### Dependencies
- Python 3.x
- wxPython
- python-nmap
- ipaddress
- socket
- subprocess
- threading

### Installation

1. Install required libraries:
```bash
pip install wxPython python-nmap
```

2. Ensure NMAP is installed on your system:
```bash
sudo apt-get install nmap  # For Ubuntu/Debian
brew install nmap          # For macOS
```

## Usage

### Launching the Application
```bash
python nmap_scanner.py
```

### Scan Workflow
1. Enter target IP/hostname
2. Specify port range
3. Select scan type
4. Choose timing template
5. (Optional) Authenticate for root access
6. Click "Start Scan"

### Scan Configuration Options
- **Target**: IP address or hostname
- **Port Range**: 
  - Single ports: `80, 443`
  - Port ranges: `1-1024`
  - Special keywords: `all`, `common`
- **Scan Types**:
  - SYN Scan: Stealth scanning
  - TCP Connect: Full connection
  - UDP Scan: UDP port discovery
  - Service Detection: Identify services
- **Timing Templates**:
  - T0: Paranoid (extremely slow)
  - T1-T2: Sneaky, polite
  - T3: Normal default
  - T4-T5: Aggressive, fast

## Security Notes
- Root access required for advanced scans
- Use network scanning responsibly
- Obtain proper authorization before scanning networks

## Limitations
- Requires NMAP installed
- Some advanced scans need root privileges
- Performance depends on network conditions

## Troubleshooting
- Ensure all dependencies are installed
- Check network connectivity
- Verify target accessibility
- Run with appropriate permissions

## Contributing
1. Fork the repository
2. Create feature branches
3. Submit pull requests

## License
[Specify your license here]

## Disclaimer
This tool is for educational and authorized network administration purposes only. Unauthorized scanning may be illegal.
