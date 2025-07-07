# IP Ports Scanner

A comprehensive web-based network vulnerability scanner with a modern Flask interface. This tool enables security professionals to discover hosts, scan ports, identify services, and detect vulnerabilities across internal networks.

## 🚀 Features

- **🌐 Modern Web Interface**: Responsive Bootstrap-based dashboard
- **🔍 Host Discovery**: Automated network scanning with ping sweeps
- **🛡️ Port Scanning**: Comprehensive TCP port analysis using Nmap
- **🔧 Service Detection**: Banner grabbing and version identification
- **🐛 CVE Integration**: Real-time vulnerability lookup via Vulners API
- **📊 Real-time Progress**: Live scan monitoring with visual indicators
- **📋 Interactive Results**: DataTables with search, sort, and filtering
- **📁 Export Functionality**: CSV export with timestamped reports
- **🔐 Optional Authentication**: Secure login system
- **⚡ Concurrent Scanning**: Multi-threaded performance
- **📱 Mobile Responsive**: Works on desktop, tablet, and mobile

## 📋 Prerequisites

### System Requirements
- **Python 3.8+**
- **Nmap** (network scanning tool)
- **macOS/Linux/Windows** (WSL)
- **Administrative privileges** (for comprehensive scans)

### Installation Dependencies

```bash
# macOS
brew install python nmap

# Ubuntu/Debian
sudo apt update && sudo apt install python3 python3-pip nmap

# CentOS/RHEL
sudo yum install python3 python3-pip nmap
```

## 🛠️ Installation

### 1. Clone/Create Project Directory

```bash
mkdir IP_Ports_Scanner
cd IP_Ports_Scanner
```

### 2. Set Up Virtual Environment

```bash
# Create virtual environment
python3 -m venv venv

# Activate virtual environment
source venv/bin/activate  # macOS/Linux
# or
venv\Scripts\activate     # Windows
```

### 3. Install Python Dependencies

```bash
pip install -r requirements.txt
```

### 4. Verify Nmap Installation

```bash
# Test Nmap accessibility
python3 -c "import nmap; nm = nmap.PortScanner(); print('✓ Nmap version:', nm.nmap_version())"
```

## 🏃‍♂️ Quick Start

### 1. Basic Launch

```bash
# Ensure virtual environment is active
source venv/bin/activate

# Start the web application
python3 app.py
```

### 2. Access Web Interface

Open your browser and navigate to:
```
http://localhost:5000
```

### 3. Configure Your First Scan

1. **Enter target subnets** in CIDR format:
   ```
   192.168.1.0/24
   192.168.2.0/24
   ```

2. **Configure settings**:
   - Thread count (1-50)
   - Enable/disable CVE lookup

3. **Start scanning** and monitor real-time progress

4. **View results** in the interactive table

5. **Export data** as CSV for reporting

## ⚙️ Configuration

### Environment Variables

```bash
# Optional authentication
export ENABLE_AUTH="true"

# Custom secret key (production)
export SECRET_KEY="your-secure-secret-key"

# Debug mode (development only)
export FLASK_DEBUG="true"

# Custom port
export FLASK_RUN_PORT="8080"
```

### Authentication (Optional)

When `ENABLE_AUTH=true`, default credentials are:

| Username | Password | Role |
|----------|----------|------|
| `admin` | `password123` | Administrator |
| `auditor` | `audit2025` | Read-only |

⚠️ **Change these credentials in production!**

## 🔧 Advanced Usage

### Command Line Interface

The core scanner can also be used via CLI:

```bash
# Basic subnet scan
python3 vuln_scan.py -t 192.168.1.0/24

# Multiple subnets with custom settings
python3 vuln_scan.py -t 192.168.1.0/24 192.168.2.0/24 --threads 20

# Scan without CVE lookup
python3 vuln_scan.py -t 10.0.0.0/16 --no-cve

# Custom output file
python3 vuln_scan.py -t 192.168.1.0/24 -o security_audit.csv
```

### Elevated Privileges

For comprehensive scanning (OS detection, SYN scans):

```bash
sudo python3 app.py
```

### Automation with Cron

```bash
# Edit crontab
crontab -e

# Add scheduled scan (daily at 2 AM)
0 2 * * * cd /path/to/IP_Ports_Scanner && source venv/bin/activate && python3 vuln_scan.py -t 192.168.1.0/24 --quiet
```

## 📊 Understanding Results

### Scan Results Table

| Column | Description |
|--------|-------------|
| **IP Address** | Target host IPv4 address |
| **Hostname** | Resolved hostname (if available) |
| **OS** | Operating system fingerprint |
| **Port** | Open port number and protocol |
| **Service** | Identified service name |
| **Product** | Software product name |
| **Version** | Software version |
| **CVEs** | Number of known vulnerabilities |
| **Top CVE** | Highest severity CVE |

### CVE Risk Levels

- 🔴 **High Risk**: CVSS ≥ 7.0 (Red text)
- 🟡 **Medium Risk**: CVSS 4.0-6.9 (Orange text)
- 🟢 **Low Risk**: CVSS < 4.0 (Green text)

## 🛡️ Security Considerations

### ⚠️ Important Warnings

- **Authorization Required**: Only scan networks you own or have explicit permission to test
- **Network Impact**: Scanning generates significant traffic and may trigger security alerts
- **Legal Compliance**: Ensure compliance with local laws and organizational policies
- **Firewall Rules**: Verify network access between scanner and targets

### Best Practices

1. **Start Small**: Test with small subnets (e.g., /30 or /28)
2. **Monitor Resources**: Watch CPU and network usage during scans
3. **Schedule Appropriately**: Run comprehensive scans during maintenance windows
4. **Secure Access**: Use authentication and restrict web interface access
5. **Regular Updates**: Keep dependencies and CVE databases current

## 🔧 Troubleshooting

### Common Issues

| Issue | Solution |
|-------|----------|
| **Nmap not found** | Install nmap: `brew install nmap` (macOS) or `sudo apt install nmap` (Ubuntu) |
| **Permission denied** | Run with sudo: `sudo python3 app.py` |
| **CVE lookup fails** | Check internet connectivity; use `--no-cve` flag if needed |
| **Slow scanning** | Reduce thread count or scan smaller subnets |
| **Port 5000 in use** | Set different port: `export FLASK_RUN_PORT=8080` |

### Performance Tuning

| Network Size | Recommended Settings |
|--------------|---------------------|
| **Small** (< 50 hosts) | Default (10 threads) |
| **Medium** (50-200 hosts) | 15-20 threads |
| **Large** (> 200 hosts) | 25+ threads, batch scanning |

### Debugging

```bash
# Enable debug mode
export FLASK_DEBUG=true

# Verbose logging
python3 app.py

# Test core scanner
python3 vuln_scan.py -t 127.0.0.1/32 --threads 1
```

## 📁 Project Structure

```
IP_Ports_Scanner/
├── app.py                 # Flask web application
├── vuln_scan.py          # Core scanner engine
├── requirements.txt      # Python dependencies
├── README.md            # Documentation
├── .gitignore           # Git ignore rules
├── .vscode/             # VSCode settings
│   └── settings.json
├── templates/           # HTML templates
│   ├── base.html
│   ├── index.html
│   ├── login.html
│   └── error.html
├── static/              # Static assets
│   ├── css/
│   ├── js/
│   └── img/
└── venv/               # Python virtual environment
```

## 🔌 API Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/` | GET | Main dashboard |
| `/start_scan` | POST | Initiate new scan |
| `/scan_status/<id>` | GET | Get scan progress |
| `/scan_results/<id>` | GET | Retrieve results |
| `/export_csv/<id>` | GET | Download CSV |
| `/active_scans` | GET | List active scans |
| `/login` | GET/POST | Authentication |

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch
3. Implement changes with tests
4. Submit a pull request

## 📄 License

This project is for authorized internal use only. Ensure compliance with:
- Local cybersecurity laws and regulations
- Organizational security policies
- Network usage agreements

## 🆘 Support

For issues and questions:
1. Check the troubleshooting section
2. Review log files in the application directory
3. Verify Nmap installation and permissions
4. Contact your system administrator

---

**⚠️ Disclaimer**: This tool is designed for authorized security testing only. Users are responsible for ensuring they have proper permission before scanning any network infrastructure.