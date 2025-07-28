# LogGuardian
LogGuardian is a log analysis tool that detects security threats like brute force, port scans, and DNS tunneling from FortiGate, Windows, and Apache logs.
## Features
- Parses FortiGate, Windows (event 4625/4624), and Apache logs
- Detects:
  - Brute Force attempts
  - Port Scanning
  - DNS Tunneling
  - Malicious Website Access
- Generates alerts with timestamps and source IPs
- Creates detailed JSON reports
- Provides an interactive console for inspection
## Installation

1. Clone this repository:
https://github.com/AfraDemir/LogGuardian/tree/main/Logguardian_2.0
cd logguardian
2. Run the script

## Usage

1. Place your log file as `örneklog.txt` in the root directory.

2. Run the script:
alarm_log.py

3. Use the console to:
- View alarms
- List all logs
- Analyze attacker IPs

4. A JSON report will be created automatically: `rapor_YYYY-MM-DD_HH-MM.json`

## Supported Log Formats

- **FortiGate:** Structured logs with `srcip`, `dstip`, `msg`, `dstport`
- **Windows:** Event ID 4625 / 4624, includes source IP
- **Apache:** Common log format, HTTP status code 401 used for brute force detection

## JSON Report Content

The output file includes:

- `toplam_log_sayisi`: Total log count
- `alarm_kayitlari`: Detailed alarm list
- `ozet`: Grouped alert summary
- `log_kayitlari`: All parsed logs with ID



