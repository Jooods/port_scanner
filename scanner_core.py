"""
scanner_core.py
Port Scanner Core Engine (User-Level, Windows compatible)
Supports TCP connect scan and UDP probe scan without requiring administrator privileges.
"""

import socket
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Callable, Dict, Generator, List, Optional, Tuple

# Comprehensive dictionary of well-known and common ports
COMMON_SERVICES: Dict[int, str] = {
    20: "FTP-Data",
    21: "FTP-Control",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    67: "DHCP-Server",
    68: "DHCP-Client",
    69: "TFTP",
    80: "HTTP (Web)",
    110: "POP3",
    123: "NTP",
    135: "MS-RPC",
    137: "NetBIOS-NS",
    138: "NetBIOS-DGM",
    139: "NetBIOS-SSN",
    143: "IMAP",
    161: "SNMP",
    162: "SNMP-Trap",
    389: "LDAP",
    443: "HTTPS (Web SSL)",
    445: "SMB (File Share)",
    465: "SMTPS",
    500: "ISAKMP/IKE",
    514: "Syslog",
    587: "SMTP (Submission)",
    636: "LDAPS",
    993: "IMAPS",
    995: "POP3S",
    1433: "MS SQL Server",
    1434: "MS SQL Monitor",
    1521: "Oracle DB",
    1723: "PPTP",
    1883: "MQTT",
    2049: "NFS",
    3000: "Dev Server / Node",
    3306: "MySQL Database",
    3389: "RDP (Remote Desktop)",
    4000: "Dev Server",
    5000: "Flask / Dev Server",
    5432: "PostgreSQL Database",
    5900: "VNC Remote Desktop",
    6379: "Redis Database",
    8000: "HTTP Alt (Dev)",
    8080: "HTTP Proxy / Alt",
    8443: "HTTPS Alt",
    8888: "HTTP Alt / Jupyter",
    9000: "SonarQube / PHP-FPM",
    9200: "Elasticsearch",
    27017: "MongoDB",
}

# Pre-packaged port lists for quick selection
PORT_PRESETS = {
    "Top 20 Common": "21,22,23,25,53,80,110,135,139,143,443,445,993,995,1433,3306,3389,5432,8080,8443",
    "Web Servers": "80,443,3000,4000,5000,8000,8080,8443,8888",
    "Databases": "1433,1521,3306,5432,6379,9200,27017",
    "Remote Access & Admin": "22,23,135,139,445,3389,5900",
    "Common UDP": "53,67,68,69,123,137,138,161,162,500,514",
    "Top 100 Range": "1-100",
    "Full Standard Range (1-1024)": "1-1024",
}


def get_service_name(port: int, proto: str = "TCP") -> str:
    """Return common service name for a given port."""
    if port in COMMON_SERVICES:
        return COMMON_SERVICES[port]
    try:
        return socket.getservbyport(port, proto.lower())
    except (OSError, socket.error):
        return "Unknown"


def parse_port_input(port_string: str) -> List[int]:
    """
    Parses user port input strings.
    Supports:
      - Single port: "80"
      - Comma-separated: "80, 443, 8080"
      - Ranges: "1-100", "8000-8080"
      - Mixed: "22, 80-85, 443, 3306"
    """
    ports = set()
    cleaned = port_string.strip()
    if not cleaned:
        return []

    tokens = [t.strip() for t in cleaned.split(",") if t.strip()]
    for token in tokens:
        if "-" in token:
            parts = token.split("-")
            if len(parts) == 2:
                try:
                    start = int(parts[0].strip())
                    end = int(parts[1].strip())
                    if start > end:
                        start, end = end, start
                    start = max(1, min(65535, start))
                    end = max(1, min(65535, end))
                    for p in range(start, end + 1):
                        ports.add(p)
                except ValueError:
                    pass
        else:
            try:
                p = int(token)
                if 1 <= p <= 65535:
                    ports.add(p)
            except ValueError:
                pass

    return sorted(list(ports))


def scan_tcp_port(target_ip: str, port: int, timeout: float = 1.0) -> Tuple[int, str, str, str, float]:
    """
    Standard user-level TCP Connect scan.
    Returns: (port, protocol, status, service, latency_ms)
    status is 'OPEN' or 'CLOSED'.
    """
    start_time = time.time()
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    status = "CLOSED"
    latency = 0.0

    try:
        result = s.connect_ex((target_ip, port))
        latency = (time.time() - start_time) * 1000.0
        if result == 0:
            status = "OPEN"
        else:
            status = "CLOSED"
    except socket.timeout:
        status = "CLOSED"
    except socket.gaierror:
        status = "ERROR"
    except Exception:
        status = "CLOSED"
    finally:
        try:
            s.close()
        except Exception:
            pass

    service = get_service_name(port, "TCP")
    return (port, "TCP", status, service, round(latency, 2))


def scan_udp_port(target_ip: str, port: int, timeout: float = 1.2) -> Tuple[int, str, str, str, float]:
    """
    User-level UDP probe scan.
    Sends lightweight service-specific probes where applicable (DNS, NTP, etc.)
    or a standard UDP ping.
    Returns: (port, protocol, status, service, latency_ms)
    """
    start_time = time.time()
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(timeout)
    status = "CLOSED"
    latency = 0.0

    # Service-specific UDP probe payloads
    probes = {
        53: b"\xaa\xaa\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x07example\x03com\x00\x00\x01\x00\x01",  # DNS query
        123: b"\x1b" + 47 * b"\0",  # NTP v3 client request
        161: b"\x30\x26\x02\x01\x00\x04\x06public\xa0\x19\x02\x01\x00\x02\x01\x00\x02\x01\x00\x30\x0e\x30\x0c\x06\x08\x2b\x06\x01\x02\x01\x01\x01\x00\x05\x00",  # SNMP Get
    }
    payload = probes.get(port, b"PING\x00\r\n")

    try:
        s.sendto(payload, (target_ip, port))
        data, _ = s.recvfrom(1024)
        latency = (time.time() - start_time) * 1000.0
        if data:
            status = "OPEN"
    except socket.timeout:
        # For UDP, no response on user-level sockets may indicate closed or silent listener.
        status = "NO RESPONSE / CLOSED"
    except ConnectionResetError:
        # Windows winsock 10054 = Port Unreachable ICMP received back
        status = "CLOSED"
    except Exception:
        status = "CLOSED"
    finally:
        try:
            s.close()
        except Exception:
            pass

    service = get_service_name(port, "UDP")
    return (port, "UDP", status, service, round(latency, 2))


def scan_ports_parallel(
    host: str,
    ports: List[int],
    protocol: str = "TCP",  # "TCP", "UDP", or "BOTH"
    max_workers: int = 50,
    timeout: float = 1.0,
    progress_callback: Optional[Callable[[int, int, Tuple], None]] = None,
    stop_event: Optional[Callable[[], bool]] = None,
) -> List[Tuple[int, str, str, str, float]]:
    """
    Scans ports concurrently using ThreadPoolExecutor.
    Calls progress_callback(completed_count, total_count, last_result) after each port.
    Returns list of (port, proto, status, service, latency_ms).
    """
    # Resolve host to IP
    try:
        target_ip = socket.gethostbyname(host)
    except socket.gaierror as e:
        raise ValueError(f"Could not resolve host '{host}': {e}")

    tasks = []
    protocol_upper = protocol.upper()
    for p in ports:
        if protocol_upper in ("TCP", "BOTH"):
            tasks.append((p, "TCP"))
        if protocol_upper in ("UDP", "BOTH"):
            tasks.append((p, "UDP"))

    total = len(tasks)
    results = []

    def worker(task_item):
        port_num, proto_type = task_item
        if proto_type == "TCP":
            return scan_tcp_port(target_ip, port_num, timeout)
        else:
            return scan_udp_port(target_ip, port_num, timeout)

    with ThreadPoolExecutor(max_workers=min(max_workers, total or 1)) as executor:
        future_to_task = {executor.submit(worker, t): t for t in tasks}
        completed = 0
        for future in as_completed(future_to_task):
            if stop_event and stop_event():
                break
            res = future.result()
            results.append(res)
            completed += 1
            if progress_callback:
                progress_callback(completed, total, res)

    # Sort results by port number and protocol
    results.sort(key=lambda x: (x[0], x[1]))
    return results
