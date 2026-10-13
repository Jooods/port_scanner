"""
port_scanner_cmd.py
Windows CMD / Terminal Port Scanner (TCP & UDP)
Runs at user level (No Administrator privileges required)
"""

import argparse
import os
import sys
import time

from scanner_core import (
    PORT_PRESETS,
    get_service_name,
    parse_port_input,
    scan_ports_parallel,
)

# Enable ANSI colors in Windows CMD if supported
if os.name == "nt":
    os.system("color")

COLOR_GREEN = "\033[92m"
COLOR_RED = "\033[91m"
COLOR_YELLOW = "\033[93m"
COLOR_CYAN = "\033[96m"
COLOR_BOLD = "\033[1m"
COLOR_RESET = "\033[0m"


def print_banner():
    banner = f"""{COLOR_CYAN}{COLOR_BOLD}
 ==============================================================
           WINDOWS PORT SCANNER (USER-LEVEL CMD)
       TCP / UDP Port Search & Status Check Engine
 =============================================================={COLOR_RESET}
"""
    print(banner)


def display_results_table(results, search_filter=None, open_only=False):
    filtered = []
    for r in results:
        port, proto, status, service, latency = r
        if open_only and status != "OPEN":
            continue
        if search_filter:
            sf = search_filter.lower()
            if not (sf in str(port) or sf in proto.lower() or sf in status.lower() or sf in service.lower()):
                continue
        filtered.append(r)

    print("-" * 72)
    print(f" {'PORT':<8} {'PROTO':<8} {'STATUS':<14} {'SERVICE':<28} {'LATENCY':<10}")
    print("-" * 72)

    open_count = 0
    for port, proto, status, service, latency in filtered:
        if status == "OPEN":
            status_str = f"{COLOR_GREEN}{COLOR_BOLD}[OPEN]{COLOR_RESET}       "
            open_count += 1
        else:
            status_str = f"{COLOR_RED}[CLOSED]{COLOR_RESET}     "

        srv_str = service[:26]
        lat_str = f"{latency:.1f}ms"
        print(f" {port:<8} {proto:<8} {status_str} {srv_str:<28} {lat_str:<10}")

    print("-" * 72)
    print(f" Displaying: {len(filtered)} port(s) | Open: {COLOR_GREEN}{open_count}{COLOR_RESET} | Closed: {len(filtered) - open_count}")
    print("-" * 72)


def interactive_mode():
    print_banner()
    print(" [1] Scan Localhost (127.0.0.1)")
    print(" [2] Enter Custom IP / Hostname")
    print(" [3] Exit")
    choice = input("\nSelect an option [1-3]: ").strip()

    if choice == "3":
        print("Goodbye!")
        return

    if choice == "1":
        host = "127.0.0.1"
    else:
        host = input("Enter target IP or Domain (e.g. 192.168.1.1 or scanme.nmap.org): ").strip()
        if not host:
            host = "127.0.0.1"

    print("\nSelect Protocol:")
    print(" [1] TCP (Default)")
    print(" [2] UDP")
    print(" [3] BOTH (TCP & UDP)")
    p_choice = input("Select protocol [1-3, default 1]: ").strip()
    proto_map = {"1": "TCP", "2": "UDP", "3": "BOTH"}
    protocol = proto_map.get(p_choice, "TCP")

    print("\nPort Presets available:")
    for idx, (name, val) in enumerate(PORT_PRESETS.items(), 1):
        print(f" [{idx}] {name:<28} ({val[:35]}...)")
    print(" [0] Custom port input (e.g., '80, 443' or '1-100')")

    preset_choice = input("\nChoose preset or 0 for custom [default: 1]: ").strip()
    if preset_choice in ("", "1"):
        ports_str = PORT_PRESETS["Top 20 Common"]
    elif preset_choice.isdigit() and 1 <= int(preset_choice) <= len(PORT_PRESETS):
        preset_keys = list(PORT_PRESETS.keys())
        ports_str = PORT_PRESETS[preset_keys[int(preset_choice) - 1]]
    else:
        ports_str = input("Enter ports (e.g. 80,443,8080 or 20-100): ").strip()

    ports = parse_port_input(ports_str)
    if not ports:
        print(f"{COLOR_RED}No valid ports specified. Exiting.{COLOR_RESET}")
        return

    print(f"\n{COLOR_CYAN}Starting scan on {host} ({len(ports)} ports, {protocol})...{COLOR_RESET}")
    start_t = time.time()

    def on_progress(done, total, res):
        port, proto, status, service, _ = res
        tag = f"{COLOR_GREEN}OPEN{COLOR_RESET}" if status == "OPEN" else "closed"
        sys.stdout.write(f"\rScanning: {done}/{total} ports checked... (Port {port}/{proto} is {tag})   ")
        sys.stdout.flush()

    results = scan_ports_parallel(
        host=host,
        ports=ports,
        protocol=protocol,
        max_workers=40,
        timeout=1.0,
        progress_callback=on_progress,
    )
    print("\n")
    print(f"{COLOR_GREEN}Scan finished in {time.time() - start_t:.2f} seconds!{COLOR_RESET}\n")

    display_results_table(results)

    # Post-scan search/filter loop
    while True:
        print("\nOptions: [s] Search/Filter results | [o] Toggle Open-only | [q] Quit to menu")
        opt = input("Choice: ").strip().lower()
        if opt == "s":
            kw = input("Enter search keyword (port number, service name, or status): ").strip()
            display_results_table(results, search_filter=kw)
        elif opt == "o":
            display_results_table(results, open_only=True)
        elif opt == "q":
            break


def cli_mode():
    parser = argparse.ArgumentParser(
        description="Windows Port Scanner (User-level TCP / UDP Scanner)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--host", "-H", default="127.0.0.1", help="Target Host or IP (default: 127.0.0.1)")
    parser.add_argument("--ports", "-p", default="80,443,8080,3000,3306,3389,22", help="Ports to scan (e.g. '80', '80,443', '1-100')")
    parser.add_argument("--proto", choices=["tcp", "udp", "both"], default="tcp", help="Protocol: tcp, udp, or both (default: tcp)")
    parser.add_argument("--timeout", "-t", type=float, default=1.0, help="Socket timeout in seconds (default: 1.0)")
    parser.add_argument("--open-only", action="store_true", help="Display only open ports in output")
    parser.add_argument("--search", "-s", default="", help="Filter results by keyword or service name")

    args = parser.parse_args()

    ports = parse_port_input(args.ports)
    if not ports:
        print(f"{COLOR_RED}Error: No valid ports entered in --ports: {args.ports}{COLOR_RESET}")
        sys.exit(1)

    print_banner()
    print(f"Target:   {COLOR_BOLD}{args.host}{COLOR_RESET}")
    print(f"Protocol: {args.proto.upper()}")
    print(f"Ports:    {len(ports)} port(s)")
    print(f"Timeout:  {args.timeout}s\n")

    start_t = time.time()
    results = scan_ports_parallel(
        host=args.host,
        ports=ports,
        protocol=args.proto.upper(),
        max_workers=50,
        timeout=args.timeout,
    )
    elapsed = time.time() - start_t

    print(f"Scan completed in {elapsed:.2f}s.\n")
    display_results_table(results, search_filter=args.search, open_only=args.open_only)


if __name__ == "__main__":
    if len(sys.argv) > 1:
        cli_mode()
    else:
        interactive_mode()
