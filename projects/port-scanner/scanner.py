#!/usr/bin/env python3
"""
Automated TCP Port Scanner (Deliverable 1)
Author: Ayan Abbas
Purpose: Fast, educational network reconnaissance and security audit tool.
Auditing exposed ports, validating AWS Security Groups, and detecting open attack surfaces.
"""

import argparse
import socket
import sys
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime


def resolve_target(target_host: str) -> str:
    """Resolves hostname to IPv4 address."""
    try:
        return socket.gethostbyname(target_host)
    except socket.gaierror:
        print(f"[-] Error: Could not resolve hostname '{target_host}'. Check DNS or network connection.")
        sys.exit(1)


def get_service_name(port: int) -> str:
    """Identifies the standard service associated with a well-known port."""
    try:
        return socket.getservbyport(port, "tcp").upper()
    except (OSError, socket.error):
        common_ports = {
            22: "SSH",
            80: "HTTP",
            443: "HTTPS",
            3306: "MYSQL",
            5432: "POSTGRESQL",
            6379: "REDIS",
            8080: "HTTP-PROXY",
            8443: "HTTPS-ALT",
            9000: "SONARQUBE",
        }
        return common_ports.get(port, "UNKNOWN")


def scan_port(target_ip: str, port: int, timeout: float = 1.0) -> tuple:
    """
    Attempts a TCP 3-way handshake on the target IP and port.
    Returns (port, is_open, service_name).
    """
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.settimeout(timeout)
        # connect_ex returns 0 on successful TCP handshake (SYN -> SYN-ACK -> ACK)
        result = sock.connect_ex((target_ip, port))
        is_open = result == 0
        service = get_service_name(port) if is_open else ""
        return (port, is_open, service)


def run_scanner(target: str, start_port: int, end_port: int, threads: int = 50, timeout: float = 1.0):
    target_ip = resolve_target(target)
    total_ports = end_port - start_port + 1

    print("=" * 70)
    print(f"  AUTOMATED TCP PORT SCANNER - CLOUD SECURITY AUDIT")
    print("=" * 70)
    print(f"  Target Host      : {target} ({target_ip})")
    print(f"  Port Range       : {start_port} - {end_port} ({total_ports} ports)")
    print(f"  Concurrency      : {threads} worker threads")
    print(f"  Socket Timeout   : {timeout}s")
    print(f"  Scan Initiated   : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("=" * 70 + "\n")

    open_ports = []

    try:
        with ThreadPoolExecutor(max_workers=threads) as executor:
            futures = [
                executor.submit(scan_port, target_ip, p, timeout)
                for p in range(start_port, end_port + 1)
            ]

            for future in futures:
                port, is_open, service = future.result()
                if is_open:
                    print(f"  [+] Port {port:5d}/TCP : OPEN  --> [{service}]")
                    open_ports.append((port, service))

    except KeyboardInterrupt:
        print("\n[!] Scan interrupted by user. Exiting...")
        sys.exit(0)

    print("\n" + "=" * 70)
    print(f"  SCAN REPORT SUMMARY")
    print("=" * 70)
    print(f"  Completed At     : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"  Total Ports      : {total_ports}")
    print(f"  Open Ports Found : {len(open_ports)}")

    if open_ports:
        print("\n  Exposed Ports List:")
        for port, service in sorted(open_ports):
            print(f"    - TCP {port} ({service})")
    else:
        print("  No open ports discovered in the specified range.")
    print("=" * 70)

    return open_ports


def main():
    parser = argparse.ArgumentParser(
        description="Automated TCP Port Scanner for Cloud Security Audits & EC2 Validation."
    )
    parser.add_argument("target", help="Target IP address or domain name (e.g., 54.211.10.5 or scanme.nmap.org)")
    parser.add_argument("start_port", type=int, help="Starting port number (e.g., 1)")
    parser.add_argument("end_port", type=int, help="Ending port number (e.g., 1024)")
    parser.add_argument("-t", "--threads", type=int, default=50, help="Number of concurrent worker threads (default: 50)")
    parser.add_argument("-w", "--timeout", type=float, default=1.0, help="Socket timeout in seconds (default: 1.0)")

    args = parser.parse_args()

    if args.start_port < 1 or args.end_port > 65535 or args.start_port > args.end_port:
        print("[-] Error: Invalid port range. Ports must be between 1 and 65535.")
        sys.exit(1)

    run_scanner(args.target, args.start_port, args.end_port, args.threads, args.timeout)


if __name__ == "__main__":
    main()
