"""
Day 02-03 Lab: CIDR Subnet Calculator
Demonstrating subnet division, prefix math, and usable host calculations using Python's ipaddress module.
"""

import ipaddress
import sys

# Ensure UTF-8 output encoding for cross-platform compatibility
if sys.platform == "win32":
    sys.stdout.reconfigure(encoding="utf-8")


def calculate_subnets(network_cidr: str, new_prefix: int):
    print("=" * 70)
    print(f"Subnetting Lab: Splitting {network_cidr} into /{new_prefix} Subnets")
    print("=" * 70)

    base_net = ipaddress.ip_network(network_cidr)
    subnets = list(base_net.subnets(new_prefix=new_prefix))

    print(f"Parent Network      : {base_net}")
    print(f"Parent Total Hosts  : {base_net.num_addresses} IP addresses")
    print(f"Borrowed Bits       : {new_prefix - base_net.prefixlen} bits")
    print(f"Total Subnets Formed: {len(subnets)}\n")

    for idx, s in enumerate(subnets, 1):
        hosts = list(s.hosts())
        first_host = hosts[0] if hosts else "None"
        last_host = hosts[-1] if hosts else "None"
        print(f"Subnet #{idx}: {s}")
        print(f"  |-- Network Address   : {s.network_address}")
        print(f"  |-- Usable Host Range : {first_host} - {last_host}")
        print(f"  |-- Broadcast Address : {s.broadcast_address}")
        print(f"  |-- Standard Usable   : {len(hosts)} hosts (Total: {s.num_addresses} - 2)")
        print(f"  \\-- AWS Usable Hosts  : {max(0, s.num_addresses - 5)} hosts (AWS reserves 5 IPs: .0, .1, .2, .3, .255)\n")


if __name__ == "__main__":
    # Splitting 192.168.10.0/24 into 4 equal subnets (/26)
    calculate_subnets("192.168.10.0/24", new_prefix=26)
