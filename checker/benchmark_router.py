"""
benchmark_router.py
A simple script to benchmark IPv4 router throughput and latency using Scapy.
Run this script on a Mininet host connected to your router.
"""

import time
from scapy.all import Ether, IP, sendp, srp1, conf

# CONFIGURATION: These values are for Host 0 sending packets to Host 1 through your router.
INTERFACE = "h-0"                # Host 0's interface name in Mininet
SRC_MAC   = "de:ad:be:ef:00:00"  # Host 0's MAC address
DST_MAC   = "de:fe:c8:ed:00:00"  # Router's MAC address on interface r-0 (next hop for Host 0)
SRC_IP    = "192.168.0.2"        # Host 0's IP address
DST_IP    = "192.168.1.2"        # Host 1's IP address (final destination)

# Benchmark parameters
PACKET_COUNT = 10000       # Number of packets for throughput test
LATENCY_RUNS = 100         # Number of pings for latency test

def throughput_test():
    """Sends PACKET_COUNT packets as fast as possible, measures throughput."""
    pkt = Ether(src=SRC_MAC, dst=DST_MAC) / IP(src=SRC_IP, dst=DST_IP)
    print(f"Sending {PACKET_COUNT} packets to measure throughput...")
    start = time.time()
    sendp([pkt] * PACKET_COUNT, iface=INTERFACE, verbose=False)
    end = time.time()
    duration = end - start
    pps = PACKET_COUNT / duration
    print(f"Throughput: {pps:,.0f} packets/sec over {duration:.2f} seconds")
    return pps

def latency_test():
    """Measures average latency by sending ICMP Echo through the router."""
    from scapy.all import ICMP
    latencies = []
    print(f"Measuring latency ({LATENCY_RUNS} runs)...")
    for i in range(LATENCY_RUNS):
        pkt = Ether(src=SRC_MAC, dst=DST_MAC) / IP(src=SRC_IP, dst=DST_IP) / ICMP()
        start = time.time()
        reply = srp1(pkt, iface=INTERFACE, timeout=2, verbose=False)
        end = time.time()
        if reply:
            latency = (end - start) * 1_000_000  # us
            latencies.append(latency)
    if latencies:
        avg = sum(latencies) / len(latencies)
        p99 = sorted(latencies)[int(0.99 * len(latencies))-1]
        print(f"Average latency: {avg:.0f} us, p99 latency: {p99:.0f} us")
    else:
        print("No replies received; check your routing and host addresses.")

if __name__ == "__main__":
    print("=== IPv4 Router Benchmark ===")
    print("Interface:", INTERFACE)
    print("Source MAC/IP:", SRC_MAC, SRC_IP)
    print("Dest MAC/IP:", DST_MAC, DST_IP)
    print()
    throughput_test()
    print()
    latency_test()