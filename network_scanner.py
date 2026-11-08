"""TCP network scanner.

Finds live hosts on a network, scans their ports, and grabs a banner
from every open port. Use only on networks you own or have permission
to test.

Examples:
    python3 network_and_port_scanner.py 192.168.20.4 -p 22,80,4444
    python3 network_and_port_scanner.py 192.168.20.0/24 -p 1-1024 --threads 5
"""

from concurrent.futures import ThreadPoolExecutor  # a team of parallel workers
import socket       # network connections
import errno        # named error numbers, e.g. errno.ECONNREFUSED
import ipaddress    # turns "192.168.20.0/24" into single addresses
import time         # used to time the whole scan
import argparse     # reads the options typed after the script name


def scan_tcp(host, port, timeout):
    """Check ONE TCP port on ONE host.

    Returns "open" (handshake completed), "closed" (host replied with a
    refusal, so nothing listens there) or "filtered" (no clear answer,
    e.g. a timeout because a firewall dropped the packets).
    """
    # a new IPv4 (AF_INET) TCP (SOCK_STREAM) socket just for this check
    scan = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    # stop waiting after `timeout` seconds so a silent host can't freeze us
    scan.settimeout(timeout)
    # connect_ex returns an error NUMBER instead of raising an exception
    result = scan.connect_ex((host, port))
    # always hang up: every open socket uses one of the OS's limited slots
    scan.close()

    if result == 0:                      # 0 means the connection succeeded
        return "open"
    elif result == errno.ECONNREFUSED:   # the host answered "nobody here"
        return "closed"
    else:                                # timeout, unreachable, dropped...
        return "filtered"


def grab_banner(host, port, timeout):
    """Read what a service says about itself when you connect.

    Returns the banner text, or "" if the service stays silent
    (web servers, for example, wait for a request first).
    """
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    try:
        # connect() raises OSError on failure (unlike connect_ex)
        sock.connect((host, port))
        # read up to 1024 bytes; raises OSError if nothing arrives in time
        received_banner = sock.recv(1024)
        # bytes -> text; "replace" swaps bad bytes for a placeholder
        # instead of crashing
        banner = received_banner.decode('utf-8', errors="replace")
        # remove the trailing \r\n
        banner = banner.strip()
        return banner
    except OSError:
        # timeout, refused, reset: all just mean "no banner"
        return ""
    finally:
        # runs no matter what happened above, so the socket never leaks
        sock.close()


def scan_host(host, ports, timeout, threads=50):
    """Scan many ports on ONE host in parallel.

    Returns a list of (port, banner) pairs, one per open port.
    """
    results = []

    # Defined inside scan_host so it can use `host` and `timeout` directly.
    # pool.map passes only ONE value (the port), so this saves us a lambda.
    def check_one_port(port):
        status = scan_tcp(host, port, timeout)
        if status == "open":
            banner = grab_banner(host, port, timeout)
            return (port, banner)
        return None   # closed/filtered ports produce no result

    # hire `threads` workers; each takes one port at a time
    with ThreadPoolExecutor(max_workers=threads) as pool:
        # map starts every job at once and hands results back in port order
        port_results = pool.map(check_one_port, ports)
    # leaving the with-block waited for all workers, so results are ready

    # keep only the real results and drop the Nones
    for result in port_results:
        if result is not None:
            results.append(result)

    return results


def is_alive(ip, probe_ports, timeout):
    """Check whether ONE host replies on any of the probe ports.

    "open" or "closed" both mean the machine answered, so it is alive.
    Only silence ("filtered") on every port counts as not alive.
    """
    for port in probe_ports:
        answer = scan_tcp(ip, port, timeout)
        if answer == "open" or answer == "closed":
            return True    # one reply is enough, skip the other ports
    return False           # every port stayed silent


def discover_hosts(network, probe_ports, timeout, threads=50):
    """Find which addresses on a network are alive, many at a time.

    network is in CIDR form, e.g. "192.168.20.0/24".
    Returns a list of live IP strings.
    """
    # 1. build the list of every address as text
    ips = []
    # .hosts() gives the usable addresses (.1 to .254 for a /24)
    addresses = ipaddress.ip_network(network, strict=False).hosts()
    for ipadress in addresses:
        ips.append(str(ipadress))

    # 2. give every address to the team; each worker runs is_alive on one
    # (lambda fills in the two fixed values because map passes just one)
    with ThreadPoolExecutor(max_workers=threads) as pool:
        results = list(pool.map(lambda ip: is_alive(ip, probe_ports, timeout), ips))

    # 3. results are in the same order as ips, so zip pairs them up
    live_hosts = []
    for ip, alive in zip(ips, results):
        if alive:
            live_hosts.append(ip)
    return live_hosts


def parse_ports(port_string):
    """Turn the text typed after -p into something we can loop over.

    "22,80,443" -> [22, 80, 443]    "1-1024" -> ports 1 to 1024
    "-" -> ports 1 to 1024          None -> None (main will ask the user)
    """
    if port_string is None:
        return None
    if port_string == "-":
        # a shortcut of this scanner (nmap's own "-p-" means ALL ports)
        return range(1, 1025)
    if "-" in port_string:
        # "1-1024" splits into ["1", "1024"], unpacked into start and end
        start, end = port_string.split("-")
        # +1 because range() stops just before its end value
        return range(int(start), int(end) + 1)
    # "22,80" -> ["22", "80"] -> [22, 80]  (list comprehension)
    return [int(p) for p in port_string.split(",")]


def main():
    """Read the command line, then run discovery and port scanning."""
    # --- read what the user typed after the script name ---
    parser = argparse.ArgumentParser()
    parser.add_argument("target")                        # required: IP or CIDR
    parser.add_argument("-p", "--ports", default=None)   # optional, None if absent
    # type=int turns the text "5" into the number 5
    parser.add_argument("--threads", type=int, default=5)

    args = parser.parse_args()   # fills args.target, args.ports, args.threads

    # if no ports were given, ask interactively
    ports_arg = args.ports
    if ports_arg is None:
        print("You didn't specify ports.")
        ports_arg = input("Enter ports (e.g. 22,80 or '-' for 1-1024): ")

    port_list = parse_ports(ports_arg)
    # NOTE: the real worker count is the typed number x 10
    # (--threads 5 means 50 workers)
    thread_count = args.threads * 10

    print(f"Target: {args.target}")
    print(f"Scanning {len(port_list)} ports using {thread_count} threads.\n")

    start_time = time.time()   # stopwatch for the "finished in" line

    # --- stage 1: which hosts are alive? ---
    if "/" in args.target:
        # a network like 192.168.20.0/24: discover live hosts first
        print(f"Discovering live hosts on {args.target}...")
        live_hosts = discover_hosts(args.target, [80, 443, 22], 1.0, thread_count)
        print(f"Found {len(live_hosts)} live hosts.\n")
    else:
        # a single IP: skip discovery and scan it directly
        live_hosts = [args.target]

    # --- stage 2: scan the ports of each live host ---
    for ip in live_hosts:
        print(f"Scanning {ip}...")
        open_ports = scan_host(ip, port_list, 1.0, thread_count)

        if not open_ports:   # an empty list counts as False
            print(f"  No open ports found on {ip}.")
        else:
            # each item is a (port, banner) pair, unpacked in the loop line
            for port, banner in open_ports:
                if banner:   # a non-empty string counts as True
                    print(f"  [OPEN] Port {port} - Banner: {banner}")
                else:
                    print(f"  [OPEN] Port {port}")
        print()   # blank line between hosts

    elapsed = round(time.time() - start_time, 2)
    print(f"Scan finished in {elapsed} seconds.")


# True only when you run this file directly (python3 file.py),
# and False if another file imports it. This line starts everything.
if __name__ == "__main__":
    main()
