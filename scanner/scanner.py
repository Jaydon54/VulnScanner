# scanner/ scanner.py
# Code for Scanner goes here

#Imports
import nmap # type: ignore
from utils.utils import print_results # type: ignore

# Quick scan function
def quick_scan(target):
    """
    Most basic scan option, it only scans the most common ports(FTP, SSh, HTTP, HTTPs).
    """
    print(f"Starting quick scan on {target}")
    scanner = nmap.PortScanner()
    try:
        # For quick scan we only scan FTP, SSH, HTTP, and HTTPS ports
        # (port 8080 added for testing)
        scanner.scan(hosts=target, ports = '21,22,80,443', arguments='-T4 -Pn')

        print("scan executed.")
        print("scan info:", scanner.scaninfo())

        # If NO open ports are found
        if not scanner.all_hosts():
            print("No open ports were found, would you like to perform a deeper scan?")
            return

        # If open ports are found
        print("Quick scan results:")    
        print_results(scanner)
    # error handling 
    except nmap.PortScannerError as e:
        print(f" Scan error: {e}")

#regular scan
def regular_scan(target):
    """ 
    Regular scan option, it scans custom ports (user input) and services.
    """
    print(f"Starting regular scan on {target}")
    scanner = nmap.PortScanner()
    try:
        #input ports to be scanned
        ports = input("Enter the ports to be scanned (eg. 21,22 or 1-1000): ")
        # sS means stealth scan, T4 = agressive scan(faster), Pn means no ping scan
        scanner.scan(hosts=target, ports = ports, arguments='-sS -T4 -Pn')

        print("scan executed.")
        print("scan info:", scanner.scaninfo())

        # If NO open ports are found
        if not scanner.all_hosts():
            print("No open ports were found, would you like to perform a deeper scan?")
            return

        # If open ports are found
        print("Regular scan results:")    
        print_results(scanner)
    # error handling 
    except nmap.PortScannerError as e:
        print(f" Scan error: {e}")


    # deep scan
    #scans all ports and services
def deep_scan(target):
    """ 
        Deep scan option, it scans all ports and services.
    """
    print(f"Starting deep scan on {target}")
    scanner = nmap.PortScanner()
    try:
        #scans all ports
        # added Sv argument to detect service provider and version
        scanner.scan(hosts=target, ports = '1-65535', arguments='-sS -sV -T4 -Pn')

        #displays scan info
        print("Deep scan executed.")
        print("scan info:", scanner.scaninfo())

        # If NO open ports are found
        if not scanner.all_hosts():
            print("No open ports were found, you should be safe!")
            return

        # If open ports are found
        print("Deep scan results:")    
        print_results(scanner)
    # error handling 
    except nmap.PortScannerError as e:
        print(f" Scan error: {e}")