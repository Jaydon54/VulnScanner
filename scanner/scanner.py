# scanner/ scanner.py
# Code for Scanner goes here

#Imports
import nmap # type: ignore

# Quick scan function
def quick_scan(target):
    """
    Most basic scan option, it only scans the most common ports.
    """
    print("Starting quick scan on {target}")
    scanner = nmap.PortScanner()
    try:
        # For quick scan we only scan FTP, SSH, HTTP, and HTTPS ports
        # (port 8080 added for testing)
        scanner.scan(hosts=target, ports = '21,22,80,443, 8080', arguments='-T4 -Pn')

        print("scan executed.")
        print("scan info:", scanner.scaninfo())

        # If NO open ports are found
        if not scanner.all_hosts():
            print("No hosts were found, would you like to perform a deeper scan?")
            return

        # If open ports are found
        print("Quick scan results:")    
        for host in scanner.all_hosts():
            print(f"Host: {host} ({scanner[host].hostname()})") 
            print(f"State: {scanner[host].state()}") #whether the host is up or down
            for proto in scanner[host].all_protocols(): 
                print(f"Protocol: {proto}")
                ports = scanner[host][proto].keys()
                for port in sorted(ports):
                    print(f"Port: {port}\tState: {scanner[host][proto][port]['state']}")
    #error handling 
    except nmap.PortScannerError as e:
        print(f" Scan error: {e}")