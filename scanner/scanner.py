# scanner/ scanner.py
# Code for Scanner goes here

#Imports
import os
import sys
import nmap # type: ignore
from utils.utils import print_results # type: ignore
from database.database import insert_result
from PDFReportGenerator.PDFReportGenerator import PDFReportGen
from CVE_Checker.CVE_Checker import CVEChecker

api_key = "835093cb-2fed-4d1b-af78-ad31e17e29e0"


# I used AI for this if/else logic - jaydon
#    I was having trouble getting nmap to be installed in the .exe file
if getattr(sys, 'frozen', False):
    # Running from bundled executable
    nmap_path = os.path.join(sys._MEIPASS, 'nmap', 'nmap.exe')
else:
    #running in development
    nmap_path = os.path.join(os.path.dirname(__file__), 'nmap', 'nmap.exe')

nmap.PortScanner()._nmap_path = nmap_path

#Objects
pdf_generator = PDFReportGen(api_key)
CVE_Checker = CVEChecker(api_key)

# port heuristics
use_port_heuristics = True

dangerous_ports = [21, 23, 512, 513, 514, 139, 445]

# Quick scan function
def quick_scan(target):
    """
    Most basic scan option, it only scans the most common ports(FTP, SSh, HTTP, HTTPs).
    """
    print(f"Starting quick scan on {target}")
    scanner = nmap.PortScanner(nmap_search_path=(nmap_path,))
    try:
        # For quick scan we only scan FTP, SSH, HTTP, and HTTPS ports
        # (port 8080 added for testing)
        scanner.scan(hosts=target, ports = '21,22,80,443', arguments='-sS -T4 -Pn -sV')

        print("scan executed.")
        print("scan info:", scanner.scaninfo())

        # If NO open ports are found
        if not scanner.all_hosts():
            print("No open ports were found, would you like to perform a deeper scan?")
            return

        # If open ports are found
        print("Quick scan results:")    
        print_results(scanner)

        #Save result to database
        for host in scanner.all_hosts():
            for proto in scanner[host].all_protocols():
                ports = scanner[host][proto].keys()
                for port in ports: 
                    service = scanner[host][proto][port].get('name', 'unknown')
                    state = scanner[host][proto][port].get('state', 'unknown')
                    product = scanner[host][proto][port].get('product', '')
                    version = scanner[host][proto][port].get('version', '')
                    extra_info = f"{product} {version}".strip()
                

                    # Get risk level from CVE checker
                    print(f"[DEBUG] Querying NVD: Product={product}, Version={version}")
                    if product:
                        cve_info = CVE_Checker.check_scan_results(service, product, version)
                        risk_level = cve_info["risk_level"]

                        if cve_info["cves"]:
                            cve_list = ', '.join(cve_info["cves"])
                            extra_info += f" | CVEs: {cve_list}"

                        
                    else:
                        risk_level = "Unknown"
                
                    if use_port_heuristics and port in dangerous_ports:
                            if risk_level == "Low":
                                risk_level = "High"

                    # Save with risk level
                    insert_result(target, port, service, state, extra_info, "quick", risk_level)


        #PDF Report
        pdf_generator.generate_report(target)
    # error handling 
    except nmap.PortScannerError as e:
        print(f" Scan error: {e}")

#regular scan
def regular_scan(target):
    """ 
    Regular scan option, it scans custom ports (user input) and services.
    """
    print(f"Starting regular scan on {target}")
    scanner = nmap.PortScanner(nmap_search_path=(nmap_path,))
    try:
        #input ports to be scanned
        ports = input("Enter the ports to be scanned (eg. 21,22 or 1-1000): ")
        # sS means stealth scan, T4 = agressive scan(faster), Pn means no ping scan
        scanner.scan(hosts=target, ports = ports, arguments='-sS -T4 -Pn -sV')

        print("scan executed.")
        print("scan info:", scanner.scaninfo())

        # If NO open ports are found    
        if not scanner.all_hosts():
            print("No open ports were found, would you like to perform a deeper scan?")
            return

        # If open ports are found
        print("Regular scan results:")    
        print_results(scanner)

        #Save result to database
        for host in scanner.all_hosts():
            for proto in scanner[host].all_protocols():
                ports = scanner[host][proto].keys()
                for port in ports: 
                    service = scanner[host][proto][port].get('name', 'unknown')
                    state = scanner[host][proto][port].get('state', 'unknown')
                    product = scanner[host][proto][port].get('product', '')
                    version = scanner[host][proto][port].get('version', '')
                    extra_info = f"{product} {version}".strip()
                
                    # Get risk level from CVE checker
                    print(f"[DEBUG] Querying NVD: Product={product}, Version={version}")

                    if product:
                        cve_info = CVE_Checker.check_scan_results(service, product, version)
                        risk_level = cve_info["risk_level"]

                        if cve_info["cves"]:
                            cve_list = ', '.join(cve_info["cves"])
                            extra_info += f" | CVEs: {cve_list}"
                        
                    else:
                        risk_level = "Unknown"
                
                    if use_port_heuristics and port in dangerous_ports:
                            if risk_level == "Low":
                                risk_level = "High"

                    # Save with risk level
                    insert_result(target, port, service, state, extra_info, "regular", risk_level)

        #PDF Report
        pdf_generator.generate_report(target)

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
    scanner = nmap.PortScanner(nmap_search_path=(nmap_path,))
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

        for host in scanner.all_hosts():
            for proto in scanner[host].all_protocols():
                ports = scanner[host][proto].keys()
                for port in ports: 
                    service = scanner[host][proto][port].get('name', 'unknown')
                    state = scanner[host][proto][port].get('state', 'unknown')
                    product = scanner[host][proto][port].get('product', '')
                    version = scanner[host][proto][port].get('version', '')
                    extra_info = f"{product} {version}".strip()
                
                    # Debug print
                    print(f"[DEBUG] Querying NVD: Product={product}, Version={version}")

                    # Get risk level from CVE checker
                    if product:
                        cve_info = CVE_Checker.check_scan_results(service, product, version)
                        risk_level = cve_info["risk_level"]

                        if cve_info["cves"]:
                            cve_list = ', '.join(cve_info["cves"])
                            extra_info += f" | CVEs: {cve_list}"

                    else:
                        risk_level = "Unknown"
                
                    if use_port_heuristics and port in dangerous_ports:
                            if risk_level == "Low":
                                risk_level = "High"

                    # Save with risk level
                    insert_result(target, port, service, state, extra_info, "deep", risk_level)

        #PDF Report
        pdf_generator.generate_report(target)

    # error handling 
    except nmap.PortScannerError as e:
        print(f" Scan error: {e}")
