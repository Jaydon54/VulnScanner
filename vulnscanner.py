#!/usr/bin/env python3
"""
Enhanced Vulnerability Scanner CLI - Finalized Version
"""

import cmd
import os
import sys
from colorama import Fore, Style, init
from scanner.scanner import quick_scan, regular_scan, deep_scan
from database.database import init_db, get_results_by_target, get_results_by_date, insert_result
from utils.utils import print_results as utils_print_results
import nmap

# Initialize colorama
init(autoreset=True)

def show_banner():
    """Display VulnScanner banner"""
    print(Fore.MAGENTA + r"""
     __      __    _        _____                                 
     \ \    / /   | |      / ____|                                
      \ \  / /   _| |_ __ | (___   ___ __ _ _ __  _ __   ___ _ __ 
       \ \/ / | | | | '_ \ \___ \ / __/ _` | '_ \| '_ \ / _ \ '__|
        \  /| |_| | | | | |____) | (_| (_| | | | | | | |  __/ |   
         \/  \__,_|_|_| |_|_____/ \___\__,_|_| |_|_| |_|\___|_|   
                                                                 
    """ + Style.RESET_ALL)

    print(Fore.CYAN + "    " + "=" * 60)
    print(Fore.YELLOW + "    | " + Fore.MAGENTA + "Vulnerability Scanner v1.0" + Fore.YELLOW + " " * 31 + "|")
    print(Fore.YELLOW + "    | " + Fore.WHITE + "Type " + Fore.GREEN + "help" + Fore.WHITE + " for commands" + Fore.YELLOW + " " * 38 + "|")
    print(Fore.YELLOW + "    | " + Fore.WHITE + "Type " + Fore.RED + "exit" + Fore.WHITE + " to quit" + Fore.YELLOW + " " * 42 + "|")
    print(Fore.CYAN + "    " + "=" * 60 + Style.RESET_ALL)
    print("\n")

class VulnScannerCLI(cmd.Cmd):
    prompt = Fore.MAGENTA + 'vulnscanner > ' + Style.RESET_ALL

    def __init__(self):
        super().__init__()
        init_db()
        self.current_target = None
        self.last_scanner = None
        os.system('cls' if os.name == 'nt' else 'clear')
        show_banner()
        self.show_quick_menu()

    def show_quick_menu(self):
        """Display the quick reference menu"""
        print(Fore.YELLOW + "\n[+] " + Fore.MAGENTA + "Main Menu" + Fore.YELLOW + " [+]")
        print(Fore.CYAN + "-" * 60)
        print(Fore.WHITE + "  " + u"\u2022" + " Scan Commands:")
        print(Fore.GREEN + "    scan quick <target>" + Fore.WHITE + "    - Quick scan (common ports)")
        print(Fore.GREEN + "    scan regular <target>" + Fore.WHITE + "  - Custom port scan")
        print(Fore.GREEN + "    scan deep <target>" + Fore.WHITE + "     - Full port scan (1-65535)")
        print(Fore.CYAN + "-" * 60)
        print(Fore.WHITE + "  " + u"\u2022" + " Target Management:")
        print(Fore.GREEN + "    set target <IP>" + Fore.WHITE + "       - Set current target")
        print(Fore.GREEN + "    show target" + Fore.WHITE + "          - Show current target")
        print(Fore.CYAN + "-" * 60)
        print(Fore.WHITE + "  " + u"\u2022" + " Results & Reports:")
        print(Fore.GREEN + "    results" + Fore.WHITE + "             - Show last scan results")
        print(Fore.GREEN + "    results date <start> <end>" + Fore.WHITE + " - Filter by date")
        print(Fore.CYAN + "-" * 60)
        print(Fore.WHITE + "  " + u"\u2022" + " System Commands:")
        print(Fore.GREEN + "    clear" + Fore.WHITE + "               - Clear screen")
        print(Fore.GREEN + "    help" + Fore.WHITE + "                - Show detailed help")
        print(Fore.GREEN + "    exit" + Fore.WHITE + "                - Exit VulnScanner")
        print(Fore.CYAN + "-" * 60 + Style.RESET_ALL)
        print("\n")

    def print_success(self, message):
        print(Fore.GREEN + "[✓] " + message)

    def print_error(self, message):
        print(Fore.RED + "[✗] ERROR: " + message)

    def print_warning(self, message):
        print(Fore.YELLOW + "[!] " + message)

    def print_info(self, message):
        print(Fore.CYAN + "[i] " + message)

    def do_scan(self, arg):
        """Perform a vulnerability scan"""
        if not arg:
            self.print_error("Missing scan type and target")
            return
        
        args = arg.split()
        if len(args) < 2:
            self.print_error("Usage: scan <quick|regular|deep> <target>")
            return
        
        scan_type, target = args[0], args[1]
        self.current_target = target
        scanner = nmap.PortScanner()
        
        try:
            if scan_type == "quick":
                scanner.scan(hosts=target, ports='21,22,80,443', arguments='-T4 -Pn')
            elif scan_type == "regular":
                ports = input(Fore.YELLOW + "Enter ports to scan (e.g., 22,80 or 1-1000): " + Style.RESET_ALL)
                scanner.scan(hosts=target, ports=ports, arguments='-sS -T4 -Pn')
            elif scan_type == "deep":
                scanner.scan(hosts=target, ports='1-65535', arguments='-sS -sV -T4 -Pn')
            else:
                self.print_error("Invalid scan type. Choose quick/regular/deep.")
                return
            
            # Display Results
            utils_print_results(scanner)
            self.print_success(f"{scan_type.capitalize()} scan completed!")

            # Save to database
            for host in scanner.all_hosts():
                for proto in scanner[host].all_protocols():
                    ports = scanner[host][proto].keys()
                    for port in sorted(ports):
                        port_data = scanner[host][proto][port]
                        service = port_data.get('name', 'unknown')
                        state = port_data.get('state', 'unknown')
                        product = port_data.get('product', '')
                        version = port_data.get('version', '')
                        extra_info = f"{product} {version}".strip()
                        insert_result(target, port, service, state, extra_info, scan_type)
            
            self.last_scanner = scanner

        except nmap.PortScannerError as e:
            self.print_error(f"Scan error: {e}")
        except Exception as e:
            self.print_error(f"Unexpected error: {str(e)}")

    def do_set(self, arg):
        """Set the current target"""
        args = arg.split()
        if len(args) == 2 and args[0] == "target":
            self.current_target = args[1]
            self.print_success(f"Target set to {self.current_target}")
        else:
            self.print_error("Usage: set target <IP>")

    def do_show(self, arg):
        """Show current target"""
        if arg.strip() == "target":
            if self.current_target:
                self.print_info(f"Current target: {self.current_target}")
            else:
                self.print_warning("No target is set")
        else:
            self.print_error("Usage: show target")

    def do_results(self, arg):
        """View scan results"""
        args = arg.split()
        if not args and self.current_target:
            results = get_results_by_target(self.current_target)
            self._display_results(results)
        elif args and args[0] == "date":
            if len(args) != 3:
                self.print_error("Usage: results date <start_date> <end_date>")
                return
            start, end = args[1], args[2]
            results = get_results_by_date(start, end)
            self._display_results(results)
        else:
            if args:
                results = get_results_by_target(args[0])
                self._display_results(results)
            else:
                self.print_error("No target specified")

    def _display_results(self, results):
        if not results:
            self.print_warning("No results found.")
            return
        
        print(Fore.YELLOW + "\nScan Results:")
        print(Fore.CYAN + "-" * 80)
        for result in results:
            print(Fore.WHITE + f"Target: {Fore.MAGENTA}{result[1]}")
            print(f"Port: {Fore.GREEN}{result[2]}  Service: {Fore.CYAN}{result[3]}")
            print(f"State: {Fore.GREEN if result[4] == 'open' else Fore.RED}{result[4]}")
            print(f"Scan Type: {Fore.YELLOW}{result[6]}")
            print(f"Timestamp: {Fore.CYAN}{result[7]}")
            print(Fore.CYAN + "-" * 80)

    def do_clear(self, arg):
        """Clear the screen"""
        os.system('cls' if os.name == 'nt' else 'clear')
        show_banner()
        self.show_quick_menu()

    def do_exit(self, arg):
        """Exit VulnScanner"""
        print(Fore.MAGENTA + "\nThank you for using VulnScanner!" + Style.RESET_ALL)
        return True

    def emptyline(self):
        """Handle empty input"""
        return False

    def default(self, line):
        """Handle unknown commands"""
        self.print_error(f"Unknown command: {line}")
        self.print_info("Type 'help' for a list of available commands.")

if __name__ == '__main__':
    try:
        VulnScannerCLI().cmdloop()
    except KeyboardInterrupt:
        print(Fore.RED + "\n\nKeyboard Interrupt detected. Exiting..." + Style.RESET_ALL)
        sys.exit(0)
