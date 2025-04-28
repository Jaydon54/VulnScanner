 # utils/utils.py
# Code for reusable utility functions goes here

# Util #2: port scanner print module
#vprints all the info of the scan results used in all the scanner funcitons
def print_results(scanner):
    for host in scanner.all_hosts():
        print(f"Host: {host} ({scanner[host].hostname()})") 
        print(f"State: {scanner[host].state()}") #whether the host is up or down
        
        for proto in scanner[host].all_protocols(): 
            print(f"Protocol: {proto}")
            ports = scanner[host][proto].keys()

            for port in sorted(ports):
                port_data = scanner[host][proto][port]
                state = port_data.get('state', 'unknown')
                service = port_data.get('name', 'unknown')
                product = port_data.get('product', '')
                version = port_data.get('version', '')
                extra_info = f"{product} {version}".strip()

                print(f"Port: {port}\tService: {service}", end='\n')
                if extra_info:
                    print(f"\tExtra Info: {extra_info}", end='')

    