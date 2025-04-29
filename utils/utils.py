# utils/utils.py
def print_results(scanner):
    for host in scanner.all_hosts():
        print(f"Host: {host} ({scanner[host].hostname()})")
        print(f"State: {scanner[host].state()}")

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

                print(f"Port: {port}\tService: {service}")
                if extra_info:
                    print(f"\tExtra Info: {extra_info}")
