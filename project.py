import nmap 

# Initialize nmap scanner
scanner = nmap.PortScanner()

print("Welcome, This is a simple nmap automation tool")
print("<------------------------------------------------->")

# Prompt for IP address and scan type
ip_addr = input("Please enter the IP address you want to scan: ")
print("The IP you entered is: ", ip_addr)

resp = input("""\nPlease enter the type of scan you want to run
                1) SYN ACK Scan
                2) UDP Scan
                3) Comprehensive Scan \n""")
print("You have selected option: ", resp)

# Perform scan based on user input
if resp == '1':
    print("Nmap Version: ", scanner.nmap_version())
    scanner.scan(ip_addr, '1-1024', '-sS -v')
    print(scanner.scaninfo())
    print("IP Status: ", scanner[ip_addr].state())
    print("Protocols:", scanner[ip_addr].all_protocols())
    
    # Check if TCP key exists to avoid KeyError
    if 'tcp' in scanner[ip_addr]:
        print("Open TCP Ports: ", scanner[ip_addr]['tcp'].keys())
    else:
        print("No open TCP ports found or TCP scan failed.")

elif resp == '2':
    print("Nmap Version: ", scanner.nmap_version())
    scanner.scan(ip_addr, '1-1024', '-sU -v')  # Corrected scan options
    print(scanner.scaninfo())
    print("IP Status: ", scanner[ip_addr].state())
    print("Protocols:", scanner[ip_addr].all_protocols())
    
    # Check if UDP key exists to avoid KeyError
    if 'udp' in scanner[ip_addr]:
        open_ports = scanner[ip_addr]['udp'].keys()
        if open_ports:
            print("Open UDP Ports: ", open_ports)
        else:
            print("No open UDP ports detected.")
    else:
        print("No open UDP ports found or UDP scan may have been blocked by firewall or permissions.")

elif resp == '3':
    print("Nmap Version: ", scanner.nmap_version())
    scanner.scan(ip_addr, '1-1024', '-v -sS -sV -sC -A -O')
    print(scanner.scaninfo())
    print("IP Status: ", scanner[ip_addr].state())
    print("Protocols:", scanner[ip_addr].all_protocols())
    
    # Check if TCP key exists for comprehensive scan results
    if 'tcp' in scanner[ip_addr]:
        print("Open TCP Ports: ", scanner[ip_addr]['tcp'].keys())
    else:
        print("No open TCP ports found or TCP scan failed.")

else:
    print("Please enter a valid option (1, 2, or 3)")
