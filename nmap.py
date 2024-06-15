import nmap

scanner = nmap.PortScanner()
print("Welcome,this is a simple nmap automation tool")
print("<--------------------------------------------------------->")
ip_addr =input("Please enter the Ip address you wanna scan:")
print("The Ip address you want to scan is "+ip_addr)
type(ip_addr)
resp=input("""\nPlease enter the type of scan you want to run
               1)SYN ACK SCAN
               2)UDP scan
               3)Comprehensive scan
               4)Tcp connect
               5)Tcp connect
               6)Tcp connect
               7)Tcp connect: \n""")

print("You have selected option "+resp)

if resp =='1':
    print("Nmap version ", scanner.nmap_version())
    scanner.scan(ip_addr, '1-8080', '-v -sS')
    print(scanner.scaninfo())
    print("Ip status: ", scanner[ip_addr].state())
    print(scanner[ip_addr].all_protocols())
    print("Open ports: ", scanner[ip_addr]['tcp'].keys())
elif resp =='2':
    print("Nmap version ", scanner.nmap_version())
    scanner.scan(ip_addr, '1-1024', '-v -sU')
    print(scanner.scaninfo())
    print("Ip status: ", scanner[ip_addr].state())
    print(scanner[ip_addr].all_protocols())
    print("Open ports: ", scanner[ip_addr]['udp'].keys())
elif resp == '3':
    print("Nmap version ", scanner.nmap_version())
    scanner.scan(ip_addr, '1-1024', '-v -sS -sV -sC -A -O')
    print(scanner.scaninfo())
    print("Ip status: ", scanner[ip_addr].state())
    print(scanner[ip_addr].all_protocols())
    print("Open ports: ", scanner[ip_addr]['tcp'].keys())
elif resp =='4':
    print("Nmap version ", scanner.nmap_version())
    scanner.scan(ip_addr, '1-6000', '-sT')
    print(scanner.scaninfo())
    print("Ip status: ", scanner[ip_addr].state())
    print(scanner[ip_addr].all_protocols())
    print("Open ports: ", scanner[ip_addr]['tcp'].keys())
elif resp =='5':
    print("Nmap version ", scanner.nmap_version())
    scanner.scan(ip_addr, '1-1024', '-sN')
    print(scanner.scaninfo())
    print("Ip status: ", scanner[ip_addr].state())
    print(scanner[ip_addr].all_protocols())
    print("Open ports: ", scanner[ip_addr]['tcp'].keys())
elif resp =='6':
    print("Nmap version ", scanner.nmap_version())
    scanner.scan(ip_addr, '1-1024', '-sF')
    print(scanner.scaninfo())
    print("Ip status: ", scanner[ip_addr].state())
    print(scanner[ip_addr].all_protocols())
    print("Open ports: ", scanner[ip_addr]['tcp'].keys())
elif resp=='7':
    print("Nmap version ", scanner.nmap_version())
    scanner.scan(ip_addr, '1-1024', '-sX')
    print(scanner.scaninfo())
    print("Ip status: ", scanner[ip_addr].state())
    print(scanner[ip_addr].all_protocols())
    print("Open ports: ", scanner[ip_addr]['tcp'].keys())
elif resp!='8':
    print("Please enter a valid option")
