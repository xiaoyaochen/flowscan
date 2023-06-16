import ipaddress


ip_list = set()
with open("1.txt") as rp:
    for i in rp.readlines():
        start_ip, end_ip = i.strip().split("-")
        start_int = int(ipaddress.IPv4Address(start_ip))
        end_int = int(ipaddress.IPv4Address(end_ip))
        for i in range(start_int, end_int + 1):
            ip_list.add(str(ipaddress.IPv4Address(i)))

with open("2.txt","w") as wp:
    for i in ip_list:
        wp.write(i+"\n")