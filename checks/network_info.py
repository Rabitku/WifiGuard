import socket
import psutil

def get_network_info():
 hostname = socket.gethostname()
 interfaces = psutil.net_if_addrs()
 
 active_interfaces = []
 
 for interface_name, addresses in interfaces.items():
  for address in addresses:
     if address.family == socket.AF_INET:
         ip_address = address.address
         
         if ip_address.startswith("127. "):
             
             continue
         if interface_name.startswith("lo"):
                continue
            
         active_interfaces.append({
                 "interface": interface_name,
                 "ip_address": ip_address
             })

 return {
    "hostname": hostname,
    "active_interfaces": active_interfaces
}
