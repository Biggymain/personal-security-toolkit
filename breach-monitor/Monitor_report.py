#!/usr/bin/env python3
import os
import subprocess
import json
import requests
from dotenv import load_dotenv

load_dotenv()

# Load Telegram and NumberVerify credentials
TELEGRAM_BOT_TOKEN = os.getenv("TELEGRAM_BOT_TOKEN")
TELEGRAM_CHAT_ID = os.getenv("TELEGRAM_CHAT_ID")
NUMBERVERIFY_API_KEY = os.getenv("NUMBERVERIFY_API_KEY")

if not TELEGRAM_BOT_TOKEN or not TELEGRAM_CHAT_ID:
    raise RuntimeError("Missing TELEGRAM_BOT_TOKEN or TELEGRAM_CHAT_ID in .env")
if not NUMBERVERIFY_API_KEY:
    raise RuntimeError("Missing NUMBERVERIFY_API_KEY in .env")


def send_telegram_message(message: str):
    url = f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendMessage"
    payload = {"chat_id": TELEGRAM_CHAT_ID, "text": message}
    response = requests.post(url, data=payload)
    if not response.ok:
        print(f"[!] Failed to send Telegram message: {response.text}")


def run_phoneinfoga(number: str) -> dict:
    """
    Run PhoneInfoga v3 Docker container for a number.
    Parses the output manually as JSON is not directly supported.
    """
    cmd = [
        "docker", "run", "--rm",
        "sundowndev/phoneinfoga:latest", "scan",
        "--number", number
    ]
    result = subprocess.run(cmd, capture_output=True, text=True)
    if result.returncode != 0:
        print(f"[!] PhoneInfoga failed for {number}: {result.stderr}")
        return {}
    
    data = {"number": number, "raw_output": result.stdout}
    
    # Extract websites if any lines start with "https://"
    lines = result.stdout.splitlines()
    websites = [line.strip() for line in lines if line.startswith("http")]
    data["websites"] = websites
    return data


def run_numberverify(number: str) -> dict:
    """
    Query NumberVerify API for additional info.
    """
    url = f"http://apilayer.net/api/validate?access_key={NUMBERVERIFY_API_KEY}&number={number}"
    try:
        resp = requests.get(url, timeout=10)
        resp.raise_for_status()
        info = resp.json()
        return {
            "valid": info.get("valid", False),
            "country_name": info.get("country_name", ""),
            "location": info.get("location", ""),
            "carrier": info.get("carrier", ""),
            "line_type": info.get("line_type", "")
        }
    except Exception as e:
        print(f"[!] NumberVerify failed for {number}: {e}")
        return {}


def main():
    numbers_input = input("Enter phone numbers separated by commas (e.g. +15551234567,+15557654321): ")
    numbers = [n.strip() for n in numbers_input.split(",") if n.strip()]
    
    for number in numbers:
        print(f"[+] Running multi-tool scan for {number}...")
        nf_data = run_numberverify(number)
        pf_data = run_phoneinfoga(number)
        
        report = f"📱 Phone Report for {number}:\n"
        if nf_data:
            report += f"- Valid: {nf_data.get('valid')}\n"
            report += f"- Country: {nf_data.get('country_name')}\n"
            report += f"- Location/State: {nf_data.get('location')}\n"
            report += f"- Carrier: {nf_data.get('carrier')}\n"
            report += f"- Line Type: {nf_data.get('line_type')}\n"
        if pf_data.get("websites"):
            report += "\n🌐 Websites mentioning this number:\n"
            for site in pf_data["websites"]:
                report += f"{site}\n"
        else:
            report += "\n🌐 No external domains found.\n"
        
        print(report)
        send_telegram_message(report)


if __name__ == "__main__":
    main()
