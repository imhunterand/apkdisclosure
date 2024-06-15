import os
import re
import json
import hashlib
import requests
from androguard.core.bytecodes.apk import APK

# ANSI escape code for green color
GREEN = '\033[92m'
RESET = '\033[0m'

ascii_art = f"""
{GREEN}
                 _    _____  _          _                          
     /\         | |  |  __ \(_)        | |                         
    /  \   _ __ | | _| |  | |_ ___  ___| | ___  ___ _   _ _ __ ___ 
   / /\ \ | '_ \| |/ / |  | | / __|/ __| |/ _ \/ __| | | | '__/ _ \
  / ____ \| |_) |   <| |__| | \__ \ (__| | (_) \__ \ |_| | | |  __/
 /_/    \_\ .__/|_|\_\_____/|_|___/\___|_|\___/|___/\__,_|_|  \___|
          | |                                                      
          |_|                                  
                                                
{RESET}
"""

def print_ascii_art():
    print(ascii_art)

def extract_strings_from_apk(apk_path):
    """
    Extract all strings from an APK file.
    """
    apk = APK(apk_path)
    strings = []
    for dex in apk.get_all_dex():
        for string in dex.get_strings():
            strings.append(string)
    return strings

def find_uris_endpoints_secrets(file_strings):
    """
    Find URIs, endpoints, and potential secrets in the extracted strings.
    """
    patterns = {
        "uris": re.compile(r'(https?://[^\s]+)'),
        "secrets": re.compile(r'(api_key|secret|password|token|user|pass)[^\s]*', re.IGNORECASE),
        "emails": re.compile(r'[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+'),
        "ip_addresses": re.compile(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'),
        "urls": re.compile(r'(https?://[^\s]+)')
    }

    found_items = {"uris": [], "secrets": [], "emails": [], "ip_addresses": [], "urls": []}

    for string in file_strings:
        for key, pattern in patterns.items():
            matches = pattern.findall(string)
            found_items[key].extend(matches)
    
    return found_items

def generate_hashes(apk_path):
    """
    Generate MD5, SHA-1, and SHA-256 hashes for the APK file.
    """
    hashes = {"md5": "", "sha1": "", "sha256": ""}
    with open(apk_path, 'rb') as f:
        data = f.read()
        hashes["md5"] = hashlib.md5(data).hexdigest()
        hashes["sha1"] = hashlib.sha1(data).hexdigest()
        hashes["sha256"] = hashlib.sha256(data).hexdigest()
    return hashes

def scan_apk(apk_path):
    """
    Scan the APK file for URIs, endpoints, and secrets.
    """
    print_ascii_art()
    print(f"Scanning APK: {apk_path}")
    file_strings = extract_strings_from_apk(apk_path)
    found_items = find_uris_endpoints_secrets(file_strings)
    hashes = generate_hashes(apk_path)
    
    print("\nFound URIs/Endpoints:")
    for uri in found_items["uris"]:
        print(uri)
    
    print("\nFound Secrets:")
    for secret in found_items["secrets"]:
        print(secret)
    
    print("\nFound Emails:")
    for email in found_items["emails"]:
        print(email)
    
    print("\nFound IP Addresses:")
    for ip_address in found_items["ip_addresses"]:
        print(ip_address)
    
    print("\nHashes:")
    for key, value in hashes.items():
        print(f"{key}: {value}")

    found_items["hashes"] = hashes

    return found_items

def save_results_to_json(results, output_path):
    """
    Save the scan results to a JSON file.
    """
    with open(output_path, 'w') as json_file:
        json.dump(results, json_file, indent=4)
    print(f"\nResults saved to {output_path}")

def check_vt_hashes(api_key, file_hash):
    """
    Check the file hashes against the VirusTotal database.
    """
    url = f"https://www.virustotal.com/vtapi/v2/file/report"
    params = {'apikey': api_key, 'resource': file_hash}
    response = requests.get(url, params=params)
    if response.status_code == 200:
        return response.json()
    else:
        return {"error": "Unable to retrieve report"}

def main():
    apk_path = input("Enter the path to the APK file: ")
    if os.path.exists(apk_path):
        results = scan_apk(apk_path)
        output_path = input("Enter the path to save the JSON results: ")
        save_results_to_json(results, output_path)
        
        vt_api_key = input("Enter your VirusTotal API key (optional, press enter to skip): ")
        if vt_api_key:
            for hash_type, file_hash in results["hashes"].items():
                print(f"\nChecking {hash_type.upper()} hash on VirusTotal...")
                vt_results = check_vt_hashes(vt_api_key, file_hash)
                print(json.dumps(vt_results, indent=4))
                results[f"virustotal_{hash_type}"] = vt_results
            save_results_to_json(results, output_path)
    else:
        print(f"File not found: {apk_path}")

if __name__ == "__main__":
    main()
