import requests
import json
import pandas as pd
import time
import socket
import re
from dotenv import load_dotenv
import os

# Load environment variables
load_dotenv()

API_KEYS = {
    'virustotal': os.getenv('VIRUSTOTAL_API_KEY'),
    'google_safebrowsing': os.getenv('GOOGLE_SAFEBROWSING_API_KEY'),
    'abuseipdb': os.getenv('ABUSEIPDB_API_KEY')
}

LOG_FILE = 'url_reputation_log.txt'

def log_to_file(message):
    with open(LOG_FILE, 'a') as log:
        log.write(f"{time.strftime('%Y-%m-%d %H:%M:%S')} - {message}\n")

def is_valid_domain(url):
    domain_regex = r'^(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}$'
    return re.match(domain_regex, url) is not None

def resolve_to_ip(url, retries=3):
    for attempt in range(retries):
        try:
            ip_address = socket.gethostbyname(url)
            return ip_address
        except socket.error:
            time.sleep(1)  # Retry delay time
    return None

def log_error(message, details):
    error_message = f"[ERROR] {message}: {details}"
    print(error_message)
    log_to_file(error_message)
    return {'error': message, 'details': details}

# Function to check URL reputation using Google Safe Browsing.

def check_url_google_safebrowsing(url):
    gsb_url = 'https://safebrowsing.googleapis.com/v4/threatMatches:find'
    headers = {'Content-Type': 'application/json'}
    payload = {
        'client': {
            'clientId': 'your_client_id',
            'clientVersion': '1.0'
        },
        'threatInfo': {
            'threatTypes': ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE"],
            'platformTypes': ["ANY_PLATFORM"],
            'threatEntryTypes': ["URL"],
            'threatEntries': [{"url": url}]
        }
    }
    params = {'key': API_KEYS['google_safebrowsing']}
    response = requests.post(gsb_url, headers=headers, params=params, data=json.dumps(payload))

    if response.status_code == 200:
        data = response.json()
        if 'matches' in data:
            return {
                'url': url,
                'threats': [match['threatType'] for match in data['matches']]
            }
        else:
            return {'url': url, 'status': 'No threats found'}
    else:
        try:
            error_details = response.json() 
        except ValueError:
            error_details = response.text  
        return log_error('Connection error', f"Status code: {response.status_code}, Response: {error_details}")

# Function to check URL reputation using VirusTotal.

def check_url_virustotal(url):
    vt_url = 'https://www.virustotal.com/vtapi/v2/url/report'
    params = {'apikey': API_KEYS['virustotal'], 'resource': url}
    response = requests.get(vt_url, params=params)

    if response.status_code == 200:
        data = response.json()
        if data['response_code'] == 1:
            result = {
                'url': url,
                'positives': data['positives'],
                'total_scans': data['total'],
                'scan_date': data['scan_date'],
                'categories': data.get('categories', 'N/A')
            }
            return result
        else:
            return {'url': url, 'status': 'Not found in VirusTotal'}
    else:
        return log_error('Connection error', f"Status code: {response.status_code}")

# Function to check URL reputation using AbuseIPDB.

def check_url_abuseipdb(url):
    ip = resolve_to_ip(url)
    if not ip:
        return log_error('Unable to resolve IP', f"URL: {url}")

    abuse_url = f'https://api.abuseipdb.com/api/v2/check'
    headers = {
        'Key': API_KEYS['abuseipdb'],
        'Accept': 'application/json'
    }
    params = {'ipAddress': ip, 'maxAgeInDays': 90}
    response = requests.get(abuse_url, headers=headers, params=params)

    if response.status_code == 200:
        data = response.json()
        return {
            'ip': ip,
            'abuse_confidence_score': data['data'].get('abuseConfidenceScore', 'N/A'),
            'total_reports': data['data'].get('totalReports', 0),
            'last_reported_at': data['data'].get('lastReportedAt', 'N/A')
        }
    else:
        return log_error('Connection error', f"Status code: {response.status_code}")

# Results combined and categorized by regions (US, Vietnam, Japan).

REGION_RULES = {
    'US': ['.com', '.us'],
    'Vietnam': ['.vn'],
    'Japan': ['.jp']
}

def categorize_by_region(url):
    for region, tlds in REGION_RULES.items():
        if any(url.endswith(tld) for tld in tlds):
            return region
    return 'Other'

# Main function to run all checks and consolidate results.

def check_url_reputation(url):
    if not is_valid_domain(url):
        return log_error('Invalid domain', f"The domain '{url}' is not valid.")

    region = categorize_by_region(url)
    vt_result = check_url_virustotal(url)
    gsb_result = check_url_google_safebrowsing(url)
    abuseip_result = check_url_abuseipdb(url)

    consolidated_result = {
        'url': url,
        'region': region,
        'virustotal': vt_result,
        'google_safebrowsing': gsb_result,
        'abuseipdb': abuseip_result
    }

    issues = []

    # Determine overall status
    if vt_result.get('positives', 0) > 0:
        issues.append('VirusTotal flagged the URL as malicious.')
    if 'threats' in gsb_result:
        issues.append(f"Google Safe Browsing detected threats: {', '.join(gsb_result['threats'])}")
    if abuseip_result.get('abuse_confidence_score', 0) > 50:
        issues.append('AbuseIPDB flagged the IP with a high abuse score.')
    if 'error' in abuseip_result and 'Unable to resolve IP' in abuseip_result['details']:
        issues.append('Domain could not be resolved to an IP.')

    if issues:
        consolidated_result['overall_status'] = 'Flagged'
        consolidated_result['issues'] = issues
    elif vt_result.get('error') or gsb_result.get('error') or abuseip_result.get('error'):
        consolidated_result['overall_status'] = 'Inconclusive'
    else:
        consolidated_result['overall_status'] = 'Safe'

    log_to_file(json.dumps(consolidated_result, indent=4))
    return consolidated_result

# Example usage.
if __name__ == '__main__':
    sample_urls = ['kooora.live-kooora.com', 'malicious-site.vn', 'safe-site.jp']
    results_list = []

    for url in sample_urls:
        result = check_url_reputation(url)
        print(json.dumps(result, indent=4))
        results_list.append(result)

    # Save results to a CSV file.
    df = pd.DataFrame(results_list)
    df.to_csv('url_reputation_results.csv', index=False)
