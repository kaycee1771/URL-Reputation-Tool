import requests
import json
import pandas as pd
import time
import socket
import re
from dotenv import load_dotenv
import os
import whois

# Load environment variables
load_dotenv()

API_KEYS = {
    'virustotal': os.getenv('VIRUSTOTAL_API_KEY'),
    'google_safebrowsing': os.getenv('GOOGLE_SAFEBROWSING_API_KEY'),
    'abuseipdb': os.getenv('ABUSEIPDB_API_KEY'), 
    'securitytrails': os.getenv('SECURITYTRAILS_API_KEY')
}

LOG_FILE = 'url_reputation_log.txt'
INCONCLUSIVE_FILE = 'inconclusive_urls.txt'
GOOGLE_DNS_API = 'https://dns.google/resolve'

DNS_SERVICES = [
    'https://dns.google/resolve',
    'https://1.1.1.1/dns-query',  
    'https://doh.opendns.com/dns-query' 
]

# Comprehensive Country-to-Continent Mapping
TLD_TO_CONTINENT = {
    'us': ('United States', 'North America'),
    'uk': ('United Kingdom', 'Europe'),
    'de': ('Germany', 'Europe'),
    'fr': ('France', 'Europe'),
    'cn': ('China', 'Asia'),
    'jp': ('Japan', 'Asia'),
    'in': ('India', 'Asia'),
    'za': ('South Africa', 'Africa'),
    'ng': ('Nigeria', 'Africa'),
    'br': ('Brazil', 'South America'),
    'ar': ('Argentina', 'South America'),
    'au': ('Australia', 'Oceania'),
    'ca': ('Canada', 'North America'),
    'ru': ('Russia', 'Europe'),
    'it': ('Italy', 'Europe'),
    'es': ('Spain', 'Europe'),
    'mx': ('Mexico', 'North America'),
    'kr': ('South Korea', 'Asia'),
    'sa': ('Saudi Arabia', 'Asia'),
    'se': ('Sweden', 'Europe'),
    'ch': ('Switzerland', 'Europe'),
    'ae': ('United Arab Emirates', 'Asia'),
    'sg': ('Singapore', 'Asia'),
    'nz': ('New Zealand', 'Oceania'),
    'ke': ('Kenya', 'Africa'),
    'gh': ('Ghana', 'Africa'),
    'cl': ('Chile', 'South America'),
    'co': ('Colombia', 'South America'),
    've': ('Venezuela', 'South America'),
    'eg': ('Egypt', 'Africa'),
    'il': ('Israel', 'Asia'),
    'pk': ('Pakistan', 'Asia'),
    'bd': ('Bangladesh', 'Asia'),
    'vn': ('Vietnam', 'Asia')
}

GENERIC_TLDS = ['com', 'net', 'org', 'edu', 'gov', 'info', 'io']

def log_to_file(message):
    with open(LOG_FILE, 'a') as log:
        log.write(f"{time.strftime('%Y-%m-%d %H:%M:%S')} - {message}\n")

# Save inconclusive URLs
def save_inconclusive_url(url):
    with open(INCONCLUSIVE_FILE, 'a') as file:
        file.write(f"{url}\n")

def is_valid_domain(url):
    domain_regex = r'^(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}$'
    return re.match(domain_regex, url) is not None

def resolve_to_ip_with_multiple_services(url):
    for dns_service in DNS_SERVICES:
        try:
            response = requests.get(dns_service, params={'name': url, 'type': 'A'}, timeout=5)
            if response.status_code == 200:
                data = response.json()
                if 'Answer' in data:
                    return data['Answer'][0]['data']
        except requests.RequestException:
            continue
    return None

def resolve_to_ip(url, retries=3):
    for attempt in range(retries):
        try:
            ip_address = socket.gethostbyname(url)
            return ip_address
        except socket.error:
            time.sleep(1)  # Retry delay time
    return None

def resolve_to_ip_with_fallback(url):
    ip = resolve_to_ip(url)
    if ip:
        return ip
    try:
        response = requests.get(GOOGLE_DNS_API, params={'name': url, 'type': 'A'})
        if response.status_code == 200:
            data = response.json()
            if 'Answer' in data:
                return data['Answer'][0]['data']
    except requests.RequestException as e:
        log_error('Fallback DNS resolution failed', str(e))
    return None

def log_error(message, details):
    error_message = f"[ERROR] {message}: {details}"
    print(error_message)
    log_to_file(error_message)
    return {'error': message, 'details': details}

# Function to categorize by region and continent
def categorize_by_region_and_continent(url):
    match = re.search(r'\.([a-z]{2,}|[a-z]{2}\.[a-z]{2})$', url)
    if not match:
        return 'Unknown', 'Unknown', 'Unknown'

    tld = match.group(1).lower()

    
    if '.' in tld:
        primary_tld = tld.split('.')[-1]
    else:
        primary_tld = tld

    
    if primary_tld in GENERIC_TLDS:
        return 'Global', 'Global', 'No specific continent'


    if primary_tld in TLD_TO_CONTINENT:
        country, continent = TLD_TO_CONTINENT[primary_tld]
        return primary_tld.upper(), country, continent

    return 'Unknown', 'Unknown', 'Unknown'

# Detect country and continent from IP address
def get_country_from_ip(ip):
    api_url = f"http://ip-api.com/json/{ip}"
    try:
        response = requests.get(api_url)
        if response.status_code == 200:
            data = response.json()
            return data.get('country', 'Unknown'), data.get('continent', 'Unknown')
    except requests.RequestException:
        return 'Unknown', 'Unknown'

# URL path analysis
def analyze_url_path(url):
    suspicious_keywords = ['login', 'secure', 'bank', 'update', 'verify']
    url_path = re.search(r'https?://[^/]+(/.*)', url)
    if url_path:
        path = url_path.group(1).lower()
        for keyword in suspicious_keywords:
            if keyword in path:
                return f"Suspicious keyword detected: {keyword}"
    return "No suspicious patterns detected"

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
    ip = resolve_to_ip_with_multiple_services(url)
    if not ip:
        save_inconclusive_url(url)
        return log_error('Unable to resolve IP', f"URL: {url}")

    abuse_url = 'https://api.abuseipdb.com/api/v2/check'
    headers = {'Key': API_KEYS['abuseipdb'], 'Accept': 'application/json'}
    params = {'ipAddress': ip, 'maxAgeInDays': 90}
    response = requests.get(abuse_url, headers=headers, params=params)

    if response.status_code == 200:
        data = response.json()
        # Safely get country and continent using the get_country_from_ip function
        country, continent = get_country_from_ip(ip) if ip else ('Unknown', 'Unknown')
        return {
            'ip': ip,
            'country': country,
            'continent': continent,
            'abuse_confidence_score': data['data'].get('abuseConfidenceScore', 'N/A'),
            'total_reports': data['data'].get('totalReports', 0),
            'last_reported_at': data['data'].get('lastReportedAt', 'N/A')
        }
    else:
        return log_error('Connection error', f"Status code: {response.status_code}")

# Main function to run all checks and consolidate results.
def check_url_reputation(url):
    if not is_valid_domain(url):
        return log_error('Invalid domain', f"The domain '{url}' is not valid.")

    tld, country, continent = categorize_by_region_and_continent(url)
    vt_result = check_url_virustotal(url)
    gsb_result = check_url_google_safebrowsing(url)
    abuseip_result = check_url_abuseipdb(url)
    url_path_analysis = analyze_url_path(url)

    consolidated_result = {
        'url': url,
        'tld': tld,
        'country': country,
        'continent': continent,
        'virustotal': vt_result,
        'google_safebrowsing': gsb_result,
        'abuseipdb': abuseip_result,
        'url_path_analysis': url_path_analysis
    }

    issues = []
    if vt_result.get('positives', 0) > 0:
        issues.append('VirusTotal flagged the URL as malicious.')
    if 'threats' in gsb_result:
        issues.append(f"Google Safe Browsing detected threats: {', '.join(gsb_result['threats'])}")
    if abuseip_result.get('abuse_confidence_score', 0) > 50:
        issues.append('AbuseIPDB flagged the IP with a high abuse score.')

    if issues:
        consolidated_result['overall_status'] = 'Flagged'
        consolidated_result['issues'] = issues
    elif vt_result.get('error') or gsb_result.get('error') or abuseip_result.get('error'):
        consolidated_result['overall_status'] = 'Inconclusive'
    else:
        consolidated_result['overall_status'] = 'Safe'

    log_to_file(json.dumps(consolidated_result, indent=4))
    return consolidated_result

def process_urls_from_file(file_path):
    try:
        with open(file_path, 'r') as f:
            urls = [line.strip() for line in f.readlines()]

        results_list = []
        for url in urls:
            result = check_url_reputation(url)
            results_list.append(result)

        df = pd.DataFrame(results_list)
        df.to_csv('url_reputation_results.csv', index=False)
        print(f"Results saved to 'url_reputation_results.csv'.")
        generate_summary_report(results_list)
    except FileNotFoundError:
        print(f"Error: File '{file_path}' not found.")

def generate_summary_report(results_list):
    safe_count = sum(1 for result in results_list if result['overall_status'] == 'Safe')
    flagged_count = sum(1 for result in results_list if result['overall_status'] == 'Flagged')
    inconclusive_count = len(results_list) - safe_count - flagged_count

    print("\nSummary Report:")
    print(f"Total URLs Processed: {len(results_list)}")
    print(f"Safe URLs: {safe_count}")
    print(f"Flagged URLs: {flagged_count}")
    print(f"Inconclusive URLs: {inconclusive_count}")

# Example usage.
if __name__ == '__main__':
    sample_urls = ['kooora.live-kooora.com', 'malicious-site.vn', 'safe-site.jp', 'bbc.co.uk', 'gov.za', 'google.de']
    results_list = []

    for url in sample_urls:
        result = check_url_reputation(url)
        print(json.dumps(result, indent=4))
        results_list.append(result)

    # Save results to a CSV file.
    df = pd.DataFrame(results_list)
    df.to_csv('url_reputation_results.csv', index=False)
