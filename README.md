# URL Reputation and Categorization Tool

This project is a Python-based tool designed to analyze URLs for their reputation, categorize them by geographic regions, and assess their safety using multiple APIs, including VirusTotal, Google Safe Browsing, and AbuseIPDB. The tool is useful for cybersecurity professionals, researchers, and developers aiming to evaluate URLs for potential threats.

---

## **Features**

1. **Multi-Source URL Reputation Analysis**:
   - Uses VirusTotal to check the URL against known malicious databases.
   - Integrates Google Safe Browsing to identify threats like malware, phishing, and unwanted software.
   - Resolves the domain's IP address and checks its reputation via AbuseIPDB.

2. **Geographic Categorization**:
   - Categorizes URLs based on their top-level domains (TLDs) into regions (e.g., US, Vietnam, Japan).

3. **Error Handling and Logging**:
   - Provides detailed error messages for failed DNS resolutions and API calls.
   - Logs results and errors into a log file for debugging and analysis.

4. **Export Results**:
   - Outputs the results into a CSV file for further analysis.

5. **Secure Key Management**:
   - Uses environment variables or configuration files to manage API keys securely.
     
6. **Country Detection from IP**:
   - Resolves the country and continent for the URL's IP using the ip-api service.
     
7. **URL Path Analysis**:
   - Analyzes the URL path for suspicious keywords like login, secure, bank, etc.
  
8. **Bulk URL Processing**:
   - Processes multiple URLs from a text file and saves results to a CSV file.
9. **Error Resilience**:
   - Implements fallback DNS resolution and robust error handling to ensure continued execution.
10. **Comprehensive Reporting**:
   - Generates a summary report with:
      - Total URLs processed
      - Safe URLs
      - Flagged URLs
      - Inconclusive URLs

---

## **Technologies Used**

- **Python**
- **APIs**: VirusTotal, Google Safe Browsing, AbuseIPDB
- **Libraries**:
  - `requests`: For making HTTP requests.
  - `json`: For JSON handling.
  - `pandas`: For data manipulation and CSV export.
  - `socket`: For DNS resolution.
  - `re`: For regex-based domain validation.
  - `python-dotenv`: For managing environment variables.

---

## **Setup and Installation**

### **1. Clone the Repository**
```bash
git clone https://github.com/your-username/url-reputation-tool.git
cd url-reputation-tool
```

### **2. Install Dependencies**
Make sure you have Python installed (version 3.7 or later). Install required libraries:
```bash
pip install -r requirements.txt
```

### **3. Configure API Keys**
#### **Option 1: Environment Variables**
1. Create a `.env` file in the root directory:
   ```
   VIRUSTOTAL_API_KEY=your_virustotal_api_key
   GOOGLE_SAFEBROWSING_API_KEY=your_google_safebrowsing_api_key
   ABUSEIPDB_API_KEY=your_abuseipdb_api_key
   ```

#### **Option 2: Configuration File**
1. Create a `config.json` file in the root directory:
   ```json
   {
       "virustotal": "your_virustotal_api_key",
       "google_safebrowsing": "your_google_safebrowsing_api_key",
       "abuseipdb": "your_abuseipdb_api_key"
   }
   ```

---

## **Usage**

### **Run the Script**
To analyze URLs, run the script:
```bash
python URL_Reputation_Tool.py
```

### **Input**
The script analyzes a predefined list of URLs. Update the `sample_urls` list in the script to include your URLs:
```python
sample_urls = ['kooora.live-kooora.com', 'malicious-site.vn', 'safe-site.jp']
```

### **Output**
- **JSON**: Detailed results for each URL are printed in JSON format to the console.
- **CSV**: Consolidated results are exported to `url_reputation_results.csv`.
- **Logs**: Logs are saved to `url_reputation_log.txt`.
- **Summary Report**: A terminal-based summary is displayed after processing.

---

## **Code Overview**

### **Main Components**

1. **API Integration**
   - `check_url_virustotal(url)`: Queries VirusTotal for URL reputation.
   - `check_url_google_safebrowsing(url)`: Queries Google Safe Browsing for threats.
   - `check_url_abuseipdb(url)`: Resolves the domain's IP and queries AbuseIPDB for abuse reports.
2. **Utility Functions**
   - `is_valid_domain(url)`: Validates the domain format using regex.
   - `resolve_to_ip_with_multiple_services(url)`: Resolves a domain to its IP address using multiple public DNS services.
   - `log_to_file(message)`: Logs messages to a file for debugging and auditing.
3. **Region Categorization**
   - `categorize_by_region_and_continent(URL)`: Maps TLDs to regions (e.g., .com to US) and resolves multi-level TLDs.
4. **Path Analysis**
   - `analyze_url_path(url)`: Detects suspicious patterns in the URL path.
5. **Summary Reporting**
   - `generate_summary_report(results_list)`: Provides a terminal-based summary of the processed URLs.
6. **Main Function**
   - `check_url_reputation(url)`: Consolidates results from all services and determines overall status.
     
---

## **Output Structure**

### **JSON Output**
The script generates detailed JSON results for each URL, including:
```json
{
    "url": "kooora.live-kooora.com",
    "region": "Global",
    "country": "Global",
    "continent": "No specific continent",
    "virustotal": {
        "positives": 0,
        "total_scans": 96,
        "scan_date": "2025-01-22"
    },
    "google_safebrowsing": {
        "status": "No threats found"
    },
    "abuseipdb": {
        "ip": "185.16.39.38",
        "abuse_confidence_score": 0,
        "total_reports": 0
    },
    "url_path_analysis": "No suspicious patterns detected",
    "overall_status": "Safe"
}

```

### **CSV Output**
The CSV output contains consolidated results for all analyzed URLs, saved as `url_reputation_results.csv`.

---

## **License**
This project is licensed under the MIT License. 

---

## **Acknowledgments**
- VirusTotal for their API services.
- Google Safe Browsing for their threat detection API.
- AbuseIPDB for providing IP reputation data.
- ip-api for geolocation services.
