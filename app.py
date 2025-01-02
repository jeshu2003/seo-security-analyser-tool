from flask import Flask, request, jsonify, render_template
import requests
from bs4 import BeautifulSoup
from urllib.parse import urlparse
import ssl
import socket
from datetime import datetime
import pandas as pd
import os
import subprocess
import re

app = Flask(__name__)

# Path to CSV for storing data
CSV_FILE = 'seo_security_data.csv'

# -------------------- Utility Functions -------------------- #

def fetch_page(url):
    try:
        response = requests.get(url, headers={'User-Agent': 'Mozilla/5.0'}, timeout=10)
        response.raise_for_status()
        return response.text, response.elapsed.total_seconds() * 1000, response.status_code
    except requests.exceptions.RequestException as e:
        print(f"Error fetching {url}: {e}")
        return None, None, None

def extract_seo_elements(html_content):
    soup = BeautifulSoup(html_content, 'html.parser')
    title = soup.title.string.strip() if soup.title else 'No Title'
    meta_desc = soup.find('meta', attrs={'name': 'description'})
    meta_description = meta_desc['content'].strip() if meta_desc else 'No Meta Description'
    return {'title': title, 'meta_description': meta_description}

def get_ssl_info(host, port=443):
    context = ssl.create_default_context()
    try:
        with socket.create_connection((host, port), timeout=10) as sock:
            with context.wrap_socket(sock, server_hostname=host) as ssock:
                cert = ssock.getpeercert()
                ssl_version = ssock.version()
                cipher = ssock.cipher()

        not_after = datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z')
        days_until_expiry = (not_after - datetime.utcnow()).days

        return {
            'SSL Version': ssl_version,
            'Cipher': cipher,
            'Expires On': not_after.strftime('%Y-%m-%d'),
            'Days Until Expiry': days_until_expiry
        }
    except Exception as e:
        print(f"Error retrieving SSL info for {host}: {e}")
        return None

def test_sql_injection(url):
    payloads = ["' OR '1'='1", "' OR 1=1--", "' OR 'a'='a"]
    results = []

    for payload in payloads:
        test_url = f"{url}?id={payload}"
        try:
            response = requests.get(test_url, headers={'User-Agent': 'Mozilla/5.0'}, timeout=10)
            if response.status_code == 200 and "error" not in response.text.lower():
                results.append({"payload": payload, "vulnerable": True})
            else:
                results.append({"payload": payload, "vulnerable": False})
        except requests.exceptions.RequestException as e:
            print(f"Error testing SQL injection: {e}")
            results.append({"payload": payload, "vulnerable": False})

    return results

def test_xss(url):
    payloads = ["<script>alert('XSS')</script>", "<img src=x onerror=alert('XSS')>"]
    results = []

    for payload in payloads:
        test_url = f"{url}?search={payload}"
        try:
            response = requests.get(test_url, headers={'User-Agent': 'Mozilla/5.0'}, timeout=10)
            if payload in response.text:
                results.append({"payload": payload, "vulnerable": True})
            else:
                results.append({"payload": payload, "vulnerable": False})
        except requests.exceptions.RequestException as e:
            print(f"Error testing XSS: {e}")
            results.append({"payload": payload, "vulnerable": False})

    return results

def check_open_ports(url):
    """Checks if common ports (80, 443, etc.) are open on the target server."""
    open_ports = []
    common_ports = [80, 443, 8080]
    for port in common_ports:
        try:
            sock = socket.create_connection((url, port), timeout=3)
            open_ports.append(port)
            sock.close()
        except socket.error:
            continue
    return open_ports

def identify_directory_traversal(url):
    payloads = ["../../../../etc/passwd", "../../../../windows/system32/config/system"]
    results = []

    for payload in payloads:
        test_url = f"{url}?file={payload}"
        try:
            response = requests.get(test_url, headers={'User-Agent': 'Mozilla/5.0'}, timeout=10)
            if response.status_code == 200 and "error" not in response.text.lower():
                results.append({"payload": payload, "vulnerable": True})
            else:
                results.append({"payload": payload, "vulnerable": False})
        except requests.exceptions.RequestException as e:
            print(f"Error testing directory traversal: {e}")
            results.append({"payload": payload, "vulnerable": False})

    return results

def analyze_server_logs(log_file_path):
    """Basic analysis of web server logs for possible attack indicators."""
    if not os.path.exists(log_file_path):
        print(f"Log file not found at {log_file_path}")
        return {}

    attack_patterns = {
        "SQL Injection": r"(?i)\b(select|insert|drop|union|--)\b",  # Common SQL keywords
        "XSS": r"(?i)<script.*?>.*?</script>|<img.*?onerror=.*?>",  # Simple XSS patterns
        "Directory Traversal": r"\.\./|\.\.\\",  # Directory traversal attempts
        "Command Injection": r"(?i)\b(?:;|&&|\|\|)\b"  # Common command injection patterns
    }

    with open(log_file_path, 'r') as file:
        logs = file.readlines()

    detected_attacks = {attack: [] for attack in attack_patterns}

    for log_entry in logs:
        for attack, pattern in attack_patterns.items():
            if re.search(pattern, log_entry):
                detected_attacks[attack].append(log_entry.strip())

    return detected_attacks

# -------------------- Data Management -------------------- #

def save_to_csv(data):
    """Saves the result to CSV and ensures that it is properly formatted."""
    if os.path.exists(CSV_FILE):
        df = pd.read_csv(CSV_FILE)
        new_data = pd.DataFrame([data])  # Convert the data to a DataFrame
        df = pd.concat([df, new_data], ignore_index=True)  # Concatenate the new data
    else:
        df = pd.DataFrame([data])
    df.to_csv(CSV_FILE, index=False)

def load_csv():
    """Loads the data from CSV."""
    if os.path.exists(CSV_FILE):
        return pd.read_csv(CSV_FILE)
    else:
        return pd.DataFrame()

# -------------------- API Endpoint -------------------- #

@app.route('/analyze', methods=['POST'])
def analyze():
    data = request.get_json()
    url = data.get('url')

    if not url:
        return jsonify({"status": "error", "message": "URL is required."}), 400

    result = {"url": url}

    # Fetch page content
    html_content, response_time, status_code = fetch_page(url)
    if not html_content:
        return jsonify({"status": "error", "message": "Failed to fetch the URL."}), 500

    # Extract SEO elements
    seo_elements = extract_seo_elements(html_content)
    result.update(seo_elements)

    # Get SSL information
    parsed_url = urlparse(url)
    host = parsed_url.netloc
    ssl_info = get_ssl_info(host)
    result['ssl_info'] = ssl_info

    # Vulnerability testing
    sql_injection_results = test_sql_injection(url)
    xss_results = test_xss(url)
    directory_traversal_results = identify_directory_traversal(url)
    open_ports = check_open_ports(host)
    vulnerabilities = {
        "sql_injection": sql_injection_results,
        "xss": xss_results,
        "directory_traversal": directory_traversal_results,
        "open_ports": open_ports
    }
    result['vulnerabilities'] = vulnerabilities

    # Log analysis
    log_file_path = 'path/to/your/logs/access.log'  # Replace with your actual log file path
    log_analysis = analyze_server_logs(log_file_path)
    result['log_analysis'] = log_analysis

    # Add timestamp to the result
    result['analysis_date'] = datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')

    # Save the result to CSV file
    save_to_csv(result)

    return jsonify({"status": "success", "data": result}), 200

@app.route('/', methods=['GET'])
def home():
    return render_template('index.html')

@app.route('/data', methods=['GET'])
def get_data():
    """Fetches all the stored data from the CSV file."""
    data = load_csv()
    return jsonify(data.to_dict(orient='records'))

# -------------------- Run the Flask App -------------------- #

if __name__ == '__main__':
    app.run(debug=True)
