# SEO & Security Analyzer

This web application is designed to perform a comprehensive analysis of a given URL for SEO elements and potential security vulnerabilities. The application offers several features, including SEO element extraction, SSL certificate inspection, vulnerability testing (SQL Injection, XSS, Directory Traversal), and analysis of open ports and server logs.

## Features

- **SEO Analysis**:
  - Extracts the page title and meta description.
  
- **SSL Certificate Information**:
  - Checks SSL version, cipher, expiration date, and days until expiration.
  
- **Vulnerability Testing**:
  - SQL Injection: Tests common SQL injection payloads.
  - Cross-Site Scripting (XSS): Tests common XSS payloads.
  - Directory Traversal: Checks for directory traversal vulnerabilities.
  - Open Ports: Tests if common ports (80, 443, 8080) are open.
  
- **Log File Analysis**:
  - Analyzes server logs for potential attack indicators, including:
    - SQL Injection patterns
    - XSS payloads
    - Directory Traversal attempts
    - Command Injection patterns
  
- **Data Persistence**:
  - Stores the results in a CSV file for further analysis.

## Requirements

- Python 3.8+
- Flask
- Requests
- BeautifulSoup
- Pandas
- SSL (Standard Library)
- Socket (Standard Library)

You can install the required Python dependencies using:

```bash
pip install flask requests beautifulsoup4 pandas
Project Structure
.
├── app.py                # Main Flask application
├── seo_security_data.csv # CSV file for storing analysis results
├── templates/
│   └── index.html        # Frontend HTML page
├── README.md             # Project documentation
└── logs/                 # (Optional) Directory containing your server logs
Setup
Clone the repository:

git clone https://github.com/yourusername/seo-security-analyzer.git
cd seo-security-analyzer
Install the required dependencies:
bash
Copy code
pip install -r requirements.txt
Update the log file path in app.py to point to the actual location of your server logs (if using log analysis).

Run the Flask application:

python app.py
The application will be available at http://127.0.0.1:5000/.

API Endpoints
POST /analyze
This endpoint accepts a JSON payload with a URL and returns an analysis report of the URL.

Request Example:

json
Copy code
{
  "url": "https://example.com"
}
Response Example:

json
Copy code
{
  "status": "success",
  "data": {
    "url": "https://example.com",
    "title": "Example Title",
    "meta_description": "Example meta description",
    "ssl_info": {
      "SSL Version": "TLSv1.2",
      "Cipher": ["AES256-GCM-SHA384"],
      "Expires On": "2025-01-01",
      "Days Until Expiry": 365
    },
    "vulnerabilities": {
      "sql_injection": [{ "payload": "' OR '1'='1", "vulnerable": true }],
      "xss": [{ "payload": "<script>alert('XSS')</script>", "vulnerable": false }],
      "directory_traversal": [{ "payload": "../../../../etc/passwd", "vulnerable": false }],
      "open_ports": [80, 443]
    },
    "log_analysis": {
      "SQL Injection": ["log entry 1", "log entry 2"],
      "XSS": ["log entry 3"],
      "Directory Traversal": ["log entry 4"],
      "Command Injection": ["log entry 5"]
    },
    "analysis_date": "2025-01-02 14:00:00"
  }
}
GET /data
Fetches all stored SEO and security analysis data from the CSV file.

Response Example:

json
Copy code
[
  {
    "url": "https://example.com",
    "title": "Example Title",
    "meta_description": "Example meta description",
    "ssl_info": {
      "SSL Version": "TLSv1.2",
      "Cipher": ["AES256-GCM-SHA384"],
      "Expires On": "2025-01-01",
      "Days Until Expiry": 365
    },
    "vulnerabilities": {
      "sql_injection": [{ "payload": "' OR '1'='1", "vulnerable": true }],
      "xss": [{ "payload": "<script>alert('XSS')</script>", "vulnerable": false }],
      "directory_traversal": [{ "payload": "../../../../etc/passwd", "vulnerable": false }],
      "open_ports": [80, 443]
    },
    "log_analysis": {
      "SQL Injection": ["log entry 1", "log entry 2"],
      "XSS": ["log entry 3"],
      "Directory Traversal": ["log entry 4"],
      "Command Injection": ["log entry 5"]
    },
    "analysis_date": "2025-01-02 14:00:00"
  }
]
Contributing
If you would like to contribute to the project, feel free to submit a pull request. Here's how you can contribute:

Fork the repository.
Create a new branch for your feature or bugfix.
Make your changes and test them.
Submit a pull request with a clear explanation of your changes.
License
This project is open-source and available under the MIT License. See the LICENSE file for more details.
