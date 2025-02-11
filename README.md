# Jatin-Web-Scanner
Web Scanner - SQLi & XSS Vulnerability Testing Tool
This is a Python-based tool for scanning websites for SQL Injection (SQLi) and Cross-Site Scripting (XSS) vulnerabilities. The tool checks for common vulnerabilities such as SQLi in URL parameters, input fields, and headers. It also performs basic checks for server configurations and SSL/TLS certificate validity.

Features:
Status Code Check: Verifies if the website is up and returns a valid status code (200).
HTTPS Check: Checks if the website uses HTTPS and validates its SSL certificate.
HTTP Headers Check: Verifies important HTTP headers like Strict-Transport-Security, X-Content-Type-Options, etc.
SQL Injection Testing: Automatically tests common SQL injection payloads in URL parameters.
Cross-Site Scripting (XSS) Testing: Attempts to inject XSS payloads in URL parameters.
Directory Traversal Test: Tests for directory traversal vulnerabilities.
Port Scanning: Scans for open ports using Nmap.
Subdomain Scan: Checks for common subdomains of the target domain.
Requirements
Before using the scanner, ensure that you have the following installed:

Python 3.x: Download and install the latest version of Python from python.org.
Required Python Libraries:
requests: For making HTTP requests.
beautifulsoup4: For parsing HTML.
pyfiglet: For displaying a fancy banner.
nmap: For scanning open ports.
ssl: For SSL certificate validation.
You can install the required libraries using pip:

bash
Copy
Edit
pip install requests beautifulsoup4 pyfiglet python-nmap
Installation
Clone the Repository:

Clone the repository to your local machine:

bash
Copy
Edit
git clone https://github.com/your-repository/web-scanner.git
cd web-scanner
Install Dependencies:

Make sure you have all the necessary Python libraries installed by running:

bash
Copy
Edit
pip install -r requirements.txt
Usage
1. Run the Scanner
To use the web scanner, simply run the Python script from the terminal:

bash
Copy
Edit
python website_scanner.py
2. Enter the Target URL
When prompted, enter the URL of the website you want to scan. For example:

bash
Copy
Edit
Enter website URL: https://www.example.com
The scanner will then perform various tests on the website, including:

Checking for vulnerabilities such as SQL Injection and XSS.
Scanning for open ports.
Checking HTTP headers for security configurations.
Validating SSL/TLS certificates.
Example Output
The output will look like this:

mathematica
Copy
Edit
     _       __     __    _    ____                __         __       
    | |     / /__  / /__ (_)  / __ \__ _   _ __   / /__ _   _/ /  ___ 
    | | /| / / _ \/ / _ \| | / / _` / _` | '_ \ / / _ \ | | |/ / / _ \
    | |/ |/ /  __/ / (_) | |/ / (_| / (_| | | |_/ /  __/ |_|   <  (_) |
    |_/_/|_/\___/_/\___//_/   \__,_|\__,_|_| .__/  \___|\__,_|\_\_\\___/
                                          |_|
--------------------------------------------------
Starting scan for https://example.com...

Status Code Check: 200 (OK)
HTTPS Check: Secure connection established (HTTPS).
SSL/TLS Certificate Info: Certificate retrieved successfully.
HTTP Headers Check: text/html; charset=UTF-8
Security Header Check: Missing 'Strict-Transport-Security' header.
Security Header Check: Missing 'X-Content-Type-Options' header.
Security Header Check: Missing 'X-Frame-Options' header.
Security Header Check: Missing 'X-XSS-Protection' header.
XSS Test: No XSS vulnerability detected.
SQL Injection Test: No SQL injection vulnerabilities found.
Directory Traversal Test: No vulnerability found.
Scanning...
Open Ports Scan:
 - Port 80: Open
Subdomain Scan:
No subdomains found.

Scan completed successfully.
--------------------------------------------------
Advanced Options
Change Timeout Duration
You can adjust the timeout duration for the requests by modifying the script. Look for the timeout parameter in the requests.get() method and change its value.

Example:

python
Copy
Edit
response = requests.get(url, timeout=15)  # Timeout set to 15 seconds
Running SQLmap with the Scanner
For more advanced testing of SQL Injection, you can use SQLmap, an automated tool that can exploit SQL injection vulnerabilities. To run SQLmap:

bash
Copy
Edit
sqlmap -u "https://www.systumm.com/page?category=123" --risk=3 --level=5 --dbs
This command will run SQLmap against a given URL and attempt to detect SQL injection vulnerabilities.

Contributing
If you find any bugs or have ideas for improvements, feel free to submit an issue or create a pull request.

Fork the repository.
Clone your fork:
bash
Copy
Edit
git clone https://github.com/your-username/web-scanner.git
Make your changes and push them:
bash
Copy
Edit
git commit -am "Added a new feature"
git push origin master
Submit a pull request with a description of the changes.
Disclaimer
This tool is intended for ethical testing of websites you own or have permission to test. Always ensure you have the proper authorization before conducting any penetration testing. Unauthorized access to websites is illegal.

