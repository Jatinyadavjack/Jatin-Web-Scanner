import requests
from bs4 import BeautifulSoup
import re
import socket
import nmap
import subprocess
import ssl
from urllib.parse import urlparse
import pyfiglet
import time
import sys

# Function to print the fancy banner
def print_banner():
    banner = pyfiglet.figlet_format("Jatin Web-Scanner", font="slant")  # You can change the font
    print(banner)
    print("-" * 50)  # Add separator for better readability

# Scanning animation function (called once after Directory Traversal Test)
def scanning_animation():
    print("Scanning", end="")
    for _ in range(3):  # Rotating dots
        sys.stdout.write(".")
        sys.stdout.flush()
        time.sleep(0.5)
    print()  # Move to the next line after animation

# Function to check the status code of the website with better error handling
def check_status(url):
    try:
        response = requests.get(url, timeout=10)  # Set a timeout for the request
        print(f"Status Code Check: {response.status_code} (OK)" if response.status_code == 200 else f"Status Code Check: {response.status_code} (Error)")
        return response.status_code
    except requests.exceptions.Timeout:
        print("Status Code Check: Error - Connection timed out.")
    except requests.exceptions.RequestException as e:
        print(f"Status Code Check: Error - {e}")
    return None

# Function to check SSL/TLS certificate with better error handling
def check_https(url):
    try:
        if url.startswith("https://"):
            print("HTTPS Check: Secure connection established (HTTPS).")
        else:
            print("HTTPS Check: Warning! No HTTPS connection.")

        cert = ssl.get_server_certificate((urlparse(url).hostname, 443))
        print("SSL/TLS Certificate Info: Certificate retrieved successfully.")
    except requests.exceptions.Timeout:
        print("SSL/TLS Certificate Info: Error - Connection timed out.")
    except ssl.SSLError as e:
        print(f"SSL/TLS Certificate Info: Error - {e}")
    except Exception as e:
        print(f"SSL/TLS Certificate Info: Error - {e}")

# Function to fetch HTTP headers and analyze security headers with better error handling
def fetch_headers(url):
    try:
        response = requests.get(url, timeout=10)  # Set a timeout for the request
        print(f"HTTP Headers Check: {response.headers.get('Content-Type', 'Not Available')}")
        # Security headers check
        headers = response.headers
        if 'Strict-Transport-Security' not in headers:
            print("Security Header Check: Missing 'Strict-Transport-Security' header.")
        if 'X-Content-Type-Options' not in headers:
            print("Security Header Check: Missing 'X-Content-Type-Options' header.")
        if 'X-Frame-Options' not in headers:
            print("Security Header Check: Missing 'X-Frame-Options' header.")
        if 'X-XSS-Protection' not in headers:
            print("Security Header Check: Missing 'X-XSS-Protection' header.")
    except requests.exceptions.Timeout:
        print("HTTP Headers Check: Error - Connection timed out.")
    except requests.exceptions.RequestException as e:
        print(f"HTTP Headers Check: Error - {e}")

# Basic function to test for XSS vulnerability
def test_xss(url):
    payload = "<script>alert('XSS')</script>"
    try:
        response = requests.get(url + payload, timeout=10)  # Set a timeout for the request
        if payload in response.text:
            print("XSS Test: Vulnerability found (XSS detected).")
        else:
            print("XSS Test: No XSS vulnerability detected.")
    except requests.exceptions.Timeout:
        print("XSS Test: Error - Connection timed out.")
    except requests.exceptions.RequestException as e:
        print(f"XSS Test: Error - {e}")

# Basic function to test for SQL injection
def test_sql_injection(url):
    payloads = ["' OR '1'='1", '" OR "1"="1', "' OR 1=1 --", "' OR 'a'='a"]
    try:
        for payload in payloads:
            response = requests.get(url + payload, timeout=10)  # Set a timeout for the request
            if "error" in response.text.lower() or "mysql" in response.text.lower():
                print(f"SQL Injection Test: Vulnerability found with payload: {payload}")
                return
        print("SQL Injection Test: No SQL injection vulnerabilities found.")
    except requests.exceptions.Timeout:
        print("SQL Injection Test: Error - Connection timed out.")
    except requests.exceptions.RequestException as e:
        print(f"SQL Injection Test: Error - {e}")

# Function to check for directory traversal vulnerability
def test_directory_traversal(url):
    payload = "../../../../etc/passwd"
    try:
        response = requests.get(url + payload, timeout=10)  # Set a timeout for the request
        if "root" in response.text:
            print("Directory Traversal Test: Vulnerability found.")
        else:
            print("Directory Traversal Test: No vulnerability found.")
    except requests.exceptions.Timeout:
        print("Directory Traversal Test: Error - Connection timed out.")
    except requests.exceptions.RequestException as e:
        print(f"Directory Traversal Test: Error - {e}")

# Function to scan for open ports using nmap
def scan_ports(url):
    nm = nmap.PortScanner()
    hostname = urlparse(url).hostname
    
    try:
        nm.scan(hostname, '1-1024')  # Scan ports from 1 to 1024
        
        # Check if the scan was successful
        if hostname not in nm.all_hosts():
            print("Open Ports Scan: No results found for the host.")
            return

        print("Open Ports Scan:")
        open_ports = False
        for proto in nm[hostname].all_protocols():
            lport = nm[hostname][proto].keys()
            for port in lport:
                print(f" - Port {port}: Open")
                open_ports = True
        if not open_ports:
            print("No open ports detected.")

    except Exception as e:
        print(f"Open Ports Scan: Error occurred - {e}")

# Function to scan for subdomains (using simple bruteforce for demo)
def subdomain_scan(domain):
    subdomains = ['www', 'mail', 'blog', 'dev', 'test', 'admin']
    print("Subdomain Scan:")
    found_subdomain = False
    for sub in subdomains:
        url = f"{sub}.{domain}"
        try:
            response = requests.get(f"http://{url}", timeout=10)  # Set a timeout for the request
            if response.status_code == 200:
                print(f" - Subdomain found: {url}")
                found_subdomain = True
        except requests.RequestException:
            continue
    if not found_subdomain:
        print("No subdomains found.")

# Main function to run the complete scan
def website_scan(url):
    print(f"Starting scan for {url}...\n")
    check_status(url)
    check_https(url)
    fetch_headers(url)
    test_xss(url)
    test_sql_injection(url)
    test_directory_traversal(url)
    scanning_animation()  # Display animation after Directory Traversal Test
    scan_ports(url)
    subdomain_scan(urlparse(url).hostname)
    print("\nScan completed successfully.\n")

if __name__ == "__main__":
    print_banner()  # Print the banner first
    target_url = input("Enter website URL: ")
    website_scan(target_url)
