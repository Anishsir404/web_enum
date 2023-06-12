import requests
import builtwith
from urllib.parse import urlparse
from selenium import webdriver
import dns.resolver
import socket
import concurrent.futures
import whois
import ssl
import re
# Input URL
# url = input("Enter the target URL: ")
url = "https://softwarica.edu.np/"

# Technology Detection
def detect_technologies(url):
    technologies = builtwith.builtwith(url)
    
    print("Technologies used:")
    for category, tech in technologies.items():
        print(f"{category}:")
        for t in tech:
            print(t)
            # Step 2: Search for Exploits
            search_exploits(t)

# Search for Exploits
def search_exploits(technology):
    query = f"{technology} exploit"
    url = f"https://www.exploit-db.com/search?description={query}"
    response = requests.get(url)
    print(response.text)
    # Process the response and extract relevant information
    # (e.g., exploit titles, URLs, descriptions, etc.)
    # Display the results
def fuzz_directories(url):
    with open("files/common.txt", "r") as file:
        common_directories = file.read().splitlines()

    for directory in common_directories:
        directory_url = url + "/" + directory
        response = requests.get(directory_url)
        if response.status_code != 404 and response.status_code != 403:
            print(f"[{response.status_code}] -- {directory_url}")
            # capture_screenshot(directory_url)
def fuzz_subdomains(url):
    parsed_url = urlparse(url)
    domain = parsed_url.netloc
    if domain.startswith("www."):
        domain = domain[4:]
    with open("files/subdomains.txt", "r") as file:
        common_subdomains = file.read().splitlines()
    for subdomain in common_subdomains:
        subdomain_url = f"https://{subdomain}.{domain}"
        try:
            response = requests.get(subdomain_url)
            if response.status_code == 200:
                print(f"Valid subdomain found: {subdomain_url}")
        except requests.exceptions.RequestException as e:
            print(f"An error occurred while fuzzing subdomain: {subdomain_url}")

def fuzz_files(url):
    with open("files/commonfile.txt", "r") as file:
        common_files = file.read().splitlines()

    for file in common_files:
        file_url = url + "/" + file
        response = requests.get(file_url)
        
        if response.status_code != 404:
            print(f"[{response.status_code}]: {file_url}")

def capture_screenshot(url):
    chromedriver_path = "D:\3rd-sem\programming\project\chromedriver_win32\chromedriver.exe"
    options = webdriver.ChromeOptions()
    options.add_argument("--headless")  # Run Chrome in headless mode (without GUI)
    options.add_argument("--no-sandbox")
    options.add_argument("--disable-dev-shm-usage")

    # Specify the path to your chromedriver executable
    driver = webdriver.Chrome(executable_path=chromedriver_path, options=options)
    driver.get(url)
    # Specify the directory path to save the screenshots
    screenshot_directory = "screenshot_file"
    # Save screenshot to a file in the specified directory
    screenshot_file = f"{screenshot_directory}/screenshot_{url.replace('https://www.', '')}.png"
    driver.save_screenshot(screenshot_file)
    print(f"Screenshot saved: {screenshot_file}")


    driver.quit()

def dns_enum(domain):
    parsed_url = urlparse(url)
    domain = parsed_url.netloc
    if domain.startswith("www."):
        domain = domain[4:]
    try:
        record_types = ['A', 'AAAA', 'MX', 'NS']
        print(f"DNS Records for {domain}:")
        for rtype in record_types:
            answers = dns.resolver.resolve(domain, rtype)
            for answer in answers:
                print(f"{rtype}: {answer}")
    except dns.resolver.NXDOMAIN:
        print(f"DNS enumeration failed for {domain}.")

def port_scan(url, start_port, end_port):
    try:
        target = socket.gethostbyname(url.split("//")[-1].split("/")[0])
        print(f"Scanning ports {start_port} to {end_port} on [{target}]...")
        open_ports = []
        
        def scan_port(port):
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)
            try:
                result = sock.connect_ex((target, port))
                if result == 0:
                    service = socket.getservbyport(port)
                    sock.close()
                    return port, "open", service
                sock.close()
                return port, "closed", None
            except socket.error as e:
                return port, str(e), None
        
        with concurrent.futures.ThreadPoolExecutor() as executor:
            futures = [executor.submit(scan_port, port) for port in range(start_port, end_port + 1)]
            for future in concurrent.futures.as_completed(futures):
                port, status, service = future.result()
                if status == "open":
                    open_ports.append((port, service))
                elif status != "closed":
                    print(f"Error occurred while scanning port {port}: {status}")
        
        if open_ports:
            print("Open ports:")
            for port, service in open_ports:
                print(f"Port {port} is open. Service: {service}")
        else:
            print("No open ports found.")
    
    except socket.gaierror as e:
        print(f"DNS resolution failed for {url}. Error: {str(e)}")
    except Exception as e:
        print(f"An error occurred during port scanning: {str(e)}")

def get_email_addresses(url):
    response = requests.get(url)
    emails = re.findall(r'[\w.-]+@[\w.-]+', response.text)
    if emails:
        print("Email addresses found:")
        for email in emails:
            print(email)
    else:
        print("No email addresses found.")

def get_whois_record(url):
    domain = url.split("//")[-1].split("/")[0]
    whois_info = whois.whois(domain)
    print("WHOIS Record:")
    print(whois_info)

def get_ssl_certificate(url):
    hostname = url.split("//")[-1].split("/")[0]
    context = ssl.create_default_context()
    with socket.create_connection((hostname, 443)) as sock:
        with context.wrap_socket(sock, server_hostname=hostname) as sslsock:
            cert = sslsock.getpeercert()
    print("SSL Certificate:")
    print(cert)

def gather_information(url):
    get_email_addresses(url)
    get_whois_record(url)
    get_ssl_certificate(url)
    
# Step 1: Detect Technologies
# detect_technologies(url)
# fuzz_directories(url)
# fuzz_subdomains(url)
# fuzz_files(url)
# capture_screenshot(url)
# dns_enum(url)
# port_scan(url, 1, 1000)
# gather_information(url)