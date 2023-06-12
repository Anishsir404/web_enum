import requests
import builtwith
from urllib.parse import urlparse
from selenium import webdriver
import dns.resolver
# Input URL
# url = input("Enter the target URL: ")
url = "https://www.google.com"

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
    screenshot_directory = "screenshot"
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

# Step 1: Detect Technologies
# detect_technologies(url)
# fuzz_directories(url)
# fuzz_subdomains(url)
# fuzz_files(url)
# capture_screenshot(url)
dns_enum(url)