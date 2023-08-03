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
from selenium.webdriver.chrome.options import Options
import json
from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas
import glob
from datetime import datetime
import os
technology = []
def get_domain(url):
    domain = url.split("//")[-1].split("/")[0]
    return domain
# Technology Detection
def detect_technologies(url):
    try:
        technologies = builtwith.builtwith(url)

        domain = get_domain(url)
        directory = os.path.join("info_collected", domain)
        if not os.path.exists(directory):
            os.makedirs(directory)

        file_path = os.path.join(directory, "technologies.txt")

        with open(file_path, "w") as file:
            file.write("Technologies used:\n")
            print("Technologies used:")
            for category, tech in technologies.items():
                file.write(f"{category}:\n")
                print(f"{category}:")
                for t in tech:
                    file.write(f"{t}\n")
                    technology.append({category:t})
                    print(t)

    except builtwith.BuiltWithError as e:
        print(f"An error occurred while detecting technologies: {str(e)}")
    except Exception as e:
        print(f"An error occurred during technology detection: {str(e)}")
# Search for Exploits
def search_exploits(technology, domain):
    base_url = "https://services.nvd.nist.gov/rest/json/cves/1.0"
    params = {
        "keyword": technology,
        "startIndex": 0,
        "resultsPerPage": 10,
        "isExactMatch": "false"
    }

    try:
        response = requests.get(base_url, params=params)
        response.raise_for_status()  # Raise an exception for 4xx or 5xx status codes
        data = response.json()
        print(f"Searching for exploits {technology}...")
        exploits = []
        if "result" in data and "CVE_Items" in data["result"]:
            for cve_item in data["result"]["CVE_Items"]:
                cve_id = cve_item["cve"]["CVE_data_meta"]["ID"]
                description = cve_item["cve"]["description"]["description_data"][0]["value"]
                exploit_info = f"CVE ID: {cve_id}\nDescription: {description}\n{'-' * 50}"
                exploits.append(exploit_info)

        output = ""
        if exploits:
            output += "\n\n".join(exploits)
        else:
            output += f"No exploits found for {technology}"

        # Create the info_collected folder if it doesn't exist
        if not os.path.exists("info_collected"):
            os.makedirs("info_collected")

        # Create the domain folder if it doesn't exist
        domain = get_domain(domain)
        domain_folder = os.path.join("info_collected", domain)
        if not os.path.exists(domain_folder):
            os.makedirs(domain_folder)

        output_file = os.path.join(domain_folder, f"{technology}_exploits.txt")
        with open(output_file, "w") as file:
            file.write(output)

        print(f"Exploits output saved in {output_file} file.")
        print(output)

    except requests.exceptions.RequestException as e:
        print("An error occurred:", str(e))
    except Exception as e:
        print(f"An error occurred during exploit search: {str(e)}")
#fuzzing for directories
def fuzz_directories(url):
    with open("files/common.txt", "r") as file:
        common_directories = file.read().splitlines()

    # Get the domain name from the URL
    domain = get_domain(url)

    # Create the info_collected folder if it doesn't exist
    if not os.path.exists("info_collected"):
        os.makedirs("info_collected")

    # Create the domain folder if it doesn't exist
    domain_folder = os.path.join("info_collected", domain)
    if not os.path.exists(domain_folder):
        os.makedirs(domain_folder)

    # Create the output file path
    output_file = os.path.join(domain_folder, "fuzzing_dir.txt")

    def process_directory(directory):
        directory_url = url + "/" + directory
        try:
            response = requests.get(directory_url)
            if response.status_code != 404 and response.status_code != 403:
                output_line = f"[{response.status_code}] -- {directory_url}\n"
                print(output_line)
                with open(output_file, "a") as file:
                    file.write(output_line)
                capture_screenshot(directory_url, domain)
                get_email_addresses(directory_url, domain)
        except requests.exceptions.RequestException as e:
            print(f"An error occurred while processing {directory_url}: {str(e)}")

    with concurrent.futures.ThreadPoolExecutor() as executor:
        # Submit the directory processing tasks to the thread pool
        futures = [executor.submit(process_directory, directory) for directory in common_directories]

        # Wait for all tasks to complete
        concurrent.futures.wait(futures)

    print("Fuzzing directories completed.")
#fuzzing for subdomains
def fuzz_subdomains(url):
    write_domain = get_domain(url)
    parsed_url = urlparse(url)
    domain = parsed_url.netloc
    for_me_domain = domain
    if domain.startswith("www."):
        domain = domain[4:]
    with open("files/subdomains.txt", "r") as file:
        common_subdomains = file.read().splitlines()

    # Create the info_collected folder if it doesn't exist
    if not os.path.exists("info_collected"):
        os.makedirs("info_collected")

    # Create the domain folder if it doesn't exist
    domain_folder = os.path.join("info_collected", write_domain)
    if not os.path.exists(domain_folder):
        os.makedirs(domain_folder)

    # Create the output file path
    output_file = os.path.join(domain_folder, "fuzzing_subdomains.txt")

    # Create a thread pool executor
    with concurrent.futures.ThreadPoolExecutor() as executor:
        futures = []
        for subdomain in common_subdomains:
            subdomain_url = f"https://{subdomain}.{domain}"
            futures.append(executor.submit(process_subdomain, subdomain_url, output_file, for_me_domain))

        # Wait for all tasks to complete
        concurrent.futures.wait(futures)

    print("Subdomain fuzzing complete.")

def process_subdomain(subdomain_url, output_file, for_me_domain):
    try:
        response = requests.get(subdomain_url)
        if response.status_code == 200:
            output_line = f"Valid subdomain found: {subdomain_url}\n"
            print(output_line)
            with open(output_file, "a") as file:
                file.write(output_line)
            capture_screenshot(subdomain_url, for_me_domain)
            get_email_addresses(subdomain_url, for_me_domain)

    except requests.exceptions.RequestException as e:
        error_line = f"An error occurred while fuzzing subdomain: {subdomain_url}\n"
        print(error_line)
        with open(output_file, "a") as file:
            file.write(error_line)
#fuzzing for files
def fuzz_files(url):
    with open("files/commonfile.txt", "r") as file:
        common_files = file.read().splitlines()

    # Get the domain name from the URL
    domain = get_domain(url)

    # Create the info_collected folder if it doesn't exist
    if not os.path.exists("info_collected"):
        os.makedirs("info_collected")

    # Create the domain folder if it doesn't exist
    domain_folder = os.path.join("info_collected", domain)
    if not os.path.exists(domain_folder):
        os.makedirs(domain_folder)

    # Create the output file path
    output_file = os.path.join(domain_folder, "fuzzing_files.txt")

    # Create a thread pool executor
    with concurrent.futures.ThreadPoolExecutor() as executor:
        futures = []
        for file_name in common_files:
            file_url = "https://"+domain + "/" + file_name
            futures.append(executor.submit(process_file, file_url, output_file, domain))

        # Wait for all tasks to complete
        concurrent.futures.wait(futures)

    print("File fuzzing complete.")

def process_file(file_url, output_file, domain):
    try:
        response = requests.get(file_url)
        if response.status_code != 404 and response.status_code != 403:
            output_line = f"[{response.status_code}]: {file_url}\n"
            print(output_line)
            with open(output_file, "a") as file:
                file.write(output_line)
            capture_screenshot(file_url, domain)
            get_email_addresses(file_url, domain)

    except requests.exceptions.RequestException as e:
        error_line = f"An error occurred while fuzzing file: {file_url}\n"
        print(error_line)
        with open(output_file, "a") as file:
            file.write(error_line)

def capture_screenshot(url, domain):
    chromedriver_path = r"chromedriver.exe"
    options = Options()
    options.add_argument("--headless")
    options.add_argument("--no-sandbox")
    options.add_argument("--disable-dev-shm-usage")

    # Specify the path to your chromedriver executable
    driver = webdriver.Chrome(executable_path=chromedriver_path, options=options)
    driver.get(url)

    # Specify the parent directory path to save the screenshots
    screenshot_directory = r"screenshot_file"

    # Create the parent directory if it doesn't exist
    os.makedirs(screenshot_directory, exist_ok=True)

    # Extract the domain name from the URL
    domain = get_domain(domain)

    # Create a subdirectory based on the domain name
    domain_directory = os.path.join(screenshot_directory, domain)
    os.makedirs(domain_directory, exist_ok=True)

    # Generate a valid screenshot file path within the domain directory
    filename = url.replace("://", "_").replace("/", "_").replace(".", "_") + ".png"
    screenshot_file = os.path.join(domain_directory, filename)

    # Create a thread pool executor
    with concurrent.futures.ThreadPoolExecutor() as executor:
        future = executor.submit(save_screenshot, driver, screenshot_file)
        try:
            # Wait for the task to complete
            future.result()
            print(f"Screenshot saved: {screenshot_file}")
        except Exception as e:
            print(f"An error occurred while capturing screenshot: {str(e)}")

    # Quit the driver
    driver.quit()

def save_screenshot(driver, screenshot_file):
    driver.save_screenshot(screenshot_file)


def dns_enum(domain):
    domain_write = get_domain(domain)
    parsed_url = urlparse(domain)
    domain = parsed_url.netloc
    if domain.startswith("www."):
        domain = domain[4:]
    try:
        record_types = ['A', 'AAAA', 'MX', 'NS']
        output = f"DNS Records for {domain}:\n"
        for rtype in record_types:
            answers = dns.resolver.resolve(domain, rtype)
            for answer in answers:
                output += f"{rtype}: {answer}\n"

        # Create the info_collected folder if it doesn't exist
        if not os.path.exists("info_collected"):
            os.makedirs("info_collected")

        # Create the domain folder if it doesn't exist
        domain_folder = os.path.join("info_collected", domain_write)
        if not os.path.exists(domain_folder):
            os.makedirs(domain_folder)

        # Create the output file path
        output_file = os.path.join(domain_folder, "dns_records.txt")

        # Write the output to the file
        with open(output_file, "w") as file:
            file.write(output)
            print(output)

        print(f"DNS enumeration output saved in {output_file} file.")

    except dns.resolver.NXDOMAIN:
        print(f"DNS enumeration failed for {domain}.")
    except dns.resolver.NoAnswer:
        print(f"No DNS records found for {domain}.")
    except dns.exception.DNSException as e:
        print(f"An error occurred during DNS enumeration: {str(e)}")

def port_scan(url, start_port, end_port):
    try:
        target = socket.gethostbyname(url.split("//")[-1].split("/")[0])
        print(f"Scanning ports {start_port} to {end_port} on [{target}]...")
        open_ports = []

        # Get the domain name from the URL
        domain = get_domain(url)

        # Create the info_collected folder if it doesn't exist
        if not os.path.exists("info_collected"):
            os.makedirs("info_collected")

        # Create the domain folder if it doesn't exist
        domain_folder = os.path.join("info_collected", domain)
        if not os.path.exists(domain_folder):
            os.makedirs(domain_folder)

        # Create the output file path
        output_file = os.path.join(domain_folder, "port_scan_results.txt")

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

        # Prepare the output to be written to the file
        output = f"Open ports for {url}:\n"
        if open_ports:
            for port, service in open_ports:
                output += f"Port {port} is open. Service: {service}\n"
                # print(output)
        else:
            output += "No open ports found.\n"

        # Write the output to the file
        with open(output_file, "w") as file:
            file.write(output)
            print(output)

        print(f"Port scanning results saved in {output_file} file.")

    except socket.gaierror as e:
        print(f"DNS resolution failed for {url}. Error: {str(e)}")
    except Exception as e:
        print(f"An error occurred during port scanning: {str(e)}")

def is_valid_email(email):
    # Regular expression pattern to validate email addresses
    pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    return re.match(pattern, email)
def remove_invalid_emails(file_path):
    valid_emails = []
    with open(file_path, 'r') as file:
        for line in file:
            email = line.strip()
            if is_valid_email(email):
                valid_emails.append(email)
    with open(file_path, 'w') as file:
        for email in valid_emails:
            file.write(email + '\n')


def get_email_addresses(url, domain):
    try:
        response = requests.get(url)
        response.raise_for_status()
        text = response.text
        emails = re.findall(r'[\w\.-]+@[\w\.-]+', text)

        # Create the info_collected folder if it doesn't exist
        if not os.path.exists("info_collected"):
            os.makedirs("info_collected")

        # Create the domain folder if it doesn't exist
        domain_folder = os.path.join("info_collected", domain)
        if not os.path.exists(domain_folder):
            os.makedirs(domain_folder)

        # Create the output file path
        output_file = os.path.join(domain_folder, "email_addresses.txt")

        if emails:
            # Prepare the output to be written to the file
            output = "Email addresses found:\n"
            for email in emails:
                output += f"{email}\n"

            # Write the output to the file
            with open(output_file, "a") as file:
                file.write(output)

            print(f"Email addresses found:\n{output}")
            remove_invalid_emails(output_file)
            print(f"Results saved in {output_file} file.")
        else:
            print("No email addresses found.")
    except requests.exceptions.RequestException as e:
        print(f"Error retrieving URL: {str(e)}")
    except IOError as e:
        print(f"Error writing to file: {str(e)}")

def get_whois_record(url):
    try:
        domain = url.split("//")[-1].split("/")[0]
        whois_info = whois.whois(domain)

        # Create the info_collected folder if it doesn't exist
        if not os.path.exists("info_collected"):
            os.makedirs("info_collected")

        # Create the domain folder if it doesn't exist
        domain_folder = os.path.join("info_collected", domain)
        if not os.path.exists(domain_folder):
            os.makedirs(domain_folder)

        # Create the output file path
        output_file = os.path.join(domain_folder, "whois_record.txt")

        # Prepare the output to be written to the file
        output = "WHOIS Record:\n"
        output += str(whois_info)

        # Write the output to the file
        with open(output_file, "w") as file:
            file.write(output)

        print(f"WHOIS record retrieved. Results saved in {output_file} file.")

    except whois.parser.PywhoisError as e:
        print(f"Error retrieving WHOIS record: {str(e)}")

def get_ssl_certificate(url):
    domain = get_domain(url)
    try:
        hostname = url.split("//")[-1].split("/")[0]
        context = ssl.create_default_context()

        # Create the info_collected folder if it doesn't exist
        if not os.path.exists("info_collected"):
            os.makedirs("info_collected")

        # Create the domain folder if it doesn't exist
        domain_folder = os.path.join("info_collected", domain)
        if not os.path.exists(domain_folder):
            os.makedirs(domain_folder)

        # Create the output file path
        output_file = os.path.join(domain_folder, "ssl_certificate.txt")

        with socket.create_connection((hostname, 443)) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as sslsock:
                cert = sslsock.getpeercert()

        # Prepare the output to be written to the file
        output = "SSL Certificate:\n"
        output += json.dumps(cert, indent=4)

        # Write the output to the file
        with open(output_file, "w") as file:
            file.write(output)

        print(f"SSL certificate retrieved. Results saved in {output_file} file.")

    except ssl.SSLError as e:
        print(f"Error retrieving SSL certificate: {str(e)}")
    except socket.gaierror as e:
        print(f"Error resolving hostname: {str(e)}")
    except socket.timeout as e:
        print(f"Timeout occurred while retrieving SSL certificate: {str(e)}")

def gather_information(url):
    get_whois_record(url)
    get_ssl_certificate(url)
    
def generate_pdf_report(url):
    domain=get_domain(url)
    # Create a new PDF document
    pdf_file = f"info_collected/{domain}/web_enum_report_of_{domain}.pdf"
    c = canvas.Canvas(pdf_file, pagesize=letter)

    # Set the title and heading of the report
    c.setFont("Helvetica-Bold", 16)
    c.drawString(50, 770, "Web Enumeration Report by Anish web enum tool")

    # Add date and time at the top
    current_datetime = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    c.setFont("Helvetica", 12)
    c.drawString(50, 740, "Date and Time: " + current_datetime)

    # Add note about automated report generation
    c.setFont("Helvetica", 10)
    c.drawString(50, 710, "This report was generated automatically.")
    c.drawString(50, 690, "Please note that there may be errors or omissions.")

    # Define the order of files
    file_order = [
        "technologies.txt",
        "fuzzing_dir.txt",
        "fuzzing_subdomains.txt",
        "fuzzing_files.txt",
        "email_addresses.txt",
        "dns_records.txt",
        "port_scan_results.txt",
        "whois_record.txt",
        "ssl_certificate.txt"
    ]

    # Read the content from the output files
    file_paths = glob.glob(f"info_collected/{domain}/*", recursive=True)

    # Set the initial position for file content
    x = 50
    y = 650

    for file_name in file_order:
        for file_path in file_paths:
            if file_path.endswith(file_name):
                c.setFont("Helvetica-Bold", 14)
                c.drawString(x, y, file_name)
                c.setFont("Courier", 10)
                try:
                    with open(file_path, "r") as file:
                        content = file.read()
                        lines = content.splitlines()
                        for line in lines:
                            c.drawString(x, y - 15, line)
                            y -= 15
                            if y < 50:
                                c.showPage()  # Move to the next page if there is not enough space
                                y = 770  # Reset the y position for the new page
                                c.setFont("Helvetica-Bold", 14)
                                c.drawString(x, y, file_name)
                                c.setFont("Courier", 10)
                except PermissionError:
                    # Handle PermissionError and continue to the next file
                    continue

                y -= 30  # Add some spacing between files

    # Add a section for the remaining files
    remaining_files = [file for file in file_paths if os.path.basename(file) not in file_order]

    if remaining_files:
        c.showPage()  # Move to the next page for the remaining files section
        c.setFont("Helvetica-Bold", 16)
        # c.drawString(50, 770, "Remaining Files")

        y = 740  # Set the initial y position for the remaining files
        c.setFont("Courier", 10)

        for file_path in remaining_files:
            file_name = os.path.basename(file_path)
            c.setFont("Helvetica-Bold", 14)
            c.drawString(x, y, file_name)
            c.setFont("Courier", 10)
            try:
                with open(file_path, "r") as file:
                    content = file.read()
                    lines = content.splitlines()
                    for line in lines:
                        c.drawString(x, y - 15, line)
                        y -= 15
                        if y < 50:
                            c.showPage()  # Move to the next page if there is not enough space
                            y = 770  # Reset the y position for the new page
                            c.setFont("Helvetica-Bold", 14)
                            c.drawString(x, y, file_name)
                            c.setFont("Courier", 10)
            except PermissionError:
                # Handle PermissionError and continue to the next file
                continue

            y -= 30  # Add some spacing between files

    # Save and close the PDF document
    c.save()
    print(f"PDF report generated: {pdf_file}")

# Call the function to generate the PDF report


def main():
    # Input URL
    url = input("Enter the target URL: ")
    # url = "https://www.google.com"

    detect_technologies(url)
    for tech_dict in technology:
        for tech_value in tech_dict.values():
            # print("Searching for exploits for: ", tech_value, "\n")
            search_exploits(tech_value,url)
    fuzz_directories(url)
    fuzz_subdomains(url)
    fuzz_files(url)
    dns_enum(url)
    port_scan(url, 1, 1000)
    gather_information(url)
    generate_pdf_report(url)
if __name__ == "__main__":
    main()
    

