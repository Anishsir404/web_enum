import requests
import builtwith

# Input URL
# url = input("Enter the target URL: ")
url = "https://softwarica.edu.np"

# Technology Detection
def detect_technologies(url):
    technologies = builtwith.builtwith(url)
    
    print("Technologies used:")
    for category, tech in technologies.items():
        print(f"{category}:")
        for t in tech:
            print(t)
            # Step 2: Search for Exploits
            # search_exploits(t)

# Search for Exploits
def search_exploits(technology):
    query = f"{technology} exploit"
    url = f"https://www.exploit-db.com/search?description={query}"
    response = requests.get(url)
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



# Step 1: Detect Technologies
# detect_technologies(url)
fuzz_directories(url)