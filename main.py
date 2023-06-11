import requests
import builtwith
import subprocess
# Input URL
# url = input("Enter the target URL: ")
url = "https://pwn.college/dojos"

# Technology Detection
def detect_technologies(url):
    technologies = builtwith.builtwith(url)
    return technologies

technologies_used = detect_technologies(url)
print("Technologies used:")
for category, tech in technologies_used.items():
    print(f"{category}:")
    for t in tech:
        print(t)
