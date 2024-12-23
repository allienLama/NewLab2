import re
import csv
import json
from collections import defaultdict
from selenium import webdriver
from selenium.webdriver.firefox.service import Service
from webdriver_manager.firefox import GeckoDriverManager
import time

# Step 1: Read access_log.txt and extract URLs and their HTTP status codes
def extract_urls_and_status_codes(log_file):
    url_status = []
    with open(log_file, 'r') as file:
        for line in file:
            match = re.search(r'\"(GET|POST) (http[s]?://[^\s]+) HTTP/1.1\" (\d{3})', line)
            if match:
                url = match.group(2)
                status_code = match.group(3)
                url_status.append((url, status_code))
    return url_status

# Step 2: Count occurrences of 404 status codes
def count_404_occurrences(url_status):
    count_dict = defaultdict(int)
    for url, status in url_status:
        if status == '404':
            count_dict[url] += 1
    return count_dict

# Step 3: Write URL status report to url_status_report.txt
def write_url_status_report(url_status, output_file):
    with open(output_file, 'w') as file:
        for url, status in url_status:
            file.write(f"{url} {status}\n")

# Step 4: Write 404 URLs to malware_candidates.csv
def write_malware_candidates(count_dict, output_file):
    with open(output_file, 'w', newline='') as csvfile:
        writer = csv.writer(csvfile)
        writer.writerow(['URL', '404 Count'])
        for url, count in count_dict.items():
            writer.writerow([url, count])

# Step 5: Scrape blacklisted domains from threat_feed.html using Selenium
def scrape_blacklisted_domains(url):
    # Set up the Firefox WebDriver
    service = Service(GeckoDriverManager().install())
    driver = webdriver.Firefox(service=service)
    
    try:
        # Access the local HTML file
        driver.get(url)
        time.sleep(2)  # Wait for the page to load

        # Locate the unordered list containing blacklisted domains
        blacklist = [li.text for li in driver.find_elements("tag name", "li")]
    finally:
        # Close the WebDriver
        driver.quit()
    
    return blacklist

# Step 6: Compare URLs with blacklisted domains
def find_blacklisted_urls(url_status, blacklist):
    blacklisted_urls = []
    for url, status in url_status:
        for domain in blacklist:
            if domain in url:
                blacklisted_urls.append((url, status))
                break
    return blacklisted_urls

# Step 7: Create alert.json with details of blacklisted URLs
def create_alert_json(blacklisted_urls, output_file):
    alert_data = []
    for url, status in blacklisted_urls:
        alert_data.append({
            'url': url,
            'status': status,
            'event_count': 1  # Assuming each occurrence is a separate event
        })
    with open(output_file, 'w') as json_file:
        json.dump(alert_data, json_file, indent=4)

# Step 8: Create summary_report.json
def create_summary_report(count_dict, output_file):
    summary = {
        'total_urls_checked': len(count_dict),
        'total_blacklisted_urls': len(count_dict),
        'total_404_errors': sum(count_dict.values())
    }
    with open(output_file, 'w') as json_file:
        json.dump(summary, json_file, indent=4)

# Main execution
if __name__ == "__main__":
    log_file = 'access_log.txt'
    threat_feed_url = 'http://127.0.0.1:5500/threat_feed.html'  # Update with the correct path

    # Extract URLs and status codes
    url_status = extract_urls_and_status_codes(log_file)

    # Count 404 occurrences
    count_dict = count_404_occurrences(url_status)

    # Write URL status report
    write_url_status_report(url_status, 'url_status_report.txt')

    # Write malware candidates
    write_malware_candidates(count_dict, 'malware_candidates.csv')

    # Scrape blacklisted domains
    blacklist = scrape_blacklisted_domains(threat_feed_url)

    # Find blacklisted URLs
    blacklisted_urls = find_blacklisted_urls(url_status, blacklist)

    # Create alert.json
    create_alert_json(blacklisted_urls, 'alert.json')

    # Create summary_report.json
    create_summary_report(blacklisted_urls , 'summary_report.json')
