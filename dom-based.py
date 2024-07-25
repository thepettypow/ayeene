import argparse
import re
import time
import logging
from selenium import webdriver
from selenium.webdriver.chrome.service import Service as ChromeService
from selenium.webdriver.firefox.service import Service as FirefoxService
from selenium.webdriver.chrome.options import Options as ChromeOptions
from selenium.webdriver.firefox.options import Options as FirefoxOptions
from webdriver_manager.chrome import ChromeDriverManager
from webdriver_manager.firefox import GeckoDriverManager

# تنظیمات logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def parse_args():
    parser = argparse.ArgumentParser(description='Reflected and DOM-based XSS vulnerability scanner')
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

def generate_test_urls(url, params):
    # کاراکترهای خاص برای تست
    special_chars = ['<', '>', '"', "'"]
    
    test_urls = []
    for param in params:
        param_key = param[1]
        param_value = param[2]
        
        for char in special_chars:
            # اضافه کردن کاراکترهای خاص به انتهای مقدار پارامتر
            test_urls.append(re.sub(f'{param_key}={re.escape(param_value)}', f'{param_key}={re.escape(param_value + char)}', url))
            # اضافه کردن کاراکترهای خاص به انتهای URL
            test_urls.append(re.sub(f'{param_key}={re.escape(param_value)}', f'{param_key}={re.escape(param_value)}{char}', url))
    
    return test_urls

def check_xss(url, browser):
    logging.info(f'Testing URL: {url} with browser: {browser}')
    
    if browser == 'chrome':
        chrome_options = ChromeOptions()
        chrome_options.add_argument('--headless')
        chrome_options.add_argument('--disable-gpu')
        chrome_options.add_argument('--no-sandbox')
        chrome_options.add_argument('--disable-dev-shm-usage')
        driver = webdriver.Chrome(service=ChromeService(ChromeDriverManager().install()), options=chrome_options)
    elif browser == 'firefox':
        firefox_options = FirefoxOptions()
        firefox_options.add_argument('--headless')
        driver = webdriver.Firefox(service=FirefoxService(GeckoDriverManager().install()), options=firefox_options)
    
    try:
        driver.get(url)
        time.sleep(3)
        
        # کاراکترهای کلیدی برای بررسی Reflected XSS
        key_chars = ['<', '>', '"', "'"]
        
        # بررسی وجود کاراکترهای کلیدی در صفحه
        page_source = driver.page_source
        if any(char in page_source for char in key_chars):
            logging.warning(f'Potential reflected XSS vulnerability found at: {url}')
        else:
            logging.info(f'No reflected XSS vulnerability found at: {url}')
        
        # بررسی رفلکت شدن مقادیر پارامترها در event handlerها
        event_handlers = ['onclick', 'onload', 'onerror', 'onchange', 'onmouseover', 'onfocus']
        for handler in event_handlers:
            if handler in page_source:
                logging.warning(f'Potential reflected XSS vulnerability found in event handlers at: {url}')
                break

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
            test_urls = generate_test_urls(url, params)
            for test_url in test_urls:
                check_xss(test_url, args.browser)
        else:
            logging.info(f'No parameters found in {url}')

if __name__ == '__main__':
    main()