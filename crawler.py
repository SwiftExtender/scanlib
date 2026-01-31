import sqlite3
import requests
from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.chrome.service import Service
from webdriver_manager.chrome import ChromeDriverManager
from datetime import datetime
import time
import os
import sys

def create_database(db_file):
    conn = sqlite3.connect(db_file)
    c = conn.cursor()
    c.execute('''
        CREATE TABLE IF NOT EXISTS pages (
            id INTEGER PRIMARY KEY,
            url TEXT NOT NULL,
            final_url TEXT,
            headers TEXT,
            screenshot BLOB,
            timestamp DATETIME
        )
    ''')
    conn.commit()
    conn.close()

def process_urls(input_file, db_file):
    # Setup Chrome options
    chrome_options = Options()
    chrome_options.add_argument("--headless=new")
    chrome_options.add_argument("--disable-gpu")
    chrome_options.add_argument("--no-sandbox")
    chrome_options.add_argument("--disable-dev-shm-usage")
    chrome_options.add_argument("--ignore-certificate-errors")    
    # Setup WebDriver
    driver = webdriver.Chrome(
        service=Service(ChromeDriverManager().install()),
        options=chrome_options
    )
    
    conn = sqlite3.connect(db_file)
    c = conn.cursor()
    
    with open(input_file, 'r') as file:
        urls = [line.strip() for line in file.readlines() if line.strip()]
        
        for url in urls:
            if not url.startswith(('http://', 'https://')):
                url = 'http://' + url
                
            print(f"Processing: {url}")
            final_url = url
            headers = {}
            screenshot = None
            
            try:
                # Get headers with requests
                response = requests.get(url, timeout=15, allow_redirects=True, verify=False)
                final_url = response.url
                headers = dict(response.headers)
                
                # Get screenshot with Selenium
                driver.get(url)
                time.sleep(3)  # Allow page rendering
                
                # Calculate full page dimensions
                total_width = driver.execute_script("return document.body.scrollWidth")
                total_height = driver.execute_script("return document.body.scrollHeight")
                driver.set_window_size(total_width, total_height)
                
                # Capture screenshot as PNG
                screenshot = driver.get_screenshot_as_png()
                
                # Save to database
                c.execute('''
                    INSERT INTO pages (url, final_url, headers, screenshot, timestamp)
                    VALUES (?, ?, ?, ?, ?)
                ''', (
                    url,
                    final_url,
                    str(headers),
                    screenshot,
                    datetime.now().isoformat()
                ))
                conn.commit()
                print(f"✅ Success: {url}")
                
            except Exception as e:
                print(f"❌ Failed: {url} - {str(e)}")
    
    driver.quit()
    conn.close()

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Usage: python script.py <input_file.txt> <output_db.db>")
        sys.exit(1)
    
    input_file = sys.argv[1]
    db_file = sys.argv[2]
    
    if not os.path.exists(input_file):
        print(f"Error: Input file '{input_file}' not found")
        sys.exit(1)
    
    create_database(db_file)
    process_urls(input_file, db_file)
    print(f"\nProcessing complete. Database saved to: {db_file}")
