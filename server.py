from http.server import BaseHTTPRequestHandler, HTTPServer
import urllib.parse as urlparse
import requests
import re
from bs4 import BeautifulSoup
from urllib.parse import urljoin


class RequestHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        print(f"Received request for path: {self.path}")
        if self.path == '/':
            self.send_response(200)
            self.send_header('Content-type', 'text/html')
            self.end_headers()
            with open('form.html', 'r', encoding='utf-8') as file:
                form_content = file.read()
            self.wfile.write(form_content.encode('utf-8'))
        elif self.path.startswith('/scan'):
            query = urlparse.urlparse(self.path).query
            params = urlparse.parse_qs(query)
            url_to_scan = params.get('url', [None])[0]

            if url_to_scan:
                print(f"Scanning URL: {url_to_scan}")
                vulnerabilities = self.scan_website(url_to_scan)
                self.send_response(200)
                self.send_header('Content-type', 'text/html')
                self.end_headers()
                self.wfile.write(self.display_results(url_to_scan, vulnerabilities).encode('utf-8'))
            else:
                self.send_response(400)
                self.end_headers()
                self.wfile.write(b'Error: No URL provided.')
        else:
            self.send_response(404)
            self.end_headers()
            self.wfile.write(b'404 Not Found')

    def display_results(self, url, vulnerabilities):
        results = f'''
            <html>
                <head>
                    <title>Scan Results for {url}</title>
                    <style>
                        body {{
                            font-family: 'Courier New', monospace;
                            background-color: #0b0b0b;
                            color: #33ff33;
                            margin: 0;
                            padding: 20px;
                        }}
                        h1 {{
                            color: #33ff33;
                            text-align: center;
                            text-shadow: 0 0 10px #00ff00;
                        }}
                        .results {{
                            margin-top: 20px;
                            background: #1c1c1c;
                            padding: 20px;
                            border-radius: 5px;
                            box-shadow: 0 2px 10px rgba(0, 0, 0, 0.5);
                        }}
                        ul {{
                            list-style-type: none;
                            padding: 0;
                        }}
                        li {{
                            margin: 10px 0;
                            padding: 10px;
                            border: 1px solid #33ff33;
                            border-radius: 5px;
                            background-color: #0b0b0b;
                        }}
                    </style>
                </head>
                <body>
                    <h1>Scan Results for {url}</h1>
        '''
        if vulnerabilities:
            results += '<ul>'
            for page_url, vulns in vulnerabilities.items():
                results += f'<li><strong>URL:</strong> {page_url}<br>'
                for vulnerability, attack_method in vulns.items():
                    results += f'<strong>Vulnerability:</strong> {vulnerability}<br>'
                    results += f'<strong>Attack Method:</strong> {attack_method}<br></li>'
            results += '</ul>'
        else:
            results += '<p>No vulnerabilities found.</p>'

        results += '</body></html>'
        return results

    def scan_website(self, url):
        vulnerabilities = {}
        discovered_urls = self.discover_urls(url)

        for page_url in discovered_urls:
            found_vulns = self.scan_url(page_url)
            if found_vulns:
                vulnerabilities[page_url] = found_vulns

        return vulnerabilities

    def discover_urls(self, url):
        discovered_urls = []
        try:
            response = requests.get(url)
            if response.status_code == 200:
                soup = BeautifulSoup(response.text, "html.parser")
                for anchor_tag in soup.find_all("a"):
                    href = anchor_tag.get("href")
                    if href:
                        absolute_url = urljoin(url, href)
                        discovered_urls.append(absolute_url)
            else:
                print(f"Failed to retrieve {url}: {response.status_code}")
        except Exception as e:
            print(f"Error during URL discovery: {str(e)}")
        return discovered_urls

    def scan_url(self, url):
        vulnerabilities = {}
        if self.is_sql_injection_vulnerable(url):
            vulnerabilities["SQL injection vulnerability"] = "Injecting SQL code into input fields"
        if self.is_xss_vulnerable(url):
            vulnerabilities["Cross-site scripting (XSS) vulnerability"] = "Injecting malicious scripts into input fields"
        if self.has_insecure_configuration(url):
            vulnerabilities["Insecure server configuration"] = "Exploiting insecure communication protocols"
        return vulnerabilities

    def is_sql_injection_vulnerable(self, url):
        payload = "' OR '1'='1"
        try:
            response = requests.get(url + "?id=" + payload)
            if re.search(r"error|warning", response.text, re.IGNORECASE):
                return True
        except Exception as e:
            print(f"Error checking SQL injection on {url}: {str(e)}")
        return False

    def is_xss_vulnerable(self, url):
        payload = "<script>alert('XSS')</script>"
        try:
            response = requests.get(url + "?input=" + payload)
            if payload in response.text:
                return True
        except Exception as e:
            print(f"Error checking XSS on {url}: {str(e)}")
        return False

    def has_insecure_configuration(self, url):
        return not url.startswith("https")


def run(server_class=HTTPServer, handler_class=RequestHandler, port=8000):
    server_address = ('', port)
    httpd = server_class(server_address, handler_class)
    print(f'Starting httpd server on port {port}...')
    httpd.serve_forever()


if __name__ == "__main__":
    run()

