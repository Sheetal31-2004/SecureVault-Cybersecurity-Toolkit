import socket
import requests
import ssl
import whois
import socket
import dns.resolver
from ipwhois import IPWhois
from datetime import datetime

COMMON_SERVICES = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    143: "IMAP",
    443: "HTTPS",
    3306: "MySQL",
    3389: "RDP",
    8080: "HTTP-ALT"
}

def simple_port_scan(host, ports=None):

    if ports is None:
        ports = [21, 22, 23, 80, 443, 8080]

    open_ports = []

    for port in ports:
        try:
            with socket.create_connection(
                (host, port),
                timeout=1
            ):
                open_ports.append(port)

        except:
            pass

    return open_ports

def identify_services(open_ports):

    services = []

    for port in open_ports:

        service = COMMON_SERVICES.get(
            port,
            "Unknown Service"
        )

        services.append(
            f"{port} - {service}"
        )

    return services

def banner_grab(target):

    banners = []

    try:

        if not target.startswith("http://") and not target.startswith("https://"):
            target = "http://" + target

        response = requests.get(
            target,
            timeout=5
        )

        server = response.headers.get(
            "Server",
            "Unknown"
        )

        powered_by = response.headers.get(
            "X-Powered-By",
            "Hidden"
        )

        content_type = response.headers.get(
            "Content-Type",
            "Unknown"
        )

        banners.append(f"Server: {server}")
        banners.append(f"Technology: {powered_by}")
        banners.append(f"Content-Type: {content_type}")

        # ADD THIS PART HERE
        html = response.text.lower()

        if "wordpress" in html:
            banners.append("CMS: WordPress")

        if "jquery" in html:
            banners.append("JavaScript Library: jQuery")

        if "bootstrap" in html:
            banners.append("Frontend Framework: Bootstrap")

        if "react" in html:
            banners.append("Frontend Framework: React")

    except Exception as e:

        banners.append(
            f"Banner Grab Failed: {str(e)}"
        )

    return banners

def ssl_analysis(host):

    results = []

    try:

        context = ssl.create_default_context()

        with context.wrap_socket(
            socket.socket(),
            server_hostname=host
        ) as s:

            s.settimeout(5)
            s.connect((host, 443))
            
            tls_version = s.version()
            results.append(
                f"TLS Version: {tls_version}"
            )
            if tls_version == "TLSv1.3":
                results.append("TLS Security: EXCELLENT")

            elif tls_version == "TLSv1.2":
                results.append("TLS Security: GOOD")

            else:
                results.append("TLS Security: WEAK")
                results.append(
                f"TLS Version: {tls_version}"
            )
            cert = s.getpeercert()

            issuer = dict(
                x[0] for x in cert['issuer']
            )

            issuer_name = issuer.get(
                'organizationName',
                'Unknown'
            )

            expiry = cert['notAfter']

            expiry_date = datetime.strptime(
                expiry,
                "%b %d %H:%M:%S %Y %Z"
            )

            days_left = (
                expiry_date - datetime.utcnow()
            ).days

            results.append(
                "[+] SSL Certificate: VALID"
            )

            results.append(
                f"Issuer: {issuer_name}"
            )

            results.append(
                f"Expires: {expiry_date.strftime('%d-%b-%Y')}"
            )

            results.append(
                f"Days Remaining: {days_left}"
            )

    except Exception as e:

        results.append(
            f"[!] SSL Analysis Failed: {str(e)}"
        )

    return results

def check_http_headers(url):
    results = []
    try:
        if not url.startswith("http://") and not url.startswith("https://"):
            url = "https://" + url

        response = requests.get(url, timeout=5)
        headers = response.headers

        security_headers = {
            'X-Frame-Options': "Prevents clickjacking",
            'X-XSS-Protection': "Helps detect cross-site scripting",
            'Content-Security-Policy': "Mitigates cross-site scripting",
            'Strict-Transport-Security': "Enforces HTTPS",
            'Referrer-Policy': "Controls referrer info sent",
            'Permissions-Policy': "Restricts browser features"
        }

        for header, description in security_headers.items():
            if header in headers:
                results.append(f"[+] {header}: ✅ Present")
            else:
                results.append(f"[-] {header}: ❌ Missing ({description})")

    except requests.exceptions.RequestException as e:
        results.append(f"[!] Failed to fetch headers from {url}. Error: {str(e)}")

    return results

def website_information(target):

    import requests
    import time
    import re

    info = {}

    try:

        if not target.startswith("http://") and not target.startswith("https://"):
            target = "https://" + target

        start = time.time()

        response = requests.get(
            target,
            timeout=10
        )

        end = time.time()

        info["url"] = response.url
        info["status"] = response.status_code
        info["protocol"] = response.url.split(":")[0].upper()
        info["server"] = response.headers.get("Server", "Unknown")
        info["content_type"] = response.headers.get("Content-Type", "Unknown")
        info["content_length"] = len(response.text)
        info["response_time"] = round(end - start, 3)
        info["reachable"] = "Yes"
        info["redirects"] = len(response.history)
        info["last_modified"] = response.headers.get(
            "Last-Modified",
            "Not Available"
        )
        info["powered_by"] = response.headers.get(
            "X-Powered-By",
            "Hidden"
        )

        html = response.text

        title = re.search(
            r"<title>(.*?)</title>",
            html,
            re.IGNORECASE | re.DOTALL
        )

        if title:
            info["title"] = title.group(1).strip()
        else:
            info["title"] = "Unknown"

    except Exception as e:

        info["title"] = "Unknown"
        info["url"] = target
        info["status"] = "N/A"
        info["protocol"] = "N/A"
        info["server"] = "Unknown"
        info["content_type"] = "Unknown"
        info["content_length"] = "Unknown"
        info["response_time"] = "Unknown"
        info["reachable"] = "No"
        info["redirects"] = 0
        info["last_modified"] = "Unknown"
        info["powered_by"] = "Unknown"

        print("Website Information Error:", e)

    return info

def domain_information(target):

    info = {}

    try:

        target = target.replace("https://", "")
        target = target.replace("http://", "")
        target = target.split("/")[0]

        info["domain"] = target

        # Public IP
        ip = socket.gethostbyname(target)
        info["ip"] = ip

        # Reverse DNS
        try:
            info["reverse_dns"] = socket.gethostbyaddr(ip)[0]
        except:
            info["reverse_dns"] = "Not Available"

        # WHOIS
        w = whois.whois(target)

        info["registrar"] = w.registrar

        info["creation_date"] = w.creation_date

        info["expiration_date"] = w.expiration_date

        # Name Servers
        try:
            info["name_servers"] = ", ".join(w.name_servers)
        except:
            info["name_servers"] = "Unknown"

        # ASN
        obj = IPWhois(ip)

        res = obj.lookup_rdap()

        info["organization"] = res["network"]["name"]

        info["country"] = res["network"]["country"]

    except Exception as e:

        info["domain"] = target

        info["ip"] = "Unknown"

        info["registrar"] = "Unknown"

        info["creation_date"] = "Unknown"

        info["expiration_date"] = "Unknown"

        info["name_servers"] = "Unknown"

        info["organization"] = "Unknown"

        info["country"] = "Unknown"

        info["reverse_dns"] = "Unknown"

        print(e)

    return info