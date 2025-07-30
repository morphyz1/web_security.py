import urllib.request
import urllib.error
import ssl
import socket
import sys

def check_ssl(url):
    """
    Check if a website uses HTTPS and verify its SSL certificate.
    """
    try:
        # Validate URL
        if not url.startswith("https://"):
            print(f"Error: {url} does not use HTTPS")
            return False

        # Check HTTPS connection
        with urllib.request.urlopen(url, timeout=10) as response:
            if response.getcode() == 200:
                print(f"{url} is using HTTPS successfully")

        # Verify SSL certificate
        hostname = url.split("://")[1].split("/")[0]
        context = ssl.create_default_context()
        with socket.create_connection((hostname, 443)) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                print(f"SSL Certificate for {hostname}:")
                print(f"  Subject: {cert['subject']}")
                print(f"  Issuer: {cert['issuer']}")
                print(f"  Expiry: {cert['notAfter']}")
                return True
    except urllib.error.URLError as e:
        print(f"SSL check failed for {url}: {e}")
        return False
    except socket.gaierror:
        print(f"Error: Could not resolve hostname for {url}")
        return False
    except Exception as e:
        print(f"Unexpected error during SSL check: {e}")
        return False

def simulate_vulnerability_scan(url):
    """
    Simulate a basic web vulnerability scan
    """
    try:
        print(f"Simulating vulnerability scan for {url}")
        # Mock vulnerabilities for demonstration
        mock_vulnerabilities = [
            {"issue": "Missing Content-Security-Policy header", "severity": "Medium"},
            {"issue": "XSS vulnerability in input field", "severity": "High"}
        ]
        if mock_vulnerabilities:
            print("Vulnerabilities found:")
            for vuln in mock_vulnerabilities:
                print(f"  - {vuln['issue']} (Severity: {vuln['severity']})")
        else:
            print("No vulnerabilities found.")
    except Exception as e:
        print(f"Error during vulnerability scan: {e}")

def main():
    """
    Main function to run web security checks.
    """
    target_url = input("Enter target URL (e.g., https://example.com): ").strip()
    print(f"\nStarting web security assessment for {target_url}")
    print("=" * 50)
    
    # Run SSL check
    print("\nChecking SSL/HTTPS configuration...")
    ssl_result = check_ssl(target_url)
    
    # Run vulnerability scan
    if ssl_result:
        print("\nRunning vulnerability scan...")
        simulate_vulnerability_scan(target_url)
    else:
        print("\nSkipping vulnerability scan due to SSL check failure.")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nProgram terminated by user.")
        sys.exit(0)
    except Exception as e:
        print(f"Unexpected error: {e}")
        sys.exit(1)
