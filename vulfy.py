import os
import sys
import subprocess
import re
from colorama import init, Fore, Style
import socket
from urllib.parse import urlparse

init(autoreset=True)

class Vulfy:
    def __init__(self):
        """Initialize the scanner"""
        self.menu_options = {
            "1": "Nmap Port Scan",
            "2": "Nikto Web Vulnerability Scan",
            "3": "SQL Injection Testing",
            "4": "SSL/TLS Security Scan",
            "5": "Directory Brute Force",
            "6": "XSS Vulnerability Scan",
            "7": "Subdomain Enumeration",
            "8": "DNS Analysis",
            "9": "Header Security Check",
            "10": "Full Scan (All Tests)",
            "11": "About Us",
            "12": "Exit"
        }
        self.target = ""
        self.is_ip = False
        self.recommendations = []

    def add_recommendation(self, category, recommendation):
        """Add a security recommendation to the list"""
        self.recommendations.append({
            'category': category,
            'recommendation': recommendation
        })

    def display_all_recommendations(self):
        """Display all collected security recommendations"""
        if not self.recommendations:
            print(Fore.YELLOW + "\nNo security recommendations found.")
            return

        print(Fore.CYAN + "\nSecurity Recommendations Summary:")
        print("="*50)
        
        # Group recommendations by category
        grouped_recommendations = {}
        for rec in self.recommendations:
            category = rec['category']
            if category not in grouped_recommendations:
                grouped_recommendations[category] = []
            grouped_recommendations[category].append(rec['recommendation'])
        
        # Display recommendations by category
        for category, recs in grouped_recommendations.items():
            print(Fore.YELLOW + f"\n{category}:")
            print("-"*30)
            for i, rec in enumerate(recs, 1):
                print(f"{Fore.GREEN}[{i}] {rec}")
        
        print("="*50)
        print(Fore.YELLOW + "\nNote: These recommendations are based on scan results and should be reviewed by security experts before implementation.")
        print("="*50)

    def get_target(self):
        """Get target from user"""
        while True:
            target = input("\nEnter target (IP address or URL): ").strip()
            if self.validate_target(target):
                self.target = target
                break
            else:
                print(Fore.RED + "Invalid target. Please enter a valid IP address or URL.")

    def validate_target(self, target):
        """Validate if the target is a valid IP or URL"""
        try:
            # Check if IP address
            socket.inet_aton(target)
            self.is_ip = True
            return True
        except socket.error:
            # Check if URL
            try:
                result = urlparse(target)
                if not result.scheme:
                    # If no scheme is provided, add http:// by default
                    target = f"http://{target}"
                    result = urlparse(target)
                
                if not result.netloc:
                    print(Fore.RED + "Invalid URL format. Please provide a valid domain or IP address.")
                    print(Fore.YELLOW + "Examples:")
                    print(Fore.YELLOW + "• IP Address: 192.168.1.1")
                    print(Fore.YELLOW + "• Domain: www.example.com")
                    print(Fore.YELLOW + "• URL: https://example.com")
                    return False
                
                self.target = target
                return True
            except Exception as e:
                print(Fore.RED + f"Invalid URL format: {str(e)}")
                print(Fore.YELLOW + "Please provide a valid domain or IP address.")
                print(Fore.YELLOW + "Examples:")
                print(Fore.YELLOW + "• IP Address: 192.168.1.1")
                print(Fore.YELLOW + "• Domain: www.example.com")
                print(Fore.YELLOW + "• URL: https://example.com")
                return False

    def get_target(self):
        """Get target from user"""
        while True:
            target = input("\nEnter target (IP address or URL): ").strip()
            if self.validate_target(target):
                self.target = target
                break
            else:
                print(Fore.RED + "Invalid target. Please enter a valid IP address or URL.")

    def display_menu(self):
        """Display main menu"""
        print("\n" + "="*50)
        print(Fore.CYAN + " VULFY - Full Stack Vulnerability Scanner ")
        print("="*50)
        print(Fore.YELLOW + " Created by: VulnSeekers Team")
        print(" Version: 1.0.0")
        print("="*50)
        print(Fore.YELLOW + "\nFollow me on GitHub: https://github.com/KiraxD")
        print("="*50)
        print("\nAvailable Scans:")
        for key, value in self.menu_options.items():
            print(f"{Fore.YELLOW}[{key}]{Style.RESET_ALL} {value}")
        
    def run_nmap_scan(self):
        """Run Nmap port scan"""
        print(Fore.GREEN + "\nStarting Nmap Port Scan...")
        try:
            if self.is_ip:
                cmd = ["nmap", "-sS", "-sV", "-O", self.target]
            else:
                cmd = ["nmap", "-sS", "-sV", "-O", "-Pn", self.target]
            
            result = subprocess.run(cmd, capture_output=True, text=True)
            print(Fore.GREEN + "\nNmap Scan Results:")
            print(result.stdout)
            
            # Parse and explain findings
            self.explain_nmap_results(result.stdout)
            
        except Exception as e:
            print(Fore.RED + f"Error running Nmap scan: {str(e)}")

    def explain_nmap_results(self, results):
        """Explain Nmap scan findings in plain language"""
        print(Fore.YELLOW + "\nSecurity Recommendations:")
        if "open" in results:
            print(Fore.YELLOW + "• Open ports detected. Consider implementing firewall rules.")
        if "vuln" in results:
            print(Fore.RED + "• Vulnerable services detected. Update and patch these services.")
        if "OS" in results:
            print(Fore.YELLOW + "• OS fingerprinting possible. Consider implementing OS obfuscation.")

    def run_nikto_scan(self):
        """Run Nikto web vulnerability scan"""
        print(Fore.GREEN + "\nStarting Nikto Web Vulnerability Scan...")
        try:
            cmd = ["nikto", "-h", self.target, "-C", "all"]  # Add cookie testing
            result = subprocess.run(cmd, capture_output=True, text=True)
            print(Fore.GREEN + "\nNikto Scan Results:")
            print(result.stdout)
            
            # Parse and explain findings
            self.explain_nikto_results(result.stdout)
            
        except Exception as e:
            print(Fore.RED + f"Error running Nikto scan: {str(e)}")

    def run_ssl_scan(self):
        """Run SSL/TLS security scan"""
        print(Fore.GREEN + "\nStarting SSL/TLS Security Scan...")
        try:
            cmd = ["sslyze", "--regular", self.target]
            result = subprocess.run(cmd, capture_output=True, text=True)
            print(Fore.GREEN + "\nSSL/TLS Scan Results:")
            print(result.stdout)
            
            self.explain_ssl_results(result.stdout)
            
        except Exception as e:
            print(Fore.RED + f"Error running SSL scan: {str(e)}")

    def explain_ssl_results(self, results):
        """Explain SSL scan findings"""
        print(Fore.YELLOW + "\nSecurity Recommendations:")
        if "SSLv2" in results:
            print(Fore.RED + "• SSLv2 protocol detected!")
            print(Fore.YELLOW + "• Disable SSLv2 and use TLS 1.2 or higher.")
        if "RC4" in results:
            print(Fore.RED + "• Weak RC4 cipher detected!")
            print(Fore.YELLOW + "• Disable RC4 and use AES ciphers.")
        if "Heartbleed" in results:
            print(Fore.RED + "• Heartbleed vulnerability detected!")
            print(Fore.YELLOW + "• Update OpenSSL immediately.")

    def explain_nikto_results(self, results):
        """Explain Nikto scan findings in plain language"""
        print(Fore.YELLOW + "\nSecurity Recommendations:")
        if "vulnerability" in results.lower():
            print(Fore.RED + "• Web application vulnerabilities detected.")
            print(Fore.YELLOW + "• Update web server software and plugins.")
            print(Fore.YELLOW + "• Implement proper input validation.")
        if "outdated" in results.lower():
            print(Fore.RED + "• Outdated components detected.")
            print(Fore.YELLOW + "• Update all web components immediately.")

    def run_sqlmap_scan(self):
        """Run SQLMap injection test"""
        print(Fore.GREEN + "\nStarting SQL Injection Testing...")
        try:
            cmd = ["sqlmap", "-u", self.target, "--batch"]
            result = subprocess.run(cmd, capture_output=True, text=True)
            print(Fore.GREEN + "\nSQLMap Scan Results:")
            print(result.stdout)
            
            # Parse and explain findings
            self.explain_sqlmap_results(result.stdout)
            
        except Exception as e:
            print(Fore.RED + f"Error running SQLMap scan: {str(e)}")

    def run_dirb_scan(self):
        """Run directory brute force scan"""
        print(Fore.GREEN + "\nStarting Directory Brute Force...")
        try:
            cmd = ["dirb", self.target]
            result = subprocess.run(cmd, capture_output=True, text=True)
            print(Fore.GREEN + "\nDirectory Scan Results:")
            print(result.stdout)
            
            self.explain_dirb_results(result.stdout)
            
        except Exception as e:
            print(Fore.RED + f"Error running directory scan: {str(e)}")

    def explain_dirb_results(self, results):
        """Explain directory scan findings"""
        print(Fore.YELLOW + "\nSecurity Recommendations:")
        if "+" in results:
            print(Fore.RED + "• Hidden directories found!")
            print(Fore.YELLOW + "• Remove unnecessary directories.")
            print(Fore.YELLOW + "• Implement proper access controls.")
            print(Fore.YELLOW + "• Use proper .htaccess restrictions.")

    def explain_sqlmap_results(self, results):
        """Explain SQLMap findings in plain language"""
        print(Fore.YELLOW + "\nSecurity Recommendations:")
        if "vulnerable" in results.lower():
            print(Fore.RED + "• SQL injection vulnerability detected!")
            print(Fore.YELLOW + "• Implement proper input validation.")
            print(Fore.YELLOW + "• Use prepared statements in database queries.")
            print(Fore.YELLOW + "• Enable WAF (Web Application Firewall).")

    def run_header_scan(self):
        """Run security header analysis"""
        print(Fore.GREEN + "\nStarting Header Security Check...")
        try:
            import requests
            response = requests.get(self.target)
            headers = response.headers
            print(Fore.GREEN + "\nSecurity Headers Analysis:")
            self.explain_header_results(headers)
            
        except Exception as e:
            print(Fore.RED + f"Error running header scan: {str(e)}")

    def explain_header_results(self, headers):
        """Explain security header findings"""
        print(Fore.YELLOW + "\nSecurity Recommendations:")
        security_headers = [
            "Strict-Transport-Security",
            "Content-Security-Policy",
            "X-Frame-Options",
            "X-Content-Type-Options",
            "Referrer-Policy",
            "Permissions-Policy"
        ]
        
        missing_headers = [h for h in security_headers if h not in headers]
        if missing_headers:
            print(Fore.RED + f"• Missing security headers: {', '.join(missing_headers)}")
            print(Fore.YELLOW + "• Add missing security headers to improve security.")

    def run_xss_scan(self):
        """Run XSS vulnerability scan"""
        print(Fore.GREEN + "\nStarting XSS Vulnerability Scan...")
        try:
            import requests
            from bs4 import BeautifulSoup
            
            # Get the page content
            response = requests.get(self.target)
            soup = BeautifulSoup(response.text, 'html.parser')
            
            # Find potential XSS vectors
            inputs = soup.find_all(['input', 'textarea'])
            scripts = soup.find_all('script')
            
            print(Fore.GREEN + "\nXSS Scan Results:")
            
            if inputs:
                print(Fore.YELLOW + "\nPotential XSS Vectors Found:")
                for i, input in enumerate(inputs, 1):
                    print(f"{Fore.YELLOW}[{i}] {Fore.GREEN}Input field: {input.get('name', 'Unnamed')}")
                    print(f"{Fore.YELLOW}Type: {Fore.GREEN}{input.get('type', 'text')}")
                    print(f"{Fore.YELLOW}Location: {Fore.GREEN}{input.get('id', 'No ID')}\n")
                    self.add_recommendation(
                        "XSS Protection",
                        f"Validate and sanitize input field: {input.get('name', 'Unnamed')}"
                    )
            
            if scripts:
                print(Fore.YELLOW + "\nPotential XSS Scripts Found:")
                for i, script in enumerate(scripts, 1):
                    print(f"{Fore.YELLOW}[{i}] {Fore.GREEN}Script found")
                    print(f"{Fore.YELLOW}Location: {Fore.GREEN}{script.get('src', 'Inline script')}\n")
                    self.add_recommendation(
                        "XSS Protection",
                        f"Review and secure script at location: {script.get('src', 'Inline script')}"
                    )
            
            # Add general XSS recommendations
            self.add_recommendation(
                "XSS Protection",
                "Implement Content Security Policy (CSP) to prevent XSS attacks"
            )
            self.add_recommendation(
                "XSS Protection",
                "Use proper HTML escaping for all user inputs"
            )
            self.add_recommendation(
                "XSS Protection",
                "Implement input validation and sanitization"
            )
            
        except Exception as e:
            print(Fore.RED + f"Error running XSS scan: {str(e)}")
            self.add_recommendation(
                "XSS Protection",
                "Error occurred during XSS scan - review application security"
            )

    def explain_xss_results(self):
        """Explain XSS scan findings"""
        print(Fore.YELLOW + "\nSecurity Recommendations:")
        print(Fore.RED + "• Input Validation:")
        print(Fore.YELLOW + "• Always validate and sanitize user inputs")
        print(Fore.YELLOW + "• Use proper encoding for output")
        print(Fore.YELLOW + "• Implement Content Security Policy (CSP)")
        print(Fore.RED + "\n• Output Encoding:")
        print(Fore.YELLOW + "• Use proper HTML escaping")
        print(Fore.YELLOW + "• Implement XSS filters")
        print(Fore.YELLOW + "• Use modern security headers")

    def run_subdomain_scan(self):
        """Run subdomain enumeration"""
        print(Fore.GREEN + "\nStarting Subdomain Enumeration...")
        try:
            import requests
            from requests.exceptions import RequestException
            
            # Basic subdomain list
            subdomains = ['www', 'admin', 'mail', 'ftp', 'test', 'dev', 'api', 'blog', 'cdn']
            found_subdomains = []
            
            print(Fore.GREEN + "\nSubdomain Scan Results:")
            
            for sub in subdomains:
                try:
                    url = f"http://{sub}.{self.target}"
                    response = requests.get(url, timeout=3)
                    if response.status_code < 400:
                        found_subdomains.append(f"{sub}.{self.target}")
                except RequestException:
                    continue
            
            if found_subdomains:
                print(Fore.YELLOW + "\nFound Subdomains:")
                for i, sub in enumerate(found_subdomains, 1):
                    print(f"{Fore.YELLOW}[{i}] {Fore.GREEN}{sub}")
            else:
                print(Fore.YELLOW + "No active subdomains found")
            
            self.explain_subdomain_results()
            
        except Exception as e:
            print(Fore.RED + f"Error running subdomain scan: {str(e)}")

    def explain_subdomain_results(self):
        """Explain subdomain scan findings"""
        print(Fore.YELLOW + "\nSecurity Recommendations:")
        print(Fore.RED + "• Subdomain Management:")
        print(Fore.YELLOW + "• Remove unused subdomains")
        print(Fore.YELLOW + "• Implement proper DNS security")
        print(Fore.YELLOW + "• Use DNSSEC if possible")
        print(Fore.RED + "\n• Monitoring:")
        print(Fore.YELLOW + "• Regularly scan for new subdomains")
        print(Fore.YELLOW + "• Monitor subdomain activity")
        print(Fore.YELLOW + "• Implement proper access controls")

    def run_dns_scan(self):
        """Run DNS analysis"""
        print(Fore.GREEN + "\nStarting DNS Analysis...")
        try:
            import dns.resolver
            
            print(Fore.GREEN + "\nDNS Scan Results:")
            print(Fore.YELLOW + "\nDNS Records:")
            
            # Check A records
            try:
                answers = dns.resolver.resolve(self.target, 'A')
                print(Fore.YELLOW + "\nA Records:")
                for rdata in answers:
                    print(f"{Fore.GREEN}{rdata}")
            except:
                print(Fore.RED + "No A records found")
            
            # Check MX records
            try:
                answers = dns.resolver.resolve(self.target, 'MX')
                print(Fore.YELLOW + "\nMX Records:")
                for rdata in answers:
                    print(f"{Fore.GREEN}{rdata}")
            except:
                print(Fore.RED + "No MX records found")
            
            # Check TXT records
            try:
                answers = dns.resolver.resolve(self.target, 'TXT')
                print(Fore.YELLOW + "\nTXT Records:")
                for rdata in answers:
                    print(f"{Fore.GREEN}{rdata}")
            except:
                print(Fore.RED + "No TXT records found")
            
            # Check NS records
            try:
                answers = dns.resolver.resolve(self.target, 'NS')
                print(Fore.YELLOW + "\nNS Records:")
                for rdata in answers:
                    print(f"{Fore.GREEN}{rdata}")
            except:
                print(Fore.RED + "No NS records found")
            
            self.explain_dns_results()
            
        except Exception as e:
            print(Fore.RED + f"Error running DNS scan: {str(e)}")

    def explain_dns_results(self):
        """Explain DNS scan findings"""
        print(Fore.YELLOW + "\nSecurity Recommendations:")
        print(Fore.RED + "• DNS Security:")
        print(Fore.YELLOW + "• Implement DNSSEC")
        print(Fore.YELLOW + "• Use DNS over HTTPS/TLS")
        print(Fore.YELLOW + "• Regularly update DNS records")
        print(Fore.RED + "\n• DNS Configuration:")
        print(Fore.YELLOW + "• Use proper DNS record TTL")
        print(Fore.YELLOW + "• Implement proper DNS caching")
        print(Fore.YELLOW + "• Use DNS monitoring")
        print(Fore.RED + "\n• DNS Records:")
        print(Fore.YELLOW + "• Keep DNS records up to date")
        print(Fore.YELLOW + "• Remove unused DNS records")
        print(Fore.YELLOW + "• Implement proper DNS access controls")

    def run_full_scan(self):
        """Run all scans sequentially and collect recommendations"""
        print(Fore.CYAN + "\nStarting Full Security Scan...")
        scans = [
            self.run_nmap_scan,
            self.run_nikto_scan,
            self.run_sqlmap_scan,
            self.run_ssl_scan,
            self.run_dirb_scan,
            self.run_xss_scan,
            self.run_subdomain_scan,
            self.run_dns_scan,
            self.run_header_scan
        ]
        
        # Run all scans and collect recommendations
        for scan in scans:
            try:
                scan()
            except Exception as e:
                print(Fore.RED + f"Error in {scan.__name__}: {str(e)}")
                continue
        
        # Display all collected recommendations
        print(Fore.CYAN + "\nSecurity Recommendations Summary:")
        print("="*50)
        
        # Group recommendations by category
        grouped_recommendations = {}
        for rec in self.recommendations:
            category = rec['category']
            if category not in grouped_recommendations:
                grouped_recommendations[category] = []
            grouped_recommendations[category].append(rec['recommendation'])
        
        # Display recommendations by category
        for category, recs in grouped_recommendations.items():
            print(Fore.YELLOW + f"\n{category}:")
            print("-"*30)
            for i, rec in enumerate(recs, 1):
                print(f"{Fore.GREEN}[{i}] {rec}")
        
        print("="*50)
        print(Fore.YELLOW + "\nNote: These recommendations are based on scan results and should be reviewed by security experts before implementation.")
        print("="*50)
        print(Fore.GREEN + "\nFull scan completed!")

    def show_about_us(self):
        """Display information about the development team"""
        print("\n" + "="*50)
        print(Fore.CYAN + " About VulnSeekers Team ")
        print("="*50)
        print(Fore.YELLOW + "\nLead Developer:")
        print(Fore.GREEN + "1. Reshob Roychoudhury (Kira xD)")
        print(Fore.YELLOW + "\n Core Helper Team:")
        print(Fore.GREEN + "2. Swarnim Kumar")
        print(Fore.GREEN + "3. Shruti Rani")
        print(Fore.GREEN + "4. Sagar Sardana")
        print(Fore.GREEN + "5. Kunal Sharma")
        print(Fore.GREEN + "6. Devjeet Behera")
        print("\n" + "="*50)
        print(Fore.YELLOW + "Thank you for using VulnSeekers!")
        print("Created by the VulnSeekers team")
        print("="*50)
        input("\nPress Enter to return to the main menu...")

    def main(self):
        """Main program loop"""
        while True:
            self.display_menu()
            choice = input("\nSelect an option (1-12): ").strip()
            
            if choice == "1":
                self.get_target()
                self.run_nmap_scan()
            elif choice == "2":
                self.get_target()
                self.run_nikto_scan()
            elif choice == "3":
                self.get_target()
                self.run_sqlmap_scan()
            elif choice == "4":
                self.get_target()
                self.run_ssl_scan()
            elif choice == "5":
                self.get_target()
                self.run_dirb_scan()
            elif choice == "6":
                self.get_target()
                self.run_xss_scan()
            elif choice == "7":
                self.get_target()
                self.run_subdomain_scan()
            elif choice == "8":
                self.get_target()
                self.run_dns_scan()
            elif choice == "9":
                self.get_target()
                self.run_header_scan()
            elif choice == "10":
                self.get_target()
                self.run_full_scan()
            elif choice == "11":
                self.show_about_us()
            elif choice == "12":
                print(Fore.GREEN + "\nThank you for using VulnSeekers! Goodbye!")
                break
            else:
                print(Fore.RED + "Invalid choice. Please select a number between 1-12.")

def exit_handler():
    print("\n" + "="*50)
    print(Fore.GREEN + "Thank you for using VulnSeekers!")
    print("Created by the VulnSeekers team")
    print("="*50)

if __name__ == "__main__":
    try:
        vulfy = Vulfy()
        vulfy.main()
    except KeyboardInterrupt:
        exit_handler()
    except Exception as e:
        print(Fore.RED + f"\nAn error occurred: {str(e)}")
        exit_handler()
    finally:
        exit_handler()
