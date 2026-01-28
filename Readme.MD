# SQLi Hunter 🎯

Automated SQL Injection Vulnerability Scanner dengan dukungan berbagai database dan teknik bypass WAF.

## Features

✨ **Multi-Database Support**
- MySQL
- PostgreSQL
- Microsoft SQL Server
- Oracle
- SQLite

🛡️ **WAF Bypass Techniques**
- Inline comments
- URL encoding variations
- Case manipulation
- Null byte injection
- Unicode encoding

🔍 **Detection Methods**
- Error-based SQL injection
- Time-based blind SQL injection
- Boolean-based blind SQL injection
- UNION-based SQL injection

⚡ **Advanced Features**
- Multi-threaded scanning
- Automatic database detection
- Custom user agents rotation
- Comprehensive vulnerability reporting

## Installation

```bash
# Clone atau download file
git clone <repository-url>
cd sqli-hunter

# Install dependencies
pip install -r requirements.txt
```

## Usage

### Basic Scan
```bash
python sqli_hunter.py -u "http://example.com/page?id=1"
```

### Verbose Mode
```bash
python sqli_hunter.py -u "http://example.com/page?id=1&name=admin" -v
```

### Multi-threaded Scan
```bash
python sqli_hunter.py -u "http://example.com/page?id=1" -t 10
```

## Command Line Options

```
-u, --url       Target URL with parameters (required)
-v, --verbose   Enable verbose output
-t, --threads   Number of concurrent threads (default: 5)
```

## Example Output

```
╔═══════════════════════════════════════════════════════════╗
║                                                           ║
║   ███████╗ ██████╗ ██╗     ██╗    ██╗  ██╗██╗   ██╗       ║
║   ██╔════╝██╔═══██╗██║     ██║    ██║  ██║██║   ██║       ║
║   ███████╗██║   ██║██║     ██║    ███████║██║   ██║       ║
║   ╚════██║██║▄▄ ██║██║     ██║    ██╔══██║██║   ██║       ║
║   ███████║╚██████╔╝███████╗██║    ██║  ██║╚██████╔╝       ║
║   ╚══════╝ ╚══▀▀═╝ ╚══════╝╚═╝    ╚═╝  ╚═╝ ╚═════╝        ║
║                                                           ║
║        SQL Injection Vulnerability Scanner                ║
║           with WAF Bypass Capabilities                    ║
║                                                           ║
╚═══════════════════════════════════════════════════════════╝

[12:30:45] [INFO] Target URL: http://example.com/page?id=1
[12:30:45] [INFO] Found 1 parameter(s) to test
[12:30:45] [INFO] Scanning parameter: id
[12:30:52] [VULN] VULNERABILITY FOUND in id using mysql payload

============================================================
SCAN RESULTS
============================================================

[12:30:55] [VULN] Found 1 SQL injection vulnerability/vulnerabilities!

[Vulnerability #1]
  Parameter: id
  Payload Type: mysql
  Payload: ' OR '1'='1' --
  Database: MYSQL
  Attack Type: Error-Based
  Response Time: 0.23s
  Vulnerable URL:
    http://example.com/page?id=%27+OR+%271%27%3D%271%27+--...

============================================================
```

## Payload Categories

### 1. Basic Payloads
- Simple quote injection
- OR-based bypass
- Comment-based bypass

### 2. MySQL Specific
- UNION-based injection
- Time-based with SLEEP()
- Information schema queries

### 3. PostgreSQL Specific
- pg_sleep() injection
- Version detection
- Database enumeration

### 4. MSSQL Specific
- WAITFOR DELAY injection
- System functions
- Database metadata

### 5. Oracle Specific
- DUAL table queries
- DBMS_PIPE techniques
- Banner information

### 6. WAF Bypass
- Inline comments (/*!*/)
- URL encoding variants
- Case manipulation
- Null byte injection
- Unicode variations

## Error Pattern Detection

Tool ini mendeteksi SQL injection melalui error patterns dari berbagai database:

- **MySQL**: SQL syntax errors, mysql_* warnings
- **PostgreSQL**: PostgreSQL ERROR, pg_* warnings
- **MSSQL**: SQL Server driver errors, ODBC messages
- **Oracle**: ORA-* error codes
- **SQLite**: SQLite exceptions

## Security Notes

⚠️ **Legal Notice**: Tool ini hanya untuk educational purposes dan authorized penetration testing. Pastikan Anda memiliki izin untuk melakukan testing pada target.

⚠️ **Responsible Disclosure**: Jika menemukan vulnerability, laporkan secara responsible kepada pemilik website.

## Technical Details

### WAF Bypass Techniques

1. **Inline Comments**
   ```sql
   /*!50000OR*/ '1'='1
   ```

2. **URL Encoding**
   ```sql
   %6Fr 1=1--  (or)
   %55nion     (union)
   ```

3. **Null Byte Injection**
   ```sql
   ' or 1=1%00
   ```

4. **Case Manipulation**
   ```sql
   UnIoN SeLeCt
   ```

### Time-Based Detection

Tool menggunakan threshold 4.5 detik untuk mendeteksi time-based injection:
- MySQL: `SLEEP(5)`
- PostgreSQL: `pg_sleep(5)`
- MSSQL: `WAITFOR DELAY '0:0:5'`
- Oracle: `DBMS_PIPE.RECEIVE_MESSAGE('a',5)`

## Limitations

- Hanya mendukung GET parameter injection
- Tidak support POST data injection
- Tidak mendukung cookie-based injection
- Memerlukan parameter di URL

## Future Enhancements

- [ ] POST data injection support
- [ ] Cookie injection support
- [ ] Header injection testing
- [ ] JSON payload injection
- [ ] XML injection
- [ ] Advanced obfuscation techniques
- [ ] Automated exploitation
- [ ] Report generation (HTML/PDF)

## Contributing

Contributions are welcome! Please feel free to submit pull requests atau report issues.

## License

MIT License - feel free to use untuk educational purposes.

## Disclaimer

Penggunaan tool ini untuk attacking sistem tanpa izin adalah ilegal. Developer tidak bertanggung jawab atas penyalahgunaan tool ini.

## Author

Created for educational and authorized security testing purposes.

---

**Remember**: Always get proper authorization before testing any system!