# Argus-WP - WordPress Vulnerability Scanner

This project is mostly vibe-coded.

A WordPress security scanner that identifies vulnerabilities, misconfigurations, and security issues in WordPress installations.

## Features

- **WordPress Version Detection** - Multiple fingerprinting techniques
- **Plugin Enumeration** - Detect installed plugins and known vulnerabilities
- **Theme Enumeration** - Identify themes and associated security issues
- **Configuration Checks** - XML-RPC, WP-Cron, registration status
- **Vulnerability Database** - Powered by WPVulnerability.net (no API key required)

## Installation

### Option 1: Docker (Recommended)

```bash
# Build the Docker image
docker build -t argus-wp .

# Run a scan
docker run --rm argus-wp scan https://example.com

# Run with enumeration
docker run --rm argus-wp scan https://example.com --enumerate p,t

# Save output to file
docker run --rm -v $(pwd):/output argus-wp scan https://example.com -o /output/results.json -f json
```

### Option 2: From Source

```bash
# Clone the repository
git clone https://github.com/yourusername/argus-wp.git
cd argus-wp

# Install dependencies
pip install -r requirements.txt

# Make CLI executable
chmod +x argus-wp.py
```

## Quick Start

### Basic Scan

```bash
python argus-wp.py scan https://example.com
```

### With Docker

```bash
docker run --rm argus-wp scan https://example.com
```

### Enumerate Plugins and Themes

```bash
python argus-wp.py scan https://example.com --enumerate p,t
```

### Output to JSON

```bash
python argus-wp.py scan https://example.com -o results.json -f json
```

### Using Docker Compose

```bash
# Build and run
docker-compose build
docker-compose run argus-wp scan https://example.com --enumerate p,t

# Save results to output directory
docker-compose run argus-wp scan https://example.com -o /output/scan.json -f json
```

### Scanning Multiple Sites

```bash
# Scan multiple URLs directly
python argus-wp.py scan --urls https://site1.com --urls https://site2.com --urls https://site3.com

# Scan from a file (one URL per line)
python argus-wp.py scan --targets targets.txt -o batch-results.json -f json

# With Docker
docker run --rm -v $(pwd):/data argus-wp scan --targets /data/targets.txt -o /data/results.json -f json
```

## Usage

```
Usage: argus-wp.py scan [OPTIONS] URL

  Scan a WordPress site for vulnerabilities.

Options:
  -t, --targets PATH          File containing list of URLs to scan (one per line)
  --urls TEXT                 Multiple URLs to scan (can be used multiple times)
  -e, --enumerate [p|t|all]   Enumerate plugins (p), themes (t), or all
  --threads INTEGER           Number of threads (default: 5)
  --timeout INTEGER           Request timeout in seconds (default: 10)
  --random-agent              Use random User-Agent strings
  --user-agent TEXT           Custom User-Agent string
  --proxy TEXT                Proxy URL (e.g., http://127.0.0.1:8080)
  -o, --output PATH           Output file path
  -f, --format [cli|json]     Output format (default: cli)
  -v, --verbose               Verbose output
  --debug                     Debug output
  --no-color                  Disable colored output
  --mode [passive|normal|aggressive|stealth]
                              Scan mode (default: normal)
  --rate-limit FLOAT          Delay between requests in seconds (default: 0)
  --no-ssl-verify             Disable SSL certificate verification
  --help                      Show this message and exit.
```

## Scan Modes

- **passive** - Only passive detection (no active probing)
- **normal** - Standard active scanning (default)
- **aggressive** - Comprehensive scanning with extensive enumeration
- **stealth** - Slower, less detectable scanning

## Examples

### Enumerate only plugins and themes

```bash
python argus-wp.py scan https://example.com --enumerate p,t
```

### Use a proxy

```bash
python argus-wp.py scan https://example.com --proxy http://127.0.0.1:8080
```

### Export results to JSON

```bash
python argus-wp.py scan https://example.com --output results.json --format json
```

### Stealth scan with rate limiting

```bash
python argus-wp.py scan https://example.com --mode stealth --rate-limit 2.0
```

### Debug mode

```bash
python argus-wp.py scan https://example.com --debug --verbose
```


## Requirements

- Python 3.9+
- See `requirements.txt` for dependencies

## Development

### Running Tests

```bash
pytest tests/
```

### Code Formatting

```bash
black src/ tests/ argus-wp.py
```

### Linting

```bash
flake8 src/ tests/ argus-wp.py
```

## Security and Legal

**WARNING**: This tool should only be used on WordPress sites you own or have explicit permission to test. Unauthorized scanning may be illegal in your jurisdiction.

- Always obtain written authorization before scanning
- Respect rate limits and server resources
- Follow responsible disclosure guidelines
- Do not use for malicious purposes

## Contributing

Contributions are welcome! Please feel free to submit pull requests or open issues.

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## License

MIT License - see LICENSE file for details

## Credits

- Vulnerability data powered by [WPVulnerability.com](https://www.wpvulnerability.com/)

## Disclaimer

This tool is for educational and authorized security testing purposes only. The authors are not responsible for misuse or damage caused by this tool.

## Support

For issues, questions, or contributions, please visit:
https://github.com/yourusername/argus-wp/issues
