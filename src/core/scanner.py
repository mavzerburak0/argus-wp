"""
Main scanner orchestrator for WordPress vulnerability scanning.
"""
import time

from src.core.config import ScanConfig, ScanResult
from src.core.http_client import HTTPClient
from src.utils.logger import Output, setup_logger
from src.scanners.wordpress_detector import WordPressDetector
from src.scanners.version_detector import VersionDetector
from src.scanners.plugin_scanner import PluginScanner
from src.scanners.theme_scanner import ThemeScanner
from src.vulndb.wpvulnerability import WPVulnerabilityDatabase


class WordPressScanner:
    """
    Main WordPress vulnerability scanner orchestrator.
    Coordinates all scanning modules and manages scan execution.
    """

    def __init__(self, config: ScanConfig):
        """
        Initialize scanner.

        Args:
            config: Scan configuration
        """
        self.config = config
        self.http_client = HTTPClient(**config.get_http_client_config())
        self.output = Output(
            use_color=not config.no_color,
            verbose=config.verbose
        )
        self.logger = setup_logger(
            level='DEBUG' if config.debug else 'INFO',
            use_color=not config.no_color
        )

        # Scan result container
        self.result = ScanResult(target_url=config.target_url)

    def scan(self) -> ScanResult:
        """
        Execute comprehensive WordPress vulnerability scan.

        Returns:
            ScanResult containing all findings
        """
        self.result.scan_start_time = time.time()

        try:
            # Display banner
            self.output.banner()
            self.output.info(f"Target: {self.config.target_url}")
            self.output.info(f"Scan Mode: {self.config.scan_mode.value}")
            self.output.newline()

            # Phase 1: WordPress Detection
            if not self._detect_wordpress():
                self.output.error("WordPress not detected on target")
                return self.result

            self.output.success("WordPress detected!")
            self.output.newline()

            # Phase 2: Version Detection
            if self.config.check_wp_version:
                self._detect_version()

            # Phase 3: Plugin Enumeration
            from src.core.config import EnumerationTarget
            if self.config.check_plugins and self.config.is_enumeration_enabled(
                EnumerationTarget.PLUGINS
            ):
                self._enumerate_plugins()

            # Phase 4: Theme Enumeration
            if self.config.check_themes:
                self._enumerate_themes()

            # Phase 6: Configuration Checks
            self._run_config_checks()

            # Display results
            self._display_results()

        except KeyboardInterrupt:
            self.output.warning("\nScan interrupted by user")
            self.result.errors.append("Scan interrupted by user")
        except Exception as e:
            self.output.error(f"Scan error: {str(e)}")
            self.result.errors.append(str(e))
            if self.config.debug:
                raise
        finally:
            self.result.scan_end_time = time.time()
            self.http_client.close()

        return self.result

    def _detect_wordpress(self) -> bool:
        """
        Detect if target is running WordPress using comprehensive detection methods.

        Returns:
            True if WordPress is detected
        """
        detector = WordPressDetector(
            target_url=self.config.target_url,
            http_client=self.http_client,
            output=self.output
        )

        detected = detector.detect()
        self.result.wordpress_detected = detected

        return detected

    def _detect_version(self):
        """Detect WordPress version and check for vulnerabilities."""
        detector = VersionDetector(
            target_url=self.config.target_url,
            http_client=self.http_client,
            output=self.output
        )

        version = detector.detect()
        if version:
            self.result.wordpress_version = version

            # Check for vulnerabilities in detected version
            self._check_wordpress_vulnerabilities(version)

    def _enumerate_plugins(self):
        """Enumerate installed plugins."""
        scanner = PluginScanner(
            target_url=self.config.target_url,
            http_client=self.http_client,
            output=self.output,
            config=self.config
        )

        plugins = scanner.scan()

        # Store results
        self.result.plugins = plugins
        self.result.plugin_count = len(plugins)

        # Count vulnerabilities
        total_vulns = sum(p.get('vulnerability_count', 0) for p in plugins)
        self.result.plugin_vulnerabilities = total_vulns

    def _enumerate_themes(self):
        """Enumerate installed themes."""
        scanner = ThemeScanner(
            target_url=self.config.target_url,
            http_client=self.http_client,
            output=self.output,
            config=self.config
        )

        themes = scanner.scan()

        # Store results
        self.result.themes = themes
        self.result.theme_count = len(themes)

        # Count vulnerabilities
        total_vulns = sum(t.get('vulnerability_count', 0) for t in themes)
        self.result.theme_vulnerabilities = total_vulns

    def _run_config_checks(self):
        """Run configuration and miscellaneous checks."""
        self.output.section("Configuration Checks")

        checks = []

        if self.config.check_xmlrpc:
            checks.append(("XML-RPC Status", self._check_xmlrpc))
        if self.config.check_wp_cron:
            checks.append(("WP-Cron Status", self._check_wp_cron))
        if self.config.check_user_registration:
            checks.append(("User Registration", self._check_user_registration))
        if self.config.check_directory_listing:
            checks.append(("Directory Listing", self._check_directory_listing))

        for check_name, check_func in checks:
            self.output.progress(f"Checking {check_name}...")
            try:
                check_func()
            except Exception as e:
                self.output.debug(f"Error in {check_name}: {str(e)}")

    def _check_xmlrpc(self):
        """Check XML-RPC status."""
        url = f"{self.config.target_url}/xmlrpc.php"
        response = self.http_client.get(url)

        if response and response.status_code == 200:
            self.result.xmlrpc_enabled = True
            self.output.warning("XML-RPC is enabled")
        else:
            self.output.debug("XML-RPC is disabled or not accessible")

    def _check_wp_cron(self):
        """Check WP-Cron status."""
        url = f"{self.config.target_url}/wp-cron.php"
        response = self.http_client.get(url)

        if response and response.status_code == 200:
            self.result.wp_cron_enabled = True
            self.output.info("WP-Cron is enabled")
        else:
            self.output.debug("WP-Cron is disabled or not accessible")

    def _check_user_registration(self):
        """Check if user registration is enabled."""
        url = f"{self.config.target_url}/wp-login.php?action=register"
        response = self.http_client.get(url)

        if response and response.status_code == 200:
            if 'registration is disabled' not in response.text.lower():
                self.result.user_registration_enabled = True
                self.output.warning("User registration appears to be enabled")
            else:
                self.output.debug("User registration is disabled")
        else:
            self.output.debug("Could not check user registration status")

    def _check_directory_listing(self):
        """Check for directory listing vulnerabilities."""
        directories = [
            '/wp-content/',
            '/wp-content/uploads/',
            '/wp-content/plugins/',
            '/wp-content/themes/',
            '/wp-includes/'
        ]

        for directory in directories:
            url = f"{self.config.target_url}{directory}"
            response = self.http_client.get(url)

            if response and response.status_code == 200:
                if 'index of' in response.text.lower():
                    self.result.directory_listings.append(directory)
                    self.output.warning(f"Directory listing enabled: {directory}")

    def _check_config_backups(self):
        """Check for wp-config.php backups."""
        backup_files = [
            '/wp-config.php.bak',
            '/wp-config.php.old',
            '/wp-config.php~',
            '/wp-config.php.save',
            '/wp-config.php.swp',
            '/wp-config.php.txt',
            '/.wp-config.php.swp',
            '/wp-config.txt'
        ]

        for backup in backup_files:
            url = f"{self.config.target_url}{backup}"
            response = self.http_client.get(url)

            if response and response.status_code == 200:
                self.result.config_backups.append(backup)
                self.output.critical(f"Config backup found: {backup}")


    def _check_wordpress_vulnerabilities(self, version: str):
        """
        Check for vulnerabilities in WordPress core version.

        Args:
            version: WordPress version to check
        """
        self.output.subsection("Vulnerability Check")
        self.output.progress(f"Checking WordPress {version} for known vulnerabilities...")

        # Initialize WPVulnerability database
        vuln_db = WPVulnerabilityDatabase(self.http_client, self.output)

        # Search for vulnerabilities
        vulnerabilities = vuln_db.search_wordpress_vulnerabilities(version)

        if vulnerabilities:
            self.output.newline()
            self.output.critical(f"Found {len(vulnerabilities)} known vulnerabilit{'y' if len(vulnerabilities) == 1 else 'ies'} in WordPress {version}!")
            self.output.newline()

            for vuln in vulnerabilities:
                self.result.wordpress_vulnerabilities.append(vuln)

                # Display vulnerability
                severity = vuln.get('severity', 'medium')
                cve_id = vuln.get('cve_id', 'Unknown')
                summary = vuln.get('summary', 'No description available')
                cvss_score = vuln.get('cvss_score', 0.0)
                version_range = vuln.get('version_range', '')
                unfixed = vuln.get('unfixed', False)

                # Show CVE ID or vulnerability name
                self.output.vuln(f"{cve_id} [{severity.upper()}]", severity)

                if cvss_score > 0:
                    self.output.item("CVSS Score", f"{cvss_score}", indent=1)

                if version_range:
                    self.output.item("Affected Versions", version_range, indent=1)

                if unfixed:
                    self.output.item("Status", "UNFIXED - No patch available!", indent=1)

                self.output.item("Description", summary[:200] + "..." if len(summary) > 200 else summary, indent=1)

                # Show CWE if available
                if vuln.get('cwe'):
                    cwe_list = vuln['cwe'][:2]  # Show first 2 CWEs
                    for cwe in cwe_list:
                        self.output.item("CWE", cwe, indent=1)

                # Show references
                if vuln.get('references'):
                    refs = vuln['references'][:2]  # Show first 2 references
                    for ref in refs:
                        self.output.item("Reference", ref, indent=1)

                self.output.newline()
        else:
            self.output.newline()
            self.output.success(f"No known vulnerabilities found in WordPress {version}")
            self.output.info("Note: This doesn't mean the site is completely secure")

    def _display_results(self):
        """Display scan results summary."""
        self.output.section("Scan Results Summary")

        # Calculate scan duration
        if self.result.scan_start_time and self.result.scan_end_time:
            duration = self.result.scan_end_time - self.result.scan_start_time
            self.output.item("Scan Duration", f"{duration:.2f} seconds")

        self.output.item("WordPress Detected", str(self.result.wordpress_detected))

        if self.result.wordpress_version:
            self.output.item("WordPress Version", self.result.wordpress_version)

        # Plugins and Themes
        if self.result.plugin_count > 0:
            self.output.item("Plugins Detected", str(self.result.plugin_count))
            if self.result.plugin_vulnerabilities > 0:
                self.output.vuln(f"Plugin Vulnerabilities: {self.result.plugin_vulnerabilities}", "high")

        if self.result.theme_count > 0:
            self.output.item("Themes Detected", str(self.result.theme_count))
            if self.result.theme_vulnerabilities > 0:
                self.output.vuln(f"Theme Vulnerabilities: {self.result.theme_vulnerabilities}", "high")

        # Vulnerabilities
        total_vulns = self.result.get_total_vulnerabilities()
        if total_vulns > 0:
            self.output.vuln(f"Total Vulnerabilities Found: {total_vulns}", "high")

        # Security issues
        issues = []
        if self.result.directory_listings:
            issues.append(f"{len(self.result.directory_listings)} directory listing(s)")
        if self.result.xmlrpc_enabled:
            issues.append("XML-RPC enabled")
        if self.result.user_registration_enabled:
            issues.append("User registration enabled")

        if issues:
            self.output.subsection("Security Issues")
            for issue in issues:
                self.output.list_item(issue)

        self.output.newline()
        self.output.success("Scan completed!")
