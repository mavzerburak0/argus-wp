"""
WordPress plugin detection and vulnerability scanning module.
"""
import re
import json
from typing import List, Dict, Optional

from src.core.http_client import HTTPClient
from src.core.config import ScanConfig
from src.utils.logger import Output
from src.vulndb.wpvulnerability import WPVulnerabilityDatabase
from src.utils.version_checker import VersionChecker


class PluginScanner:
    """
    Detects and scans WordPress plugins for vulnerabilities.
    """

    def __init__(self, target_url: str, http_client: HTTPClient,
                 output: Output, config: ScanConfig):
        """
        Initialize plugin scanner.

        Args:
            target_url: Target URL to scan
            http_client: HTTP client instance
            output: Output handler
            config: Scan configuration
        """
        self.target_url = target_url
        self.http_client = http_client
        self.output = output
        self.config = config
        self.detected_plugins: Dict[str, Dict] = {}
        self.vuln_db = WPVulnerabilityDatabase(http_client, output)

    def scan(self) -> List[Dict]:
        """
        Run plugin enumeration and vulnerability scanning.

        Returns:
            List of detected plugins with their details
        """
        self.output.section("Plugin Enumeration")

        # Phase 1: Passive detection (always run)
        self._passive_detection()

        # Phase 2: Version detection for found plugins
        if self.detected_plugins:
            self.output.newline()
            self.output.progress("Detecting plugin versions...")
            self._detect_versions()

        # Phase 3: Vulnerability scanning
        if self.detected_plugins:
            self.output.newline()
            self.output.progress("Scanning for vulnerabilities...")
            self._scan_vulnerabilities()

        # Phase 4: Check latest versions
        if self.detected_plugins:
            self.output.newline()
            self.output.progress("Checking for updates...")
            self._check_latest_versions()

        # Display results
        self._display_results()

        return list(self.detected_plugins.values())

    def _passive_detection(self) -> None:
        """
        Passively detect plugins from homepage HTML/CSS/JS references.
        """
        self.output.progress("Analyzing homepage for plugin references...")

        response = self.http_client.get(self.target_url)

        if not response or response.status_code != 200:
            self.output.warning("Could not fetch homepage for passive detection")
            return

        content = response.text

        # Extract plugin references from wp-content/plugins/ paths
        # Pattern: /wp-content/plugins/PLUGIN-SLUG/
        pattern = r'/wp-content/plugins/([a-zA-Z0-9_-]+)/'
        matches = re.findall(pattern, content)

        if matches:
            unique_slugs = set(matches)
            self.output.success(f"Found {len(unique_slugs)} plugin reference(s) in HTML")

            for slug in unique_slugs:
                self._add_plugin(slug, detection_method="passive")
                self.output.debug(f"  - {slug}")
        else:
            self.output.info("No plugin references found in HTML")

        # Also check REST API for plugin info
        self._check_rest_api()

    def _check_rest_api(self) -> None:
        """
        Check WordPress REST API for plugin information.
        """
        self.output.progress("Checking REST API for plugin data...")

        # Check wp-json/wp/v2/plugins endpoint (requires authentication usually)
        api_url = f"{self.target_url}/wp-json/wp/v2/plugins"
        response = self.http_client.get(api_url)

        if response and response.status_code == 200:
            try:
                data = json.loads(response.text)
                if isinstance(data, list):
                    for plugin in data:
                        slug = plugin.get('plugin', '').split('/')[0]
                        if slug:
                            self._add_plugin(slug, detection_method="rest_api")
                            self.output.debug(f"  Found via REST API: {slug}")
            except (json.JSONDecodeError, KeyError):
                pass

    def _detect_versions(self) -> None:
        """
        Detect versions for all found plugins.
        """
        total = len(self.detected_plugins)
        self.output.progress(f"Detecting versions for {total} plugin(s)...")

        for slug, plugin_data in self.detected_plugins.items():
            version = self._detect_plugin_version(slug)
            if version:
                plugin_data['version'] = version
                plugin_data['version_detection'] = 'confirmed'
                self.output.success(f"  {slug}: v{version}")
            else:
                plugin_data['version'] = 'unknown'
                plugin_data['version_detection'] = 'failed'
                self.output.debug(f"  {slug}: version unknown")

    def _detect_plugin_version(self, slug: str) -> Optional[str]:
        """
        Detect version of a specific plugin.

        Args:
            slug: Plugin slug

        Returns:
            Version string or None
        """
        # Try readme.txt first (most common)
        readme_url = f"{self.target_url}/wp-content/plugins/{slug}/readme.txt"
        response = self.http_client.get(readme_url)

        if response and response.status_code == 200:
            version = self._parse_version_from_readme(response.text)
            if version:
                return version

        # Try main plugin PHP file
        plugin_file_url = f"{self.target_url}/wp-content/plugins/{slug}/{slug}.php"
        response = self.http_client.get(plugin_file_url)

        if response and response.status_code == 200:
            version = self._parse_version_from_php(response.text)
            if version:
                return version

        # Try style.css
        css_url = f"{self.target_url}/wp-content/plugins/{slug}/style.css"
        response = self.http_client.get(css_url)

        if response and response.status_code == 200:
            version = self._parse_version_from_css(response.text)
            if version:
                return version

        # Try checking query string version in HTML
        homepage = self.http_client.get(self.target_url)
        if homepage and homepage.status_code == 200:
            version = self._parse_version_from_html(homepage.text, slug)
            if version:
                return version

        return None

    def _parse_version_from_readme(self, content: str) -> Optional[str]:
        """
        Parse version from readme.txt file.

        Args:
            content: Readme file content

        Returns:
            Version string or None
        """
        # Stable tag: X.Y.Z
        patterns = [
            r'Stable tag:\s*([0-9.]+)',
            r'Version:\s*([0-9.]+)',
        ]

        for pattern in patterns:
            match = re.search(pattern, content, re.IGNORECASE)
            if match:
                return match.group(1)

        return None

    def _parse_version_from_php(self, content: str) -> Optional[str]:
        """
        Parse version from PHP plugin file header.

        Args:
            content: PHP file content

        Returns:
            Version string or None
        """
        # * Version: X.Y.Z
        pattern = r'\*\s*Version:\s*([0-9.]+)'
        match = re.search(pattern, content, re.IGNORECASE)

        if match:
            return match.group(1)

        return None

    def _parse_version_from_css(self, content: str) -> Optional[str]:
        """
        Parse version from CSS file header.

        Args:
            content: CSS file content

        Returns:
            Version string or None
        """
        # Version: X.Y.Z
        pattern = r'Version:\s*([0-9.]+)'
        match = re.search(pattern, content, re.IGNORECASE)

        if match:
            return match.group(1)

        return None

    def _parse_version_from_html(self, content: str, slug: str) -> Optional[str]:
        """
        Parse version from HTML query strings.

        Args:
            content: HTML content
            slug: Plugin slug

        Returns:
            Version string or None
        """
        # /wp-content/plugins/SLUG/...?ver=X.Y.Z
        pattern = rf'/wp-content/plugins/{re.escape(slug)}/[^"\']*\?ver=([0-9.]+)'
        match = re.search(pattern, content)

        if match:
            return match.group(1)

        return None

    def _scan_vulnerabilities(self) -> None:
        """
        Scan all detected plugins for known vulnerabilities.
        """
        total = len(self.detected_plugins)
        self.output.progress(f"Checking {total} plugin(s) for vulnerabilities...")

        total_vulns = 0

        for slug, plugin_data in self.detected_plugins.items():
            version = plugin_data.get('version')

            # Skip vulnerability check if version is unknown
            if version == 'unknown':
                plugin_data['vulnerabilities'] = []
                plugin_data['vulnerability_count'] = 0
                self.output.debug(f"  {slug}: Skipping vulnerability check (version unknown)")
                continue

            # Search for vulnerabilities
            vulnerabilities = self.vuln_db.search_plugin_vulnerabilities(
                plugin_slug=slug,
                version=version
            )

            if vulnerabilities:
                plugin_data['vulnerabilities'] = vulnerabilities
                plugin_data['vulnerability_count'] = len(vulnerabilities)
                total_vulns += len(vulnerabilities)

                severity_counts = self._count_severities(vulnerabilities)
                self.output.vuln(
                    f"  {slug} (v{version}): {len(vulnerabilities)} vulnerability/ies found!",
                    "high"
                )

    def _check_latest_versions(self) -> None:
        """
        Check latest available versions for all detected plugins.
        """
        total = len(self.detected_plugins)
        checked = 0

        for slug, plugin_data in self.detected_plugins.items():
            current_version = plugin_data.get('version', 'unknown')

            # Only check if version is valid
            if VersionChecker.is_version_valid(current_version):
                latest_version = VersionChecker.get_latest_plugin_version(slug)
                if latest_version:
                    plugin_data['latest_version'] = latest_version
                    plugin_data['is_outdated'] = VersionChecker.compare_versions(
                        current_version, latest_version
                    )
                    checked += 1
                    self.output.debug(f"  {slug}: v{current_version} (latest: v{latest_version})")

        self.output.debug(f"Checked {checked}/{total} plugins for updates")

    def _count_severities(self, vulnerabilities: List[Dict]) -> Dict[str, int]:
        """
        Count vulnerabilities by severity.

        Args:
            vulnerabilities: List of vulnerability dictionaries

        Returns:
            Dictionary with severity counts
        """
        counts = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0}
        for vuln in vulnerabilities:
            severity = vuln.get('severity', 'medium')
            counts[severity] = counts.get(severity, 0) + 1
        return counts

    def _add_plugin(self, slug: str, detection_method: str) -> None:
        """
        Add a plugin to detected plugins list.

        Args:
            slug: Plugin slug
            detection_method: How the plugin was detected
        """
        if slug not in self.detected_plugins:
            self.detected_plugins[slug] = {
                'slug': slug,
                'detection_method': detection_method,
                'version': None,
                'version_detection': 'pending',
                'vulnerabilities': [],
                'vulnerability_count': 0,
            }

    def _display_results(self) -> None:
        """
        Display plugin scanning results.
        """
        if not self.detected_plugins:
            self.output.newline()
            self.output.info("No plugins detected")
            return

        self.output.newline()
        self.output.success(f"Detected {len(self.detected_plugins)} plugin(s)")
        self.output.newline()

        # Display each plugin
        for slug, plugin_data in sorted(self.detected_plugins.items()):
            version = plugin_data.get('version', 'unknown')
            vuln_count = plugin_data.get('vulnerability_count', 0)

            # Plugin header
            if vuln_count > 0:
                self.output.vuln(f"[!] {slug}", "high")
            else:
                self.output.item("Plugin", slug)

            self.output.item("Version", version, indent=1)
            self.output.item("Detection", plugin_data.get('detection_method', 'unknown'), indent=1)

            # Show vulnerabilities
            if vuln_count > 0:
                self.output.item("Vulnerabilities", f"{vuln_count} found", indent=1)

                # Show top 3 vulnerabilities
                vulns = plugin_data.get('vulnerabilities', [])[:3]
                for vuln in vulns:
                    cve_id = vuln.get('cve_id', 'Unknown')
                    severity = vuln.get('severity', 'medium')
                    cvss_score = vuln.get('cvss_score', 0.0)

                    self.output.vuln(f"{cve_id} [{severity.upper()}]", severity, indent=2)

                    # Convert cvss_score to float for comparison
                    try:
                        score = float(cvss_score) if cvss_score else 0.0
                        if score > 0:
                            self.output.item("CVSS", f"{score}", indent=3)
                    except (ValueError, TypeError):
                        pass

                    summary = vuln.get('summary', '')
                    if summary:
                        display_summary = summary[:100] + "..." if len(summary) > 100 else summary
                        self.output.item("Description", display_summary, indent=3)

                if vuln_count > 3:
                    self.output.info(f"... and {vuln_count - 3} more vulnerabilities", indent=2)

            self.output.newline()

    def get_detected_plugins(self) -> Dict[str, Dict]:
        """
        Get all detected plugins.

        Returns:
            Dictionary of detected plugins
        """
        return self.detected_plugins.copy()
