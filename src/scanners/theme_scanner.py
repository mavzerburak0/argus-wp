"""
WordPress theme detection and vulnerability scanning module.
"""
import re
import json
from typing import List, Dict, Optional

from src.core.http_client import HTTPClient
from src.core.config import ScanConfig
from src.utils.logger import Output
from src.vulndb.wpvulnerability import WPVulnerabilityDatabase


class ThemeScanner:
    """
    Detects and scans WordPress themes for vulnerabilities.
    """

    def __init__(self, target_url: str, http_client: HTTPClient,
                 output: Output, config: ScanConfig):
        """
        Initialize theme scanner.

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
        self.detected_themes: Dict[str, Dict] = {}
        self.vuln_db = WPVulnerabilityDatabase(http_client, output)

    def scan(self) -> List[Dict]:
        """
        Run theme enumeration and vulnerability scanning.

        Returns:
            List of detected themes with their details
        """
        self.output.section("Theme Enumeration")

        # Phase 1: Passive detection
        self._passive_detection()

        # Phase 2: Version detection for found themes
        if self.detected_themes:
            self.output.newline()
            self.output.progress("Detecting theme versions...")
            self._detect_versions()

        # Phase 3: Vulnerability scanning
        if self.detected_themes:
            self.output.newline()
            self.output.progress("Scanning for vulnerabilities...")
            self._scan_vulnerabilities()

        # Display results
        self._display_results()

        return list(self.detected_themes.values())

    def _passive_detection(self) -> None:
        """
        Passively detect themes from homepage HTML/CSS references.
        """
        self.output.progress("Analyzing homepage for theme references...")

        response = self.http_client.get(self.target_url)

        if not response or response.status_code != 200:
            self.output.warning("Could not fetch homepage for passive detection")
            return

        content = response.text

        # Extract theme references from wp-content/themes/ paths
        # Pattern: /wp-content/themes/THEME-SLUG/
        pattern = r'/wp-content/themes/([a-zA-Z0-9_-]+)/'
        matches = re.findall(pattern, content)

        if matches:
            unique_slugs = set(matches)
            self.output.success(f"Found {len(unique_slugs)} theme reference(s) in HTML")

            for slug in unique_slugs:
                self._add_theme(slug, detection_method="passive")
                self.output.debug(f"  - {slug}")
        else:
            self.output.info("No theme references found in HTML")

        # Also check REST API and meta tags
        self._check_rest_api()
        self._check_meta_tags(content)

    def _check_rest_api(self) -> None:
        """
        Check WordPress REST API for theme information.
        """
        self.output.progress("Checking REST API for theme data...")

        # Check wp-json endpoint for site info
        api_url = f"{self.target_url}/wp-json"
        response = self.http_client.get(api_url)

        if response and response.status_code == 200:
            try:
                data = json.loads(response.text)
                # Some sites expose theme info in the home URL field
                if isinstance(data, dict):
                    # Look for theme references in the response
                    response_text = json.dumps(data)
                    theme_pattern = r'/wp-content/themes/([a-zA-Z0-9_-]+)/'
                    themes = re.findall(theme_pattern, response_text)
                    for theme in set(themes):
                        if theme not in self.detected_themes:
                            self._add_theme(theme, detection_method="rest_api")
                            self.output.debug(f"  Found via REST API: {theme}")
            except (json.JSONDecodeError, KeyError):
                pass

    def _check_meta_tags(self, content: str) -> None:
        """
        Check HTML meta tags for theme information.

        Args:
            content: HTML content
        """
        # Some themes add meta tags with theme name
        # <meta name="theme" content="theme-name">
        meta_pattern = r'<meta[^>]*name=["\']theme["\'][^>]*content=["\']([^"\']+)["\']'
        match = re.search(meta_pattern, content, re.IGNORECASE)
        if match:
            theme_name = match.group(1)
            if theme_name not in self.detected_themes:
                self._add_theme(theme_name, detection_method="meta_tag")

    def _detect_versions(self) -> None:
        """
        Detect versions for all found themes.
        """
        total = len(self.detected_themes)
        self.output.progress(f"Detecting versions for {total} theme(s)...")

        for slug, theme_data in self.detected_themes.items():
            version = self._detect_theme_version(slug)
            if version:
                theme_data['version'] = version
                theme_data['version_detection'] = 'confirmed'
                self.output.success(f"  {slug}: v{version}")
            else:
                theme_data['version'] = 'unknown'
                theme_data['version_detection'] = 'failed'
                self.output.debug(f"  {slug}: version unknown")

    def _detect_theme_version(self, slug: str) -> Optional[str]:
        """
        Detect version of a specific theme.

        Args:
            slug: Theme slug

        Returns:
            Version string or None
        """
        # Try style.css first (most common for themes)
        style_url = f"{self.target_url}/wp-content/themes/{slug}/style.css"
        response = self.http_client.get(style_url)

        if response and response.status_code == 200:
            version = self._parse_version_from_css(response.text)
            if version:
                return version

        # Try readme.txt
        readme_url = f"{self.target_url}/wp-content/themes/{slug}/readme.txt"
        response = self.http_client.get(readme_url)

        if response and response.status_code == 200:
            version = self._parse_version_from_readme(response.text)
            if version:
                return version

        # Try checking query string version in HTML
        homepage = self.http_client.get(self.target_url)
        if homepage and homepage.status_code == 200:
            version = self._parse_version_from_html(homepage.text, slug)
            if version:
                return version

        return None

    def _parse_version_from_css(self, content: str) -> Optional[str]:
        """
        Parse version from CSS file header (WordPress theme standard).

        Args:
            content: CSS file content

        Returns:
            Version string or None
        """
        # WordPress themes have a standard header in style.css
        # Version: X.Y.Z
        pattern = r'Version:\s*([0-9.]+)'
        match = re.search(pattern, content, re.IGNORECASE)

        if match:
            return match.group(1)

        return None

    def _parse_version_from_readme(self, content: str) -> Optional[str]:
        """
        Parse version from readme.txt file.

        Args:
            content: Readme file content

        Returns:
            Version string or None
        """
        patterns = [
            r'Stable tag:\s*([0-9.]+)',
            r'Version:\s*([0-9.]+)',
        ]

        for pattern in patterns:
            match = re.search(pattern, content, re.IGNORECASE)
            if match:
                return match.group(1)

        return None

    def _parse_version_from_html(self, content: str, slug: str) -> Optional[str]:
        """
        Parse version from HTML query strings.

        Args:
            content: HTML content
            slug: Theme slug

        Returns:
            Version string or None
        """
        # /wp-content/themes/SLUG/...?ver=X.Y.Z
        pattern = rf'/wp-content/themes/{re.escape(slug)}/[^"\']*\?ver=([0-9.]+)'
        match = re.search(pattern, content)

        if match:
            return match.group(1)

        return None

    def _scan_vulnerabilities(self) -> None:
        """
        Scan all detected themes for known vulnerabilities.
        """
        total = len(self.detected_themes)
        self.output.progress(f"Checking {total} theme(s) for vulnerabilities...")

        total_vulns = 0

        for slug, theme_data in self.detected_themes.items():
            version = theme_data.get('version')

            # Skip vulnerability check if version is unknown
            if version == 'unknown':
                theme_data['vulnerabilities'] = []
                theme_data['vulnerability_count'] = 0
                self.output.debug(f"  {slug}: Skipping vulnerability check (version unknown)")
                continue

            # Search for vulnerabilities
            vulnerabilities = self.vuln_db.search_theme_vulnerabilities(
                theme_slug=slug,
                version=version
            )

            if vulnerabilities:
                theme_data['vulnerabilities'] = vulnerabilities
                theme_data['vulnerability_count'] = len(vulnerabilities)
                total_vulns += len(vulnerabilities)

                severity_counts = self._count_severities(vulnerabilities)
                self.output.vuln(
                    f"  {slug} (v{version}): {len(vulnerabilities)} vulnerability/ies found!",
                    "high"
                )
                self.output.debug(f"    Severity: {severity_counts}")
            else:
                theme_data['vulnerabilities'] = []
                theme_data['vulnerability_count'] = 0
                self.output.debug(f"  {slug}: No known vulnerabilities")

        if total_vulns > 0:
            self.output.newline()
            self.output.critical(f"Total theme vulnerabilities found: {total_vulns}")

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

    def _add_theme(self, slug: str, detection_method: str) -> None:
        """
        Add a theme to detected themes list.

        Args:
            slug: Theme slug
            detection_method: How the theme was detected
        """
        if slug not in self.detected_themes:
            self.detected_themes[slug] = {
                'slug': slug,
                'detection_method': detection_method,
                'version': None,
                'version_detection': 'pending',
                'vulnerabilities': [],
                'vulnerability_count': 0,
            }

    def _display_results(self) -> None:
        """
        Display theme scanning results.
        """
        if not self.detected_themes:
            self.output.newline()
            self.output.info("No themes detected")
            return

        self.output.newline()
        self.output.success(f"Detected {len(self.detected_themes)} theme(s)")
        self.output.newline()

        # Display each theme
        for slug, theme_data in sorted(self.detected_themes.items()):
            version = theme_data.get('version', 'unknown')
            vuln_count = theme_data.get('vulnerability_count', 0)

            # Theme header
            if vuln_count > 0:
                self.output.vuln(f"[!] {slug}", "high")
            else:
                self.output.item("Theme", slug)

            self.output.item("Version", version, indent=1)
            self.output.item("Detection", theme_data.get('detection_method', 'unknown'), indent=1)

            # Show vulnerabilities
            if vuln_count > 0:
                self.output.item("Vulnerabilities", f"{vuln_count} found", indent=1)

                # Show top 3 vulnerabilities
                vulns = theme_data.get('vulnerabilities', [])[:3]
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

    def get_detected_themes(self) -> Dict[str, Dict]:
        """
        Get all detected themes.

        Returns:
            Dictionary of detected themes
        """
        return self.detected_themes.copy()
