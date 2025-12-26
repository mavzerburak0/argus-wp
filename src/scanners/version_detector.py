"""
WordPress version detection module.
Implements multiple fingerprinting techniques to detect WordPress version.
"""
import re
import hashlib
from typing import Optional, Dict, Set
from src.core.http_client import HTTPClient
from src.utils.logger import Output


class VersionDetector:
    """
    Detects WordPress version using multiple fingerprinting techniques.
    """

    # Known version-specific file paths and their hashes
    # This is a small sample - in production, you'd have a comprehensive database
    VERSION_SIGNATURES = {
        # Format: file_path: {hash: version}
        '/wp-includes/js/jquery/jquery.js': {},  # Populated from database
        '/readme.html': {},  # Contains version info in text
    }

    def __init__(self, target_url: str, http_client: HTTPClient, output: Output):
        """
        Initialize version detector.

        Args:
            target_url: Target URL to scan
            http_client: HTTP client instance
            output: Output handler
        """
        self.target_url = target_url
        self.http_client = http_client
        self.output = output
        self.detected_versions: Set[str] = set()
        self.version_sources: Dict[str, str] = {}

    def detect(self) -> Optional[str]:
        """
        Run all version detection methods.

        Returns:
            Detected WordPress version or None
        """
        self.output.section("WordPress Version Detection")

        detection_methods = [
            ("Meta Generator Tag", self._detect_from_meta_generator),
            ("readme.html", self._detect_from_readme),
            ("RSS Feed", self._detect_from_rss),
            ("Emoji Detection Script", self._detect_from_emoji_script),
            ("CSS/JS Version Parameters", self._detect_from_static_files),
            ("Default Files", self._detect_from_default_files),
            ("Atom Feed", self._detect_from_atom_feed),
        ]

        for method_name, method_func in detection_methods:
            self.output.progress(f"Trying: {method_name}...")
            try:
                version = method_func()
                if version:
                    self.detected_versions.add(version)
                    self.version_sources[version] = method_name
                    self.output.success(f"✓ {method_name}: Found version {version}")
                else:
                    self.output.debug(f"✗ {method_name}: No version found")
            except Exception as e:
                self.output.debug(f"Error in {method_name}: {str(e)}")

        self.output.newline()

        # Determine the most likely version
        final_version = self._determine_version()

        if final_version:
            self.output.success(f"WordPress Version: {final_version}")
            self._display_version_info(final_version)
        else:
            self.output.warning("Could not determine WordPress version")
            self.output.info("The site may be hiding version information")

        return final_version

    def _determine_version(self) -> Optional[str]:
        """
        Determine the most likely version from detected versions.
        Uses majority voting - the version detected by most methods wins.

        Returns:
            Most likely version or None
        """
        if not self.detected_versions:
            return None

        # If all methods agree, return that version
        if len(self.detected_versions) == 1:
            return list(self.detected_versions)[0]

        # Count how many methods detected each version
        version_counts = {}
        for version, detected_source in self.version_sources.items():
            version_counts[version] = version_counts.get(version, 0) + 1

        # Find the version with the most detections (majority voting)
        most_common_version = max(version_counts.items(), key=lambda x: x[1])

        # If there's a clear majority (more than half), use it
        total_detections = len(self.version_sources)
        if most_common_version[1] > total_detections / 2:
            return most_common_version[0]

        # If no clear majority, prefer certain reliable sources
        priority_sources = [
            "Meta Generator Tag",
            "RSS Feed",
            "Atom Feed",
            "Emoji Detection Script",
            "readme.html",  # Less reliable, so lower priority
        ]

        for source in priority_sources:
            for version, detected_source in self.version_sources.items():
                if detected_source == source:
                    return version

        # Fallback to most common version
        return most_common_version[0]

    def _display_version_info(self, version: str):
        """
        Display information about detected version.

        Args:
            version: Detected version
        """
        if len(self.detected_versions) > 1:
            self.output.subsection("Version Detection Details")
            self.output.warning(f"Multiple versions detected: {', '.join(sorted(self.detected_versions))}")
            self.output.info(f"Using version: {version}")

        # Show which methods found this version
        sources = [src for ver, src in self.version_sources.items() if ver == version]
        if sources:
            self.output.item("Detected by", ", ".join(sources))

    def _detect_from_meta_generator(self) -> Optional[str]:
        """
        Detect version from HTML meta generator tag.

        Returns:
            Version string or None
        """
        response = self.http_client.get(self.target_url)

        if not response or response.status_code != 200:
            return None

        # Look for meta generator tag
        # <meta name="generator" content="WordPress 6.4.2" />
        pattern = r'<meta\s+name=["\']generator["\']\s+content=["\']WordPress\s+([\d.]+)["\']'
        match = re.search(pattern, response.text, re.IGNORECASE)

        if match:
            return match.group(1)

        # Try reverse order
        pattern = r'content=["\']WordPress\s+([\d.]+)["\']\s+name=["\']generator["\']'
        match = re.search(pattern, response.text, re.IGNORECASE)

        if match:
            return match.group(1)

        return None

    def _detect_from_readme(self) -> Optional[str]:
        """
        Detect version from readme.html file.

        Returns:
            Version string or None
        """
        response = self.http_client.get(f"{self.target_url}/readme.html")

        if not response or response.status_code != 200:
            return None

        content = response.text

        # Look for version in readme.html
        # Examples:
        # <br /> Version 6.4.2
        # WordPress 6.4.2
        patterns = [
            r'Version\s+([\d.]+)',
            r'WordPress\s+([\d.]+)',
            r'<br\s*/>\s*Version\s+([\d.]+)',
        ]

        for pattern in patterns:
            match = re.search(pattern, content, re.IGNORECASE)
            if match:
                return match.group(1)

        return None

    def _detect_from_rss(self) -> Optional[str]:
        """
        Detect version from RSS feed.

        Returns:
            Version string or None
        """
        feed_urls = [
            '/feed/',
            '/feed/rss/',
            '/feed/rss2/',
            '/?feed=rss2',
        ]

        for feed_url in feed_urls:
            url = f"{self.target_url}{feed_url}"
            response = self.http_client.get(url)

            if response and response.status_code == 200:
                # Look for generator tag in RSS
                # <generator>https://wordpress.org/?v=6.4.2</generator>
                pattern = r'<generator>.*?wordpress\.org/\?v=([\d.]+)</generator>'
                match = re.search(pattern, response.text, re.IGNORECASE)

                if match:
                    return match.group(1)

                # Alternative format
                pattern = r'<generator>WordPress\s+([\d.]+)</generator>'
                match = re.search(pattern, response.text, re.IGNORECASE)

                if match:
                    return match.group(1)

        return None

    def _detect_from_atom_feed(self) -> Optional[str]:
        """
        Detect version from Atom feed.

        Returns:
            Version string or None
        """
        response = self.http_client.get(f"{self.target_url}/feed/atom/")

        if not response or response.status_code != 200:
            return None

        # Look for generator in Atom feed
        # <generator uri="https://wordpress.org/" version="6.4.2">WordPress</generator>
        pattern = r'<generator[^>]+version=["\']?([\d.]+)["\']?[^>]*>WordPress</generator>'
        match = re.search(pattern, response.text, re.IGNORECASE)

        if match:
            return match.group(1)

        return None

    def _detect_from_emoji_script(self) -> Optional[str]:
        """
        Detect version from WordPress emoji detection script.

        Returns:
            Version string or None
        """
        response = self.http_client.get(self.target_url)

        if not response or response.status_code != 200:
            return None

        # Look for emoji script with version parameter
        # wp-includes/js/wp-emoji-release.min.js?ver=6.4.2
        patterns = [
            r'wp-emoji-release\.min\.js\?ver=([\d.]+)',
            r'wp-emoji\.js\?ver=([\d.]+)',
        ]

        for pattern in patterns:
            match = re.search(pattern, response.text)
            if match:
                return match.group(1)

        return None

    def _detect_from_static_files(self) -> Optional[str]:
        """
        Detect version from CSS/JS file version parameters.

        Returns:
            Version string or None
        """
        response = self.http_client.get(self.target_url)

        if not response or response.status_code != 200:
            return None

        content = response.text

        # Look for version parameters in static file URLs
        # Common patterns:
        # /wp-includes/css/dist/block-library/style.min.css?ver=6.4.2
        # /wp-includes/js/jquery/jquery.min.js?ver=3.7.1 (jQuery version, not WP)
        # /wp-content/themes/theme-name/style.css?ver=6.4.2

        patterns = [
            r'wp-includes/css/[^"\']+\.css\?ver=([\d.]+)',
            r'wp-includes/js/[^"\']+\.js\?ver=([\d.]+)',
            r'wp-admin/css/[^"\']+\.css\?ver=([\d.]+)',
        ]

        version_counts: Dict[str, int] = {}

        for pattern in patterns:
            matches = re.findall(pattern, content)
            for match in matches:
                # Filter out obvious non-WP versions (too old or too new)
                if self._is_valid_wp_version(match):
                    version_counts[match] = version_counts.get(match, 0) + 1

        if version_counts:
            # Return the most common version
            most_common = max(version_counts.items(), key=lambda x: x[1])
            if most_common[1] >= 2:  # At least 2 occurrences
                return most_common[0]

        return None

    def _detect_from_default_files(self) -> Optional[str]:
        """
        Detect version by checking for version-specific default files.

        Returns:
            Version string or None
        """
        # Check for version-specific files
        # This would require a database of known files per version
        # For now, we'll check license.txt which sometimes has version info

        response = self.http_client.get(f"{self.target_url}/license.txt")

        if response and response.status_code == 200:
            # Some sites include version in license.txt
            pattern = r'WordPress\s+([\d.]+)'
            match = re.search(pattern, response.text, re.IGNORECASE)
            if match:
                return match.group(1)

        return None

    def _is_valid_wp_version(self, version: str) -> bool:
        """
        Check if a version string looks like a valid WordPress version.

        Args:
            version: Version string to check

        Returns:
            True if version looks valid
        """
        try:
            parts = version.split('.')
            if len(parts) < 2:
                return False

            major = int(parts[0])
            minor = int(parts[1])

            # WordPress versions start from 0.7 (2003) and are currently at 6.x
            # Major version should be 0-10 (accounting for future)
            # Minor version should be reasonable
            if major < 0 or major > 10:
                return False

            if minor < 0 or minor > 50:
                return False

            # Filter out common JavaScript library versions that aren't WP
            # jQuery is usually 1.x, 2.x, 3.x
            # WordPress is usually 3.x, 4.x, 5.x, 6.x
            if major < 3 and version not in ['0.7', '0.71', '1.0', '1.2', '1.5', '2.0', '2.1', '2.2', '2.3', '2.5', '2.6', '2.7', '2.8', '2.9']:
                return False

            return True
        except (ValueError, IndexError):
            return False

    def get_detected_versions(self) -> Set[str]:
        """
        Get all detected versions.

        Returns:
            Set of detected versions
        """
        return self.detected_versions.copy()

    def get_version_sources(self) -> Dict[str, str]:
        """
        Get mapping of versions to their detection sources.

        Returns:
            Dictionary mapping versions to sources
        """
        return self.version_sources.copy()
