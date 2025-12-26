"""
WordPress detection module.
Implements multiple techniques to detect WordPress installations.
"""
from typing import Optional, Dict, List
import re
from src.core.http_client import HTTPClient
from src.utils.logger import Output


class WordPressDetector:
    """
    Detects WordPress installations using multiple fingerprinting techniques.
    """

    def __init__(self, target_url: str, http_client: HTTPClient, output: Output):
        """
        Initialize WordPress detector.

        Args:
            target_url: Target URL to scan
            http_client: HTTP client instance
            output: Output handler
        """
        self.target_url = target_url
        self.http_client = http_client
        self.output = output
        self.detection_results: Dict[str, bool] = {}

    def detect(self) -> bool:
        """
        Run all WordPress detection methods.

        Returns:
            True if WordPress is detected
        """
        self.output.section("WordPress Detection")

        detection_methods = [
            ("Standard Paths", self._check_standard_paths),
            ("Meta Generator Tag", self._check_meta_generator),
            ("WordPress Headers", self._check_wp_headers),
            ("RSS Feed", self._check_rss_feed),
            ("Login Page", self._check_login_page),
            ("XML-RPC", self._check_xmlrpc),
            ("wp-json API", self._check_wp_json),
        ]

        detected = False
        confidence_score = 0
        total_methods = len(detection_methods)

        for method_name, method_func in detection_methods:
            self.output.progress(f"Checking: {method_name}...")
            try:
                result = method_func()
                self.detection_results[method_name] = result

                if result:
                    confidence_score += 1
                    self.output.success(f"✓ {method_name}: WordPress indicator found")
                    detected = True
                else:
                    self.output.debug(f"✗ {method_name}: No indicator found")

            except Exception as e:
                self.output.debug(f"Error in {method_name}: {str(e)}")
                self.detection_results[method_name] = False

        # Calculate confidence
        confidence_percentage = (confidence_score / total_methods) * 100

        self.output.newline()

        # Require at least 3 positive detections and 40% confidence to be sure
        # This helps reduce false positives
        if detected and confidence_score >= 3 and confidence_percentage >= 40:
            self.output.success(f"WordPress DETECTED! (Confidence: {confidence_percentage:.1f}%)")
            self.output.item("Detection Methods", f"{confidence_score}/{total_methods} positive")
            return True
        elif detected and confidence_score < 3:
            self.output.warning(f"Possible WordPress site, but confidence is LOW ({confidence_percentage:.1f}%)")
            self.output.item("Detection Methods", f"{confidence_score}/{total_methods} positive")
            self.output.info("This might be a false positive. Not enough indicators found.")
            return False
        else:
            self.output.warning("WordPress NOT detected")
            self.output.info("This does not appear to be a WordPress site")
            return False

    def _check_standard_paths(self) -> bool:
        """
        Check for standard WordPress paths and directories.

        Returns:
            True if WordPress paths are found
        """
        paths = [
            '/wp-content/',
            '/wp-includes/',
            '/wp-admin/',
        ]

        found = 0
        for path in paths:
            url = f"{self.target_url}{path}"
            response = self.http_client.head(url)

            # 200, 301, 302, 403 are all valid indicators
            # 403 means the directory exists but access is forbidden
            if response and response.status_code in [200, 301, 302, 403]:
                self.output.debug(f"  Found: {path} (HTTP {response.status_code})")
                found += 1

        return found >= 2  # At least 2 standard paths should exist

    def _check_meta_generator(self) -> bool:
        """
        Check for WordPress meta generator tag in HTML.

        Returns:
            True if WordPress meta tag is found
        """
        response = self.http_client.get(self.target_url)

        if not response or response.status_code != 200:
            return False

        content = response.text

        # Look for meta generator tag
        # <meta name="generator" content="WordPress X.Y.Z" />
        patterns = [
            r'<meta\s+name=["\']generator["\']\s+content=["\']WordPress[^"\']*["\']',
            r'content=["\']WordPress[^"\']*["\']\s+name=["\']generator["\']',
        ]

        for pattern in patterns:
            if re.search(pattern, content, re.IGNORECASE):
                # Try to extract version
                version_match = re.search(r'WordPress\s+([\d.]+)', content, re.IGNORECASE)
                if version_match:
                    version = version_match.group(1)
                    self.output.debug(f"  WordPress version from meta: {version}")
                return True

        return False

    def _check_wp_headers(self) -> bool:
        """
        Check for WordPress-specific HTTP headers and content.

        Returns:
            True if WordPress headers/content is found
        """
        response = self.http_client.get(self.target_url)

        if not response or response.status_code != 200:
            return False

        # Check response headers
        headers = response.headers

        # Some WordPress sites use specific headers
        wp_header_indicators = [
            'x-powered-by',  # Sometimes shows WordPress
            'link',  # Often contains wp-json links
        ]

        for header in wp_header_indicators:
            if header in headers:
                header_value = headers[header].lower()
                if 'wordpress' in header_value or 'wp-json' in header_value:
                    self.output.debug(f"  WordPress indicator in {header} header")
                    return True

        # Check HTML content for common WordPress patterns
        content = response.text.lower()

        wp_content_indicators = [
            'wp-content',
            'wp-includes',
            '/wp-json/',
            'wordpress',
        ]

        found_indicators = sum(1 for indicator in wp_content_indicators if indicator in content)

        if found_indicators >= 2:
            self.output.debug(f"  Found {found_indicators} WordPress content indicators")
            return True

        return False

    def _check_rss_feed(self) -> bool:
        """
        Check RSS feed for WordPress generator tag.

        Returns:
            True if WordPress is identified in feed
        """
        feed_urls = [
            '/feed/',
            '/feed/rss/',
            '/feed/rss2/',
            '/feed/atom/',
            '/?feed=rss2',
        ]

        for feed_url in feed_urls:
            url = f"{self.target_url}{feed_url}"
            response = self.http_client.get(url)

            if response and response.status_code == 200:
                content = response.text

                # Look for WordPress generator in feed
                if re.search(r'<generator>.*?WordPress.*?</generator>', content, re.IGNORECASE):
                    self.output.debug(f"  WordPress generator found in {feed_url}")

                    # Try to extract version
                    version_match = re.search(r'WordPress\s+([\d.]+)', content, re.IGNORECASE)
                    if version_match:
                        version = version_match.group(1)
                        self.output.debug(f"  WordPress version from feed: {version}")

                    return True

        return False

    def _check_login_page(self) -> bool:
        """
        Check for WordPress login page.

        Returns:
            True if WordPress login page is found
        """
        response = self.http_client.get(f"{self.target_url}/wp-login.php")

        if not response or response.status_code != 200:
            return False

        content = response.text.lower()

        # Look for WordPress login page indicators
        login_indicators = [
            'wordpress',
            'wp-submit',
            'log in',
            'user_login',
            'wp-admin',
        ]

        found = sum(1 for indicator in login_indicators if indicator in content)

        if found >= 3:
            self.output.debug("  WordPress login page found at /wp-login.php")
            return True

        return False

    def _check_xmlrpc(self) -> bool:
        """
        Check for WordPress XML-RPC endpoint.

        Returns:
            True if XML-RPC endpoint is found
        """
        response = self.http_client.post(
            f"{self.target_url}/xmlrpc.php",
            data='<?xml version="1.0"?><methodCall><methodName>system.listMethods</methodName></methodCall>',
            headers={'Content-Type': 'application/xml'}
        )

        if not response:
            # Try GET request as fallback
            response = self.http_client.get(f"{self.target_url}/xmlrpc.php")

            if response and response.status_code == 405:  # Method Not Allowed
                self.output.debug("  XML-RPC endpoint exists (405 Method Not Allowed)")
                return True

            return False

        # Check for XML-RPC response
        if response.status_code == 200:
            content = response.text.lower()

            # Look for WordPress-specific XML-RPC methods
            wp_methods = [
                'wp.getpost',
                'wp.getusers',
                'wp.newtag',
                'pingback.ping',
            ]

            found = sum(1 for method in wp_methods if method in content)

            if found > 0:
                self.output.debug(f"  XML-RPC endpoint found with {found} WordPress methods")
                return True

        return False

    def _check_wp_json(self) -> bool:
        """
        Check for WordPress REST API (wp-json).

        Returns:
            True if wp-json API is found
        """
        api_endpoints = [
            '/wp-json/',
            '/wp-json/wp/v2/',
            '/?rest_route=/',
        ]

        for endpoint in api_endpoints:
            url = f"{self.target_url}{endpoint}"
            response = self.http_client.get(url)

            if response and response.status_code == 200:
                try:
                    # Try to parse as JSON
                    import json
                    data = json.loads(response.text)

                    # Check for WordPress-specific fields in JSON response
                    wp_json_indicators = [
                        'namespace',
                        'routes',
                        'authentication',
                        'name',  # Site name
                        'description',  # Site description
                    ]

                    # Also check if 'wp/v2' appears in the response
                    if isinstance(data, dict):
                        if any(key in data for key in wp_json_indicators):
                            self.output.debug(f"  WordPress REST API found at {endpoint}")

                            # Try to get site info
                            if 'name' in data:
                                self.output.debug(f"  Site name: {data.get('name')}")

                            return True

                        # Check for wp/v2 in routes or namespaces
                        content_str = response.text.lower()
                        if 'wp/v2' in content_str or 'wp-json' in content_str:
                            self.output.debug(f"  WordPress REST API indicators found")
                            return True

                except (json.JSONDecodeError, ValueError):
                    # Not valid JSON, but check content anyway
                    if 'wp/v2' in response.text.lower():
                        return True

        return False

    def get_detection_summary(self) -> Dict[str, bool]:
        """
        Get summary of detection results.

        Returns:
            Dictionary of detection method results
        """
        return self.detection_results.copy()
