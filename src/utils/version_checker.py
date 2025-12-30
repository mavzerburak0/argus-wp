"""
WordPress version checking utility using WordPress.org APIs.
"""
import requests
import re
from typing import Optional


# Global cache for version API responses
_VERSION_CACHE = {}


class VersionChecker:
    """
    Checks latest versions from WordPress.org for WordPress core, plugins, and themes.
    """

    @staticmethod
    def get_latest_wordpress_version() -> Optional[str]:
        """
        Get the latest WordPress version from WordPress.org API.

        Returns:
            Latest version string or None if unavailable
        """
        try:
            if 'wordpress_core' in _VERSION_CACHE:
                return _VERSION_CACHE['wordpress_core']

            response = requests.get(
                'https://api.wordpress.org/core/version-check/1.7/',
                timeout=10
            )
            if response.status_code == 200:
                data = response.json()
                if data.get('offers') and len(data['offers']) > 0:
                    latest_version = data['offers'][0].get('version')
                    _VERSION_CACHE['wordpress_core'] = latest_version
                    return latest_version
        except Exception:
            pass
        return None

    @staticmethod
    def get_latest_plugin_version(plugin_slug: str) -> Optional[str]:
        """
        Get the latest plugin version from WordPress.org API.

        Args:
            plugin_slug: Plugin slug

        Returns:
            Latest version string or None if unavailable
        """
        try:
            cache_key = f'plugin_{plugin_slug}'
            if cache_key in _VERSION_CACHE:
                return _VERSION_CACHE[cache_key]

            response = requests.get(
                f'https://api.wordpress.org/plugins/info/1.0/{plugin_slug}.json',
                timeout=10
            )
            if response.status_code == 200:
                data = response.json()
                latest_version = data.get('version')
                if latest_version:
                    _VERSION_CACHE[cache_key] = latest_version
                    return latest_version
        except Exception:
            pass
        return None

    @staticmethod
    def get_latest_theme_version(theme_slug: str) -> Optional[str]:
        """
        Get the latest theme version from WordPress.org API.

        Args:
            theme_slug: Theme slug

        Returns:
            Latest version string or None if unavailable
        """
        try:
            cache_key = f'theme_{theme_slug}'
            if cache_key in _VERSION_CACHE:
                return _VERSION_CACHE[cache_key]

            response = requests.get(
                f'https://api.wordpress.org/themes/info/1.2/?action=query_themes&request[slug]={theme_slug}',
                timeout=10
            )
            if response.status_code == 200:
                data = response.json()
                themes = data.get('themes', [])
                if themes and len(themes) > 0:
                    latest_version = themes[0].get('version')
                    if latest_version:
                        _VERSION_CACHE[cache_key] = latest_version
                        return latest_version
        except Exception:
            pass
        return None

    @staticmethod
    def is_version_valid(version: str) -> bool:
        """
        Check if a version string looks valid.

        Args:
            version: Version string to validate

        Returns:
            True if version looks valid
        """
        if not version or version == 'Unknown' or version == 'unknown':
            return False

        # Check if it's a timestamp (10+ digits)
        if re.match(r'^\d{10,}$', version):
            return False

        # Check if it looks like a valid semantic version
        if not re.search(r'\d+\.\d+', version):
            return False

        return True

    @staticmethod
    def compare_versions(current: str, latest: str) -> bool:
        """
        Compare two version strings.

        Args:
            current: Current version
            latest: Latest version

        Returns:
            True if current version is older than latest
        """
        try:
            # Extract numeric parts
            current_parts = [int(x) for x in re.findall(r'\d+', current)]
            latest_parts = [int(x) for x in re.findall(r'\d+', latest)]

            # Pad shorter version
            max_len = max(len(current_parts), len(latest_parts))
            current_parts += [0] * (max_len - len(current_parts))
            latest_parts += [0] * (max_len - len(latest_parts))

            return current_parts < latest_parts
        except (ValueError, TypeError):
            return False
