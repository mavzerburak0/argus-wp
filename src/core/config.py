"""
Configuration management for WordPress vulnerability scanner.
"""
from dataclasses import dataclass, field
from typing import Optional, List, Set

from enum import Enum


class OutputFormat(Enum):
    """Output format options."""
    CLI = "cli"
    JSON = "json"
    XML = "xml"
    HTML = "html"
    CSV = "csv"


class ScanMode(Enum):
    """Scanning mode options."""
    PASSIVE = "passive"      # Only passive detection
    NORMAL = "normal"        # Standard active scanning
    AGGRESSIVE = "aggressive"  # Comprehensive scanning
    STEALTH = "stealth"      # Slower, less detectable


class EnumerationTarget(Enum):
    """Targets for enumeration."""
    PLUGINS = "p"
    THEMES = "t"
    USERS = "u"
    ALL = "all"


@dataclass
class ScanConfig:
    """
    Configuration for WordPress vulnerability scanning.
    """
    # Target configuration
    target_url: str
    follow_redirects: bool = True

    # Scan scope
    scan_mode: ScanMode = ScanMode.NORMAL
    enumerate: Set[EnumerationTarget] = field(default_factory=lambda: {
        EnumerationTarget.PLUGINS,
        EnumerationTarget.THEMES,
        EnumerationTarget.USERS
    })

    # Performance settings
    threads: int = 5
    timeout: int = 10
    rate_limit: float = 0.0  # Seconds between requests (0 = no limit)

    # HTTP settings
    user_agent: Optional[str] = None
    random_agent: bool = False
    proxy: Optional[str] = None
    verify_ssl: bool = True
    max_retries: int = 3

    # Authentication (for authenticated scans)
    auth_username: Optional[str] = None
    auth_password: Optional[str] = None
    auth_cookie: Optional[str] = None

    # Brute force settings
    enable_brute_force: bool = False
    username_wordlist: Optional[str] = None
    password_wordlist: Optional[str] = None
    brute_force_usernames: List[str] = field(default_factory=list)
    max_brute_force_attempts: int = 50

    # Output settings
    output_format: OutputFormat = OutputFormat.CLI
    output_file: Optional[str] = None
    verbose: bool = False
    debug: bool = False
    no_color: bool = False

    # Cache settings
    cache_responses: bool = True
    max_cache_size: int = 1000

    # Vulnerability database
    update_database: bool = False
    database_path: str = "./data/vulns"
    offline_mode: bool = False

    # Feature toggles (which checks to run)
    check_wp_version: bool = True
    check_plugins: bool = True
    check_themes: bool = True
    check_users: bool = True
    check_config_backups: bool = True
    check_db_dumps: bool = True
    check_error_logs: bool = True
    check_media_files: bool = True
    check_timthumb: bool = True
    check_readme: bool = True
    check_wp_cron: bool = True
    check_user_registration: bool = True
    check_directory_listing: bool = True
    check_full_path_disclosure: bool = True
    check_xmlrpc: bool = True

    # Advanced options
    custom_headers: dict = field(default_factory=dict)
    custom_cookies: dict = field(default_factory=dict)
    exclude_paths: List[str] = field(default_factory=list)

    def __post_init__(self):
        """Validate configuration after initialization."""
        # Ensure target URL has scheme
        if not self.target_url.startswith(('http://', 'https://')):
            self.target_url = f'http://{self.target_url}'

        # Remove trailing slash from target URL
        self.target_url = self.target_url.rstrip('/')

        # Validate threads
        if self.threads < 1:
            self.threads = 1
        elif self.threads > 50:
            self.threads = 50

        # Validate timeout
        if self.timeout < 1:
            self.timeout = 1

        # Set rate limit for stealth mode
        if self.scan_mode == ScanMode.STEALTH and self.rate_limit == 0.0:
            self.rate_limit = 2.0

    def is_enumeration_enabled(self, target: EnumerationTarget) -> bool:
        """
        Check if enumeration is enabled for a specific target.

        Args:
            target: Enumeration target to check

        Returns:
            True if enumeration is enabled
        """
        return target in self.enumerate or EnumerationTarget.ALL in self.enumerate

    def get_http_client_config(self) -> dict:
        """
        Get configuration for HTTP client.

        Returns:
            Dictionary of HTTP client configuration
        """
        return {
            'timeout': self.timeout,
            'max_retries': self.max_retries,
            'proxy': self.proxy,
            'user_agent': self.user_agent,
            'random_agent': self.random_agent,
            'verify_ssl': self.verify_ssl,
            'rate_limit': self.rate_limit,
            'cache_responses': self.cache_responses,
            'max_cache_size': self.max_cache_size
        }

    def to_dict(self) -> dict:
        """
        Convert configuration to dictionary.

        Returns:
            Dictionary representation of configuration
        """
        return {
            'target_url': self.target_url,
            'scan_mode': self.scan_mode.value,
            'enumerate': [e.value for e in self.enumerate],
            'threads': self.threads,
            'timeout': self.timeout,
            'verbose': self.verbose,
            'output_format': self.output_format.value,
            # Add more fields as needed
        }


@dataclass
class ScanResult:
    """
    Container for scan results.
    """
    target_url: str
    wordpress_detected: bool = False
    wordpress_version: Optional[str] = None
    wordpress_latest_version: Optional[str] = None
    wordpress_is_outdated: bool = False
    wordpress_vulnerabilities: List[dict] = field(default_factory=list)

    plugins: List[dict] = field(default_factory=list)
    plugin_count: int = 0
    plugin_vulnerabilities: int = 0

    themes: List[dict] = field(default_factory=list)
    theme_count: int = 0
    theme_vulnerabilities: int = 0

    users: List[dict] = field(default_factory=list)

    config_backups: List[str] = field(default_factory=list)
    db_dumps: List[str] = field(default_factory=list)
    error_logs: List[str] = field(default_factory=list)
    exposed_files: List[str] = field(default_factory=list)

    timthumb_found: List[dict] = field(default_factory=list)
    readme_found: bool = False
    wp_cron_enabled: bool = False
    user_registration_enabled: bool = False
    xmlrpc_enabled: bool = False

    directory_listings: List[str] = field(default_factory=list)
    full_path_disclosures: List[dict] = field(default_factory=list)

    weak_passwords: List[dict] = field(default_factory=list)

    scan_start_time: Optional[float] = None
    scan_end_time: Optional[float] = None
    errors: List[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        """
        Convert results to dictionary.

        Returns:
            Dictionary representation of results
        """
        return {
            'target_url': self.target_url,
            'wordpress_detected': self.wordpress_detected,
            'wordpress_version': self.wordpress_version,
            'wordpress_latest_version': self.wordpress_latest_version,
            'wordpress_is_outdated': self.wordpress_is_outdated,
            'wordpress_vulnerabilities': self.wordpress_vulnerabilities,
            'plugins': self.plugins,
            'themes': self.themes,
            'users': self.users,
            'config_backups': self.config_backups,
            'db_dumps': self.db_dumps,
            'error_logs': self.error_logs,
            'exposed_files': self.exposed_files,
            'timthumb_found': self.timthumb_found,
            'readme_found': self.readme_found,
            'wp_cron_enabled': self.wp_cron_enabled,
            'user_registration_enabled': self.user_registration_enabled,
            'xmlrpc_enabled': self.xmlrpc_enabled,
            'directory_listings': self.directory_listings,
            'full_path_disclosures': self.full_path_disclosures,
            'weak_passwords': self.weak_passwords,
            'errors': self.errors
        }

    def add_vulnerability(self, component: str, vuln: dict):
        """
        Add a vulnerability to the appropriate list.

        Args:
            component: Component type (wordpress, plugin, theme)
            vuln: Vulnerability information
        """
        if component == 'wordpress':
            self.wordpress_vulnerabilities.append(vuln)
        elif component == 'plugin':
            # Find the plugin and add vuln to it
            for plugin in self.plugins:
                if plugin.get('slug') == vuln.get('component_slug'):
                    if 'vulnerabilities' not in plugin:
                        plugin['vulnerabilities'] = []
                    plugin['vulnerabilities'].append(vuln)
                    break
        elif component == 'theme':
            # Find the theme and add vuln to it
            for theme in self.themes:
                if theme.get('slug') == vuln.get('component_slug'):
                    if 'vulnerabilities' not in theme:
                        theme['vulnerabilities'] = []
                    theme['vulnerabilities'].append(vuln)
                    break

    def get_total_vulnerabilities(self) -> int:
        """
        Get total count of vulnerabilities found.

        Returns:
            Total vulnerability count
        """
        count = len(self.wordpress_vulnerabilities)

        for plugin in self.plugins:
            count += len(plugin.get('vulnerabilities', []))

        for theme in self.themes:
            count += len(theme.get('vulnerabilities', []))

        return count
