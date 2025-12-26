"""
Unit tests for configuration.
"""
import pytest
from src.core.config import ScanConfig, ScanMode, OutputFormat, EnumerationTarget


class TestScanConfig:
    """Test scan configuration."""

    def test_default_config(self):
        """Test default configuration values."""
        config = ScanConfig(target_url="https://example.com")

        assert config.target_url == "https://example.com"
        assert config.scan_mode == ScanMode.NORMAL
        assert config.threads == 5
        assert config.timeout == 10
        assert config.verify_ssl is True
        assert config.cache_responses is True

    def test_url_normalization(self):
        """Test URL normalization."""
        # Should add http:// if missing
        config1 = ScanConfig(target_url="example.com")
        assert config1.target_url == "http://example.com"

        # Should remove trailing slash
        config2 = ScanConfig(target_url="https://example.com/")
        assert config2.target_url == "https://example.com"

        # Should preserve https://
        config3 = ScanConfig(target_url="https://example.com")
        assert config3.target_url == "https://example.com"

    def test_thread_validation(self):
        """Test thread count validation."""
        # Too low - should be set to 1
        config1 = ScanConfig(target_url="https://example.com", threads=0)
        assert config1.threads == 1

        # Too high - should be capped at 50
        config2 = ScanConfig(target_url="https://example.com", threads=100)
        assert config2.threads == 50

        # Valid - should remain unchanged
        config3 = ScanConfig(target_url="https://example.com", threads=10)
        assert config3.threads == 10

    def test_stealth_mode_rate_limit(self):
        """Test stealth mode automatically sets rate limit."""
        config = ScanConfig(
            target_url="https://example.com",
            scan_mode=ScanMode.STEALTH
        )
        assert config.rate_limit == 2.0

    def test_enumeration_enabled(self):
        """Test enumeration target checking."""
        config = ScanConfig(
            target_url="https://example.com",
            enumerate={EnumerationTarget.PLUGINS, EnumerationTarget.THEMES}
        )

        assert config.is_enumeration_enabled(EnumerationTarget.PLUGINS)
        assert config.is_enumeration_enabled(EnumerationTarget.THEMES)
        assert not config.is_enumeration_enabled(EnumerationTarget.USERS)

    def test_http_client_config(self):
        """Test HTTP client configuration extraction."""
        config = ScanConfig(
            target_url="https://example.com",
            timeout=15,
            proxy="http://127.0.0.1:8080",
            verify_ssl=False
        )

        http_config = config.get_http_client_config()

        assert http_config['timeout'] == 15
        assert http_config['proxy'] == "http://127.0.0.1:8080"
        assert http_config['verify_ssl'] is False

    def test_to_dict(self):
        """Test configuration serialization to dict."""
        config = ScanConfig(target_url="https://example.com")
        config_dict = config.to_dict()

        assert isinstance(config_dict, dict)
        assert config_dict['target_url'] == "https://example.com"
        assert config_dict['scan_mode'] == "normal"
