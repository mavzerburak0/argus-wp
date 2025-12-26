"""
Unit tests for HTTP client.
"""
import pytest
from src.core.http_client import HTTPClient


class TestHTTPClient:
    """Test HTTP client functionality."""

    def test_initialization(self):
        """Test HTTP client initialization."""
        client = HTTPClient(timeout=5, max_retries=2)
        assert client.timeout == 5
        assert client.verify_ssl is True
        assert client.rate_limit == 0.0

    def test_custom_user_agent(self):
        """Test custom User-Agent."""
        custom_ua = "CustomBot/1.0"
        client = HTTPClient(user_agent=custom_ua)
        assert client.user_agent == custom_ua
        assert client._get_user_agent() == custom_ua

    def test_random_agent(self):
        """Test random User-Agent selection."""
        client = HTTPClient(random_agent=True)
        ua1 = client._get_user_agent()
        ua2 = client._get_user_agent()
        # Both should be valid user agents
        assert ua1 in HTTPClient.USER_AGENTS
        assert ua2 in HTTPClient.USER_AGENTS

    def test_cache_key_generation(self):
        """Test cache key generation."""
        client = HTTPClient()
        key1 = client._cache_key('GET', 'https://example.com')
        key2 = client._cache_key('GET', 'https://example.com')
        key3 = client._cache_key('GET', 'https://different.com')

        # Same requests should have same key
        assert key1 == key2
        # Different requests should have different keys
        assert key1 != key3

    def test_cache_operations(self):
        """Test cache add and get operations."""
        client = HTTPClient(cache_responses=True, max_cache_size=2)

        # Create mock response
        class MockResponse:
            status_code = 200

        resp = MockResponse()
        key = 'test_key'

        # Test adding to cache
        client._add_to_cache(key, resp)
        assert client._get_from_cache(key) == resp

        # Test cache eviction (LRU)
        client._add_to_cache('key2', resp)
        client._add_to_cache('key3', resp)  # Should evict first key

        assert client._get_from_cache(key) is None
        assert client._get_from_cache('key3') == resp

    def test_clear_cache(self):
        """Test cache clearing."""
        client = HTTPClient()

        class MockResponse:
            status_code = 200

        client._add_to_cache('key1', MockResponse())
        client._add_to_cache('key2', MockResponse())

        assert len(client._cache) == 2

        client.clear_cache()
        assert len(client._cache) == 0
        assert len(client._cache_order) == 0
