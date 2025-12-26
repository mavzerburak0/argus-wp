"""
HTTP client with retry logic, rate limiting, and caching support.
"""
import time
import hashlib
import random
from typing import Optional, Dict, Any
from urllib.parse import urljoin
import requests
from requests.adapters import HTTPAdapter
from requests.packages.urllib3.util.retry import Retry


class HTTPClient:
    """
    Robust HTTP client for WordPress scanning with retry logic and rate limiting.
    """

    USER_AGENTS = [
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
        'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
        'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0',
        'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.1 Safari/605.1.15',
    ]

    def __init__(
        self,
        timeout: int = 10,
        max_retries: int = 3,
        proxy: Optional[str] = None,
        user_agent: Optional[str] = None,
        random_agent: bool = False,
        verify_ssl: bool = True,
        rate_limit: float = 0.0,
        cache_responses: bool = True,
        max_cache_size: int = 1000
    ):
        """
        Initialize HTTP client.

        Args:
            timeout: Request timeout in seconds
            max_retries: Maximum number of retry attempts
            proxy: Proxy URL (e.g., 'http://127.0.0.1:8080')
            user_agent: Custom User-Agent string
            random_agent: Use random User-Agent for each request
            verify_ssl: Verify SSL certificates
            rate_limit: Delay between requests in seconds
            cache_responses: Enable response caching
            max_cache_size: Maximum number of cached responses
        """
        self.timeout = timeout
        self.proxy = proxy
        self.user_agent = user_agent
        self.random_agent = random_agent
        self.verify_ssl = verify_ssl
        self.rate_limit = rate_limit
        self.cache_responses = cache_responses
        self.max_cache_size = max_cache_size

        # Response cache
        self._cache: Dict[str, Any] = {}
        self._cache_order = []

        # Last request timestamp for rate limiting
        self._last_request_time = 0.0

        # Configure session with retry logic
        self.session = self._create_session(max_retries)

    def _create_session(self, max_retries: int) -> requests.Session:
        """
        Create a requests session with retry logic.

        Args:
            max_retries: Maximum number of retry attempts

        Returns:
            Configured requests.Session object
        """
        session = requests.Session()

        # Configure retry strategy
        retry_strategy = Retry(
            total=max_retries,
            backoff_factor=1,  # Exponential backoff: {backoff factor} * (2 ** (retry - 1))
            status_forcelist=[429, 500, 502, 503, 504],
            allowed_methods=["HEAD", "GET", "OPTIONS", "POST"]
        )

        adapter = HTTPAdapter(max_retries=retry_strategy)
        session.mount("http://", adapter)
        session.mount("https://", adapter)

        # Set proxy if provided
        if self.proxy:
            session.proxies = {
                'http': self.proxy,
                'https': self.proxy
            }

        return session

    def _get_user_agent(self) -> str:
        """
        Get User-Agent string.

        Returns:
            User-Agent string
        """
        if self.random_agent:
            return random.choice(self.USER_AGENTS)
        elif self.user_agent:
            return self.user_agent
        else:
            return self.USER_AGENTS[0]

    def _apply_rate_limit(self):
        """Apply rate limiting between requests."""
        if self.rate_limit > 0:
            elapsed = time.time() - self._last_request_time
            if elapsed < self.rate_limit:
                time.sleep(self.rate_limit - elapsed)
        self._last_request_time = time.time()

    def _cache_key(self, method: str, url: str, **kwargs) -> str:
        """
        Generate cache key for a request.

        Args:
            method: HTTP method
            url: Request URL
            **kwargs: Additional request parameters

        Returns:
            Cache key string
        """
        # Include method, URL, and relevant kwargs in cache key
        cache_str = f"{method}:{url}"
        if 'params' in kwargs:
            cache_str += f":{str(kwargs['params'])}"
        if 'data' in kwargs:
            cache_str += f":{str(kwargs['data'])}"

        return hashlib.md5(cache_str.encode()).hexdigest()

    def _get_from_cache(self, cache_key: str) -> Optional[requests.Response]:
        """
        Get response from cache.

        Args:
            cache_key: Cache key

        Returns:
            Cached response or None
        """
        return self._cache.get(cache_key)

    def _add_to_cache(self, cache_key: str, response: requests.Response):
        """
        Add response to cache.

        Args:
            cache_key: Cache key
            response: Response to cache
        """
        # Implement LRU cache eviction
        if len(self._cache) >= self.max_cache_size:
            oldest_key = self._cache_order.pop(0)
            del self._cache[oldest_key]

        self._cache[cache_key] = response
        self._cache_order.append(cache_key)

    def request(
        self,
        method: str,
        url: str,
        use_cache: bool = True,
        **kwargs
    ) -> Optional[requests.Response]:
        """
        Make an HTTP request with retry logic and caching.

        Args:
            method: HTTP method (GET, POST, etc.)
            url: Request URL
            use_cache: Use cached response if available
            **kwargs: Additional arguments passed to requests

        Returns:
            Response object or None if request failed
        """
        # Check cache first (only for GET requests)
        if self.cache_responses and use_cache and method.upper() == 'GET':
            cache_key = self._cache_key(method, url, **kwargs)
            cached_response = self._get_from_cache(cache_key)
            if cached_response:
                return cached_response

        # Apply rate limiting
        self._apply_rate_limit()

        # Set headers
        headers = kwargs.get('headers', {})
        headers['User-Agent'] = self._get_user_agent()
        kwargs['headers'] = headers

        # Set timeout if not provided
        if 'timeout' not in kwargs:
            kwargs['timeout'] = self.timeout

        # Set SSL verification
        if 'verify' not in kwargs:
            kwargs['verify'] = self.verify_ssl

        try:
            response = self.session.request(method, url, **kwargs)

            # Cache successful GET responses
            if self.cache_responses and method.upper() == 'GET' and response.status_code == 200:
                cache_key = self._cache_key(method, url, **kwargs)
                self._add_to_cache(cache_key, response)

            return response
        except requests.exceptions.RequestException as e:
            # Log error (will be handled by logger in future)
            return None

    def get(self, url: str, **kwargs) -> Optional[requests.Response]:
        """
        Make a GET request.

        Args:
            url: Request URL
            **kwargs: Additional arguments

        Returns:
            Response object or None
        """
        return self.request('GET', url, **kwargs)

    def post(self, url: str, **kwargs) -> Optional[requests.Response]:
        """
        Make a POST request.

        Args:
            url: Request URL
            **kwargs: Additional arguments

        Returns:
            Response object or None
        """
        return self.request('POST', url, **kwargs)

    def head(self, url: str, **kwargs) -> Optional[requests.Response]:
        """
        Make a HEAD request.

        Args:
            url: Request URL
            **kwargs: Additional arguments

        Returns:
            Response object or None
        """
        return self.request('HEAD', url, **kwargs)

    def options(self, url: str, **kwargs) -> Optional[requests.Response]:
        """
        Make an OPTIONS request.

        Args:
            url: Request URL
            **kwargs: Additional arguments

        Returns:
            Response object or None
        """
        return self.request('OPTIONS', url, **kwargs)

    def clear_cache(self):
        """Clear the response cache."""
        self._cache.clear()
        self._cache_order.clear()

    def close(self):
        """Close the session."""
        self.session.close()
