#!/bin/bash
# Argus-WP Docker Build Script

set -e

echo "Building Argus-WP Docker image..."
docker build -t argus-wp:latest .

echo ""
echo "Build complete! You can now use Argus-WP with Docker:"
echo ""
echo "  docker run --rm argus-wp scan https://example.com"
echo "  docker run --rm argus-wp scan https://example.com --enumerate p,t"
echo "  docker run --rm -v \$(pwd):/output argus-wp scan https://example.com -o /output/scan.json -f json"
echo ""
echo "Or use docker-compose:"
echo ""
echo "  docker-compose run argus-wp scan https://example.com"

echo ""
