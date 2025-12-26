"""
Setup script for Argus-WP WordPress vulnerability scanner.
"""
from setuptools import setup, find_packages

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

with open("requirements.txt", "r", encoding="utf-8") as fh:
    requirements = [line.strip() for line in fh if line.strip() and not line.startswith("#")]

setup(
    name="argus-wp",
    version="1.0.0",
    author="Your Name",
    author_email="mavzer122@gmail.com",
    description="WordPress vulnerability scanner and security auditor",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/mavzerburak0/argus-wp",
    packages=find_packages(),
    classifiers=[
        "Development Status :: 3 - Alpha",
        "Intended Audience :: Information Technology",
        "Intended Audience :: System Administrators",
        "Topic :: Security",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
    ],
    python_requires=">=3.9",
    install_requires=requirements,
    entry_points={
        "console_scripts": [
            "argus-wp=argus-wp:cli",
        ],
    },
    keywords="wordpress security vulnerability scanner audit penetration-testing",
    project_urls={
        "Bug Reports": "https://github.com/mavzerburak0/argus-wp/issues",
        "Source": "https://github.com/mavzerburak0/argus-wp",
    },
)
