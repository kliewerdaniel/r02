"""
Setup script for QASP v0.2 Python SDK

This is a minimal SDK package for interacting with QASP v0.2 servers.
It provides client-side cryptographic operations and protocol implementation.
"""

from setuptools import setup, find_packages


# Read README if available
try:
    with open("README.md", "r") as f:
        long_description = f.read()
except FileNotFoundError:
    long_description = "QASP v0.2 Python Client SDK"

setup(
    name="qasp-sdk",
    version="0.2.0",
    description="QASP v0.2 Python Client SDK",
    long_description=long_description,
    long_description_content_type="text/markdown",
    author="QASP Development Team",
    author_email="dev@qasp.org",
    url="https://github.com/kliewerdaniel/r02",
    packages=find_packages(),
    classifiers=[
        "Development Status :: 3 - Alpha",
        "Intended Audience :: Developers",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Topic :: Security :: Cryptography",
        "Topic :: Software Development :: Libraries :: Python Modules",
    ],
    keywords="qasp quantum post-quantum cryptography security api client sdk",
    python_requires=">=3.8",
    install_requires=[
        "cryptography>=3.4.0",
        "pqcrypto>=0.1.0",  # Post-quantum crypto library
        "httpx>=0.24.0",
        "structlog>=22.1.0",
    ],
    extras_require={
        "dev": [
            "pytest>=7.0.0",
            "black>=22.0.0",
            "isort>=5.10.0",
            "mypy>=0.950",
        ],
    },
    project_urls={
        "Bug Reports": "https://github.com/kliewerdaniel/r02/issues",
        "Source": "https://github.com/kliewerdaniel/r02",
    },
)
