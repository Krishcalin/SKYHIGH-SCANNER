"""Vulnerability Management Scanner — setup.py for pip installation."""

from setuptools import find_packages, setup

setup(
    name="vulnerability-management",
    version="1.0.0",
    description="Comprehensive Active Vulnerability Scanner",
    author="Vulnerability Management",
    packages=find_packages(),
    python_requires=">=3.9",
    entry_points={
        "console_scripts": [
            "vulnerability-management=vulnerability_management.__main__:main",
        ],
    },
    install_requires=[
        "requests>=2.28.0",
    ],
    extras_require={
        "linux": ["paramiko>=3.0.0"],
        "cisco": ["netmiko>=4.0.0", "pysnmp-lextudio>=5.0.0"],
        "windows": ["pywinrm>=0.4.3"],
        "all": [
            "paramiko>=3.0.0",
            "netmiko>=4.0.0",
            "pysnmp-lextudio>=5.0.0",
            "pywinrm>=0.4.3",
        ],
    },
    package_data={
        "vulnerability_management": [
            "cve_data/seed/*.json",
            "cve_data/cpe_mappings.json",
            "benchmarks/*.json",
            "templates/*.html",
        ],
    },
    classifiers=[
        "Development Status :: 3 - Alpha",
        "Intended Audience :: Information Technology",
        "Topic :: Security",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
    ],
)
