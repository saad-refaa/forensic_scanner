"""
Setup script for Forensic Security Scanner
"""

from setuptools import setup, find_packages
from pathlib import Path

# قراءة README
readme_path = Path(__file__).parent / "README.md"
long_description = readme_path.read_text(encoding='utf-8') if readme_path.exists() else ""

# قراءة المتطلبات
requirements_path = Path(__file__).parent / "requirements.txt"
requirements = []
if requirements_path.exists():
    with open(requirements_path) as f:
        requirements = [line.strip() for line in f if line.strip() and not line.startswith('#')]

setup(
    name="forensic-security-scanner",
    version="1.0.0",
    author="Forensic Security Team",
    author_email="forensic-scanner@example.com",
    description="Forensic Security Scanner for Historical Blockchain Data (2009-2014)",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/yourusername/forensic-scanner",
    packages=find_packages(),
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Developers",
        "Intended Audience :: Science/Research",
        "Topic :: Security :: Cryptography",
        "Topic :: Software Development :: Libraries :: Python Modules",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Operating System :: OS Independent",
    ],
    python_requires=">=3.8",
    install_requires=requirements,
    extras_require={
        'dev': [
            'pytest>=8.0.0',
            'pytest-asyncio>=0.23.4',
            'black>=24.0.0',
            'flake8>=7.0.0',
            'mypy>=1.8.0',
        ],
        'gui': [
            'PyQt6>=6.6.1',
        ],
    },
    entry_points={
        'console_scripts': [
            'forensic-scanner=main:main',
        ],
    },
    include_package_data=True,
    package_data={
        'forensic_scanner': [
            'wordlists/*.txt',
            'config/*.py',
        ],
    },
    zip_safe=False,
)
